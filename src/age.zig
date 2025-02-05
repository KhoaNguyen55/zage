const std = @import("std");
const testing = std.testing;
const test_allocator = testing.allocator;
const assert = std.debug.assert;

const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const random = std.crypto.random;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const X25519 = @import("x25519.zig");
const X25519Identity = X25519.X25519Identity;
const X25519Recipient = X25519.X25519Recipient;

const format = @import("format.zig");
const Header = format.Header;
const Stanza = format.Stanza;
const AnyIdentity = format.AnyIdentity;
const AnyRecipient = format.AnyRecipient;
const computeHkdfKey = @import("primitives.zig").computeHkdfKey;

const version_line = format.version_line;
const mac_prefix = format.mac_prefix;
const file_key_size = format.file_key_size;
const payload_key_nonce_length = 16;

const payload_label = "payload";
const header_label = "header";
const last_chunk_flag = 0x01;
const payload_nonce_length = 12;
const chunk_size = 64 * 1024;

const Error = error{
    NoValidIdentities,
    MacsNotEqual,
};

fn setLastChunkFlag(nonce: *[ChaCha20Poly1305.nonce_length]u8) void {
    nonce.*[nonce.len - 1] = last_chunk_flag;
}

fn incrementNonce(nonce: *[ChaCha20Poly1305.nonce_length]u8) void {
    var i = nonce.len - 2;
    while (i >= 0) : (i -= 1) {
        nonce.*[i] +%= 1;
        if (nonce[i] != 0) {
            break;
        }
        if (i == 0) {
            @panic("Chunk counter wrapped around");
        }
    }
}

pub const AgeEncryptor = struct {
    payload_key: [ChaCha20Poly1305.key_length]u8,
    payload_nonce: [payload_nonce_length]u8,
    buffer: [chunk_size]u8,
    buffer_pos: usize,
    dest: std.io.AnyWriter,

    /// Initialize the encryption process.
    /// Use `AgeEncryptor.update()` to write encrypted data to `dest`.
    /// Must use `AgeEncryptor.finish()` to write the final chunk.
    pub fn encryptInit(
        allocator: Allocator,
        recipients: []const AnyRecipient,
        dest: std.io.AnyWriter,
    ) anyerror!AgeEncryptor {
        var file_key: [file_key_size]u8 = undefined;
        random.bytes(&file_key);

        var stanzas = try allocator.alloc(Stanza, recipients.len);
        defer {
            for (stanzas) |stanza| {
                stanza.deinit();
            }
            allocator.free(stanzas);
        }

        for (recipients, 0..) |recipient, i| {
            const stanza = try recipient.wrap(allocator, &file_key);
            stanzas[i] = stanza;
        }

        var header = Header{
            .allocator = allocator,
            .recipients = stanzas,
            .mac = null,
        };

        const header_no_mac = try std.fmt.allocPrint(allocator, "{nomac}", .{header});
        defer allocator.free(header_no_mac);

        const hmac_key = computeHkdfKey(&file_key, "", header_label);
        var hmac: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&hmac, header_no_mac, &hmac_key);

        header.mac = hmac;

        var key_nonce: [payload_key_nonce_length]u8 = undefined;
        random.bytes(&key_nonce);

        const payload_key = computeHkdfKey(&file_key, &key_nonce, payload_label);

        try dest.print("{mac}\n", .{header});
        try dest.writeAll(&key_nonce);

        // const buf = allocator.alloc(u8, chunk_size);
        return .{
            .payload_key = payload_key,
            .payload_nonce = [_]u8{0} ** payload_nonce_length,
            .buffer = [_]u8{0} ** chunk_size,
            .buffer_pos = 0,
            .dest = dest,
        };
    }

    pub fn update(
        self: *AgeEncryptor,
        source: []const u8,
    ) anyerror!void {
        var written: usize = 0;
        while (written < source.len) {
            const written_size = @min(source.len - written, chunk_size);
            const new_size = self.buffer_pos + written_size;

            @memcpy(self.buffer[self.buffer_pos..new_size], source[written .. written + written_size]);

            written += written_size;
            self.buffer_pos += written_size;

            if (self.buffer_pos == chunk_size) {
                try self.encryptChunk(false);
            }
        }
    }

    pub fn finish(self: *AgeEncryptor) anyerror!void {
        try self.encryptChunk(true);
    }

    fn encryptChunk(self: *AgeEncryptor, last: bool) anyerror!void {
        if (!last and self.buffer_pos != chunk_size) {
            @panic("Encrypting partial chunk");
        }

        if (last) {
            setLastChunkFlag(&self.payload_nonce);
        }

        var encrypted: [chunk_size]u8 = undefined;
        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;

        ChaCha20Poly1305.encrypt(
            encrypted[0..self.buffer_pos],
            &tag,
            self.buffer[0..self.buffer_pos],
            "",
            self.payload_nonce,
            self.payload_key,
        );

        try self.dest.writeAll(encrypted[0..self.buffer_pos]);
        try self.dest.writeAll(&tag);
        incrementNonce(&self.payload_nonce);
        self.buffer_pos = 0;
    }
};

pub fn decrypt(
    allocator: Allocator,
    encrypted_message: std.io.AnyReader,
    identities: []const AnyIdentity,
) anyerror![]u8 {
    const header = try Header.parse(allocator, encrypted_message);
    defer header.deinit();

    const file_key: [file_key_size]u8 = for (identities) |identity| {
        const key = try identity.unwrap(header.recipients);
        // const key = identity.unwrap(header.recipients) catch continue;
        break key.?;
    } else {
        return Error.NoValidIdentities;
    };

    const header_no_mac = try std.fmt.allocPrint(allocator, "{nomac}", .{header});
    defer allocator.free(header_no_mac);

    const hmac_key = computeHkdfKey(&file_key, "", header_label);
    var hmac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&hmac, header_no_mac, &hmac_key);

    if (!std.mem.eql(u8, &hmac, &header.mac.?)) {
        return Error.MacsNotEqual;
    }

    var key_nonce: [payload_key_nonce_length]u8 = undefined;
    if (try encrypted_message.read(&key_nonce) < payload_key_nonce_length) {
        unreachable;
    }

    const payload_key = computeHkdfKey(&file_key, &key_nonce, payload_label);

    var payload_nonce: [ChaCha20Poly1305.nonce_length]u8 = .{0} ** ChaCha20Poly1305.nonce_length;
    // TODO: split it into chunks of 64KiB
    setLastChunkFlag(&payload_nonce);

    var c_m = try encrypted_message.readAllAlloc(allocator, 64000);
    defer allocator.free(c_m);

    const m = try allocator.alloc(u8, c_m.len - ChaCha20Poly1305.tag_length);
    errdefer allocator.free(m);

    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    @memcpy(&tag, c_m[c_m.len - ChaCha20Poly1305.tag_length ..]);

    try ChaCha20Poly1305.decrypt(
        m,
        c_m[0 .. c_m.len - ChaCha20Poly1305.tag_length],
        tag,
        "",
        payload_nonce,
        payload_key,
    );

    return m;
}
