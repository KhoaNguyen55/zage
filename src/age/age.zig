//! This module provide functions to encrypt and decrypt files using the [age](https://age-encryption.org/) format

const std = @import("std");
const assert = std.debug.assert;

const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const random = std.crypto.random;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const computeHkdfKey = @import("primitives.zig").computeHkdfKey;
const format = @import("format.zig");
const Header = format.Header;
pub const Stanza = format.Stanza;
pub const AnyIdentity = format.AnyIdentity;
pub const AnyRecipient = format.AnyRecipient;
pub const file_key_size = format.file_key_size;

pub const x25519 = @import("x25519.zig");
pub const scrypt = @import("scrypt.zig");

const payload_key_nonce_length = 16;

const payload_label = "payload";
const header_label = format.header_label;
const last_chunk_flag = 0x01;
const payload_nonce_length = 12;
const chunk_size = 64 * 1024;

pub const HeaderError = error{
    MalformedHeader,
    NoValidIdentities,
    MacsNotEqual,
    EmptyLastChunk,
    UnsupportedVersion,
};

pub const PayloadError = error{
    DataAfterEnd,
    DataIsTruncated,
    DecryptFailure,
};

const Error = HeaderError || PayloadError || Allocator.Error;

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
    header: Header,

    /// Initialize the encryption process.
    /// Use `AgeEncryptor.addRecipient()` and `AgeEncryptor.finalizeRecipients()` before `AgeEncryptor.update()`
    /// Use `AgeEncryptor.update()` to write encrypted data to `dest`.
    /// Must use `AgeEncryptor.finish()` to complete the encryption process.
    pub fn encryptInit(
        allocator: Allocator,
    ) anyerror!AgeEncryptor {
        var file_key: [file_key_size]u8 = undefined;
        random.bytes(&file_key);

        const header = Header.init(allocator, file_key);
        errdefer header.destroy();

        return .{
            .payload_key = undefined,
            .payload_nonce = [_]u8{0} ** payload_nonce_length,
            .buffer = [_]u8{0} ** chunk_size,
            .buffer_pos = 0,
            .dest = undefined,
            .header = header,
        };
    }

    /// use `AgeEncryptor.finalizeRecipients()` after all recipients have been added.
    pub fn addRecipient(self: *AgeEncryptor, recipient: anytype) !void {
        errdefer self.header.destroy();
        try self.header.update(recipient, self.file_key);
    }

    /// Finalizes all intended recipients for the encrypted data and write header to `dest`
    pub fn finalizeRecipients(self: *AgeEncryptor, dest: std.io.AnyWriter) !void {
        defer self.header.destroy();
        try self.header.final(self.file_key);

        var key_nonce: [payload_key_nonce_length]u8 = undefined;
        random.bytes(&key_nonce);

        const payload_key = computeHkdfKey(&self.header.file_key, &key_nonce, payload_label);

        try self.dest.print("{mac}\n", .{self.header});
        try self.dest.writeAll(&key_nonce);

        self.payload_key = payload_key;
        self.dest = dest;
    }

    /// Write encrypted data to `AgeEncryptor.dest`
    ///
    /// Must be call after `AgeEncryptor.finalizeRecipients()`, undefined behavior otherwise.
    ///
    /// Note: Data are only written in chunk of 64 KiB, if `source` is less than 64 KiB then another `AgeEncryptor.update()` call is needed, or use `AgeEncryptor.finish()` to finalize the encryption process.
    pub fn update(
        self: *AgeEncryptor,
        source: []const u8,
    ) anyerror!void {
        var written: usize = 0;
        while (written < source.len) {
            const written_size = @min(chunk_size - self.buffer_pos, source.len - written);
            const new_buf_size = self.buffer_pos + written_size;
            const new_written_size = written + written_size;

            @memcpy(self.buffer[self.buffer_pos..new_buf_size], source[written..new_written_size]);

            written = new_written_size;
            self.buffer_pos = new_buf_size;

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

// TODO: redesign this when peeking api get implemented, see https://github.com/ziglang/zig/issues/4501
pub const AgeDecryptor = struct {
    // payload_key: [ChaCha20Poly1305.key_length]u8,
    // payload_nonce: [payload_nonce_length]u8,
    // buffer: [chunk_size]u8,
    // buffer_pos: usize,
    // dest: std.io.AnyWriter,

    pub fn decryptFromReaderToWriter(
        allocator: Allocator,
        identities: []const AnyIdentity,
        dest: std.io.AnyWriter,
        source: std.io.AnyReader,
    ) anyerror!void {
        const header = try Header.parse(allocator, source);
        defer header.destroy();

        const file_key: [file_key_size]u8 = for (identities) |identity| {
            const key = identity.unwrap(header.recipients.items) catch {
                return Error.MalformedHeader;
            };
            if (key) |k| break k;
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
        if (try source.read(&key_nonce) < payload_key_nonce_length) {
            return Error.EmptyLastChunk;
        }

        const payload_key = computeHkdfKey(&file_key, &key_nonce, payload_label);

        var payload_nonce = [_]u8{0} ** payload_nonce_length;
        var encrypt_buffer: [chunk_size + ChaCha20Poly1305.tag_length]u8 = undefined;
        var decrypt_buffer: [chunk_size]u8 = undefined;
        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
        var last = false;

        while (!last) {
            const read_size = try source.read(&encrypt_buffer);
            if (read_size < ChaCha20Poly1305.tag_length) {
                return Error.DataIsTruncated;
            }

            const chunk_end = read_size - ChaCha20Poly1305.tag_length;

            if (chunk_end == 0) {
                if (!std.mem.allEqual(u8, &payload_nonce, 0)) {
                    return Error.EmptyLastChunk;
                }

                var tmp: [1]u8 = undefined;
                if (try source.read(&tmp) > 0) {
                    return Error.DataAfterEnd;
                }
            }

            if (chunk_end < chunk_size) {
                last = true;
                setLastChunkFlag(&payload_nonce);
            }

            @memcpy(&tag, encrypt_buffer[chunk_end .. chunk_end + tag.len]);

            ChaCha20Poly1305.decrypt(
                decrypt_buffer[0..chunk_end],
                encrypt_buffer[0..chunk_end],
                tag,
                "",
                payload_nonce,
                payload_key,
            ) catch {
                last = true;
                setLastChunkFlag(&payload_nonce);

                ChaCha20Poly1305.decrypt(
                    decrypt_buffer[0..chunk_end],
                    encrypt_buffer[0..chunk_end],
                    tag,
                    "",
                    payload_nonce,
                    payload_key,
                ) catch return PayloadError.DecryptFailure;
            };

            try dest.writeAll(decrypt_buffer[0..chunk_end]);
            incrementNonce(&payload_nonce);
        }
    }
};

test {
    _ = @import("bech32.zig");
    _ = @import("format.zig");
    _ = @import("x25519.zig");
}
