const std = @import("std");
const testing = std.testing;
const test_allocator = testing.allocator;
const assert = std.debug.assert;

const FixedBufferStream = std.io.FixedBufferStream;
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

const last_chunk_flag = 0x01;
const payload_label = "payload";
const header_label = "header";

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

pub fn encrypt(
    allocator: Allocator,
    message: []const u8,
    recipients: []const AnyRecipient,
) anyerror![]u8 {
    var file_key: [file_key_size]u8 = undefined;
    random.bytes(&file_key);

    var stanzas = try allocator.alloc(Stanza, recipients.len);
    errdefer {
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
    defer header.deinit();

    const header_no_mac = try std.fmt.allocPrint(allocator, "{nomac}", .{header});
    defer allocator.free(header_no_mac);

    const hmac_key = computeHkdfKey(&file_key, "", header_label);
    var hmac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&hmac, header_no_mac, &hmac_key);

    header.mac = hmac;

    var key_nonce: [payload_key_nonce_length]u8 = undefined;
    random.bytes(&key_nonce);

    const payload_key = computeHkdfKey(&file_key, &key_nonce, payload_label);

    var payload_nonce: [ChaCha20Poly1305.nonce_length]u8 = .{0} ** ChaCha20Poly1305.nonce_length;
    // TODO: split it into chunks of 64KiB
    setLastChunkFlag(&payload_nonce);

    const encrypted_message = try allocator.alloc(u8, message.len);
    defer allocator.free(encrypted_message);
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;

    ChaCha20Poly1305.encrypt(
        encrypted_message,
        &tag,
        message,
        "",
        payload_nonce,
        payload_key,
    );

    const header_string = try std.fmt.allocPrint(allocator, "{mac}\n", .{header});
    defer allocator.free(header_string);
    const completed_msg = try std.mem.concat(allocator, u8, &.{
        header_string,
        &key_nonce,
        encrypted_message,
        &tag,
    });

    return completed_msg;
}

test "Encryting" {
    const test_str = "Hello World!";
    const public_key = "age17mt2y8v5f3chc5dv22jz4unfcqey37v9jtxlcq834hx5cytjvp6s9txfk0";
    const recipient = (try X25519.X25519Recipient.parse(public_key)).any();
    const encrypted = try encrypt(test_allocator, test_str, &.{recipient});
    defer test_allocator.free(encrypted);

    const file = try std.fs.cwd().createFile("test_encrypted.age", .{});
    defer file.close();

    // std.debug.print("encryted\n", .{});
    try file.writeAll(encrypted);
}

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

test "decrypt" {
    const secret_key = "AGE-SECRET-KEY-1QGN768HAM3H3SDL9WRZZYNP9JESEMEQFLFSJYLZE5A52U55WM2GQH8PMPW";
    const identity = try X25519Identity.parse(secret_key);
    const encrypt_file = try std.fs.cwd().openFile("test.age", .{});
    defer encrypt_file.close();
    const message = try decrypt(test_allocator, encrypt_file.reader().any(), &.{identity.any()});
    defer test_allocator.free(message);
    std.debug.print("{s}\n", .{message});
}
