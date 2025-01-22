const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const bech32 = @import("bech32.zig");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const base64Decoder = std.base64.standard_no_pad.Decoder;

const structs = @import("structs.zig");
const AnyIdentity = structs.AnyIdentity;
const Stanza = structs.Stanza;

const testing = std.testing;
const test_allocator = std.testing.allocator;

const file_key_size = 16;

const secret_key_hrp = "AGE-SECRET-KEY-";
const public_key_hrp = "age";
const identity_type = "X25519";

const Error = error{
    InvalidX25519Hrp,
    InvalidStanza,
    InvalidX25519SecretKey,
    InvalidCipherTextSize,
};

const X25519Identity = struct {
    secret_key: [X25519.secret_length]u8,
    our_public_key: [X25519.public_length]u8,

    pub fn parse(key: []const u8) !X25519Identity {
        var buffer: [512]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buffer);
        const allocator = fba.allocator();

        const decoded_key = try bech32.decode(allocator, key);
        defer {
            allocator.free(decoded_key.hrp);
            allocator.free(decoded_key.data);
        }

        if (!std.mem.eql(u8, decoded_key.hrp, secret_key_hrp)) {
            return Error.InvalidX25519Hrp;
        }

        if (decoded_key.data.len != X25519.secret_length) {
            return Error.InvalidX25519SecretKey;
        }
        const secret_key = decoded_key.data[0..X25519.secret_length].*;
        const public_key = try X25519.recoverPublicKey(secret_key);

        return X25519Identity{
            .secret_key = secret_key,
            .our_public_key = public_key,
        };
    }

    pub fn unwrap(context: *const anyopaque, stanzas: []const Stanza) anyerror![]u8 {
        const self: *const X25519Identity = @ptrCast(@alignCast(context));
        var file_key: [file_key_size]u8 = undefined;
        for (stanzas) |stanza| {
            if (!std.mem.eql(u8, stanza.type, identity_type)) {
                continue;
            }

            if (stanza.args.len != 1) {
                return Error.InvalidStanza;
            }

            const public_key_encrypted = stanza.args[0];
            const decrypted_len = try base64Decoder.calcSizeForSlice(public_key_encrypted);
            if (decrypted_len != X25519.public_length) {
                return Error.InvalidStanza;
            }

            var public_key: [X25519.public_length]u8 = undefined;
            try base64Decoder.decode(&public_key, public_key_encrypted);

            const shared_secret = try X25519.scalarmult(self.secret_key, public_key);
            if (std.mem.allEqual(u8, &shared_secret, 0x00)) {
                return Error.InvalidStanza;
            }

            var salt: [X25519.public_length * 2]u8 = undefined;
            @memcpy(salt[0..public_key.len], &public_key);
            @memcpy(salt[public_key.len..], &self.our_public_key);

            const wrap_key: [32]u8 = HkdfSha256.extract(&salt, &shared_secret);

            std.debug.print("Stanza body: {any}\n", .{stanza.body});
            if (stanza.body.len != file_key_size + ChaCha20Poly1305.tag_length) {
                return Error.InvalidCipherTextSize;
            }

            const nonce = [_]u8{0x00} ** ChaCha20Poly1305.nonce_length;

            try ChaCha20Poly1305.decrypt(
                &file_key,
                stanza.body[0..file_key_size],
                stanza.body[file_key_size..32].*,
                "",
                nonce,
                wrap_key,
            );
        }
        return &file_key;
    }

    pub fn any(self: *const X25519Identity) AnyIdentity {
        return AnyIdentity{ .context = self, .unwrapFn = unwrap };
    }
};

test "decrypt file_key test" {
    const test_string = "X25519 A76ighm6OB6DbLMzD8SA1Ozg7lAbyG6qNNaNoEC+m1w\np0OFXKOnut5HGzfUsfu26JLBPzOJAokn41L5kLvkNtI\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const stanza = try Stanza.parse(buffer.reader().any(), test_allocator);
    defer stanza.deinit();

    const secret_key = "AGE-SECRET-KEY-1QGN768HAM3H3SDL9WRZZYNP9JESEMEQFLFSJYLZE5A52U55WM2GQH8PMPW";
    const x25519 = try X25519Identity.parse(secret_key);
    _ = try x25519.any().unwrap(&.{stanza});
    // std.debug.print("{any}\n", .{key});
}

test "Identity test" {
    const expected_sec_key = "AGE-SECRET-KEY-1QGN768HAM3H3SDL9WRZZYNP9JESEMEQFLFSJYLZE5A52U55WM2GQH8PMPW";
    const expected_pub_key = "age17mt2y8v5f3chc5dv22jz4unfcqey37v9jtxlcq834hx5cytjvp6s9txfk0";
    const x25519 = try X25519Identity.parse(expected_sec_key);
    const sec_key = try bech32.encode(test_allocator, secret_key_hrp, &x25519.secret_key);
    defer test_allocator.free(sec_key);
    const pub_key = try bech32.encode(test_allocator, public_key_hrp, &x25519.our_public_key);
    defer test_allocator.free(pub_key);
    try testing.expectEqualStrings(pub_key, expected_pub_key);
    try testing.expectEqualStrings(sec_key, expected_sec_key);
}
