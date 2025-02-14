const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const bech32 = @import("bech32.zig");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const random = std.crypto.random;

const base64Decoder = std.base64.standard_no_pad.Decoder;
const base64Encoder = std.base64.standard_no_pad.Encoder;
const b64Error = std.base64.Error;

const computeHkdfKey = @import("primitives.zig").computeHkdfKey;

const format = @import("format.zig");
const AnyIdentity = format.AnyIdentity;
const AnyRecipient = format.AnyRecipient;
const Stanza = format.Stanza;
const file_key_size = format.file_key_size;

const testing = std.testing;
const test_allocator = std.testing.allocator;

const x25519_label = "age-encryption.org/v1/X25519";
const secret_key_hrp = "AGE-SECRET-KEY-";
const public_key_hrp = "age";
const identity_type = "X25519";

const Error = error{
    InvalidX25519Hrp,
    InvalidStanza,
    InvalidX25519SecretKey,
    InvalidCipherTextSize,
    InvalidFileKeySize,
    InvalidBech32String,
    ShareSecretIsZero,
} || Allocator.Error;

pub const X25519Recipient = struct {
    their_public_key: [X25519.public_length]u8,

    /// Parse X25519 recipient from bech32 encoded public key.
    ///
    /// The returned memory does not need to be free.
    pub fn parse(allocator: Allocator, key: []const u8) Error!X25519Recipient {
        // const decoded_key = try bech32.decode(allocator, key);
        const decoded_key = bech32.decode(allocator, key) catch {
            return Error.InvalidBech32String;
        };
        defer {
            allocator.free(decoded_key.hrp);
            allocator.free(decoded_key.data);
        }

        if (!std.mem.eql(u8, decoded_key.hrp, public_key_hrp)) {
            return Error.InvalidX25519Hrp;
        }

        if (decoded_key.data.len != X25519.public_length) {
            return Error.InvalidCipherTextSize;
        }
        const public_key = decoded_key.data[0..X25519.public_length].*;

        return X25519Recipient{
            .their_public_key = public_key,
        };
    }

    fn wrap(context: *const anyopaque, allocator: Allocator, file_key: []const u8) anyerror!Stanza {
        const self: *const X25519Recipient = @ptrCast(@alignCast(context));

        var ephemeral_secret: [X25519.secret_length]u8 = undefined;
        random.bytes(&ephemeral_secret);

        const ephemeral_share = X25519.recoverPublicKey(ephemeral_secret) catch {
            return Error.ShareSecretIsZero;
        };

        var salt: [X25519.public_length * 2]u8 = undefined;
        @memcpy(salt[0..ephemeral_share.len], &ephemeral_share);
        @memcpy(salt[ephemeral_share.len..], &self.their_public_key);

        const shared_secret = X25519.scalarmult(ephemeral_secret, self.their_public_key) catch {
            return Error.ShareSecretIsZero;
        };

        const nonce = [_]u8{0x00} ** ChaCha20Poly1305.nonce_length;

        const overhead_size = file_key_size + ChaCha20Poly1305.tag_length;

        const wrap_key = computeHkdfKey(&shared_secret, &salt, x25519_label);

        var body: [overhead_size]u8 = undefined;

        ChaCha20Poly1305.encrypt(
            body[0..file_key_size],
            body[file_key_size..],
            file_key,
            "",
            nonce,
            wrap_key,
        );

        return Stanza.create(
            allocator,
            "X25519",
            &.{&ephemeral_share},
            &body,
        );
    }

    pub fn any(self: *const X25519Recipient) AnyRecipient {
        return AnyRecipient{ .context = self, .wrapFn = wrap, .destroyFn = null };
    }
};

pub const X25519Identity = struct {
    secret_key: [X25519.secret_length]u8,
    our_public_key: [X25519.public_length]u8,
    /// Parse X25519 identity from bech32 encoded secret key.
    ///
    /// The returned memory does not need to be free.
    pub fn parse(allocator: Allocator, key: []const u8) Error!X25519Identity {
        const decoded_key = bech32.decode(allocator, key) catch {
            return Error.InvalidBech32String;
        };
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
        const public_key = X25519.recoverPublicKey(secret_key) catch {
            return Error.ShareSecretIsZero;
        };

        return X25519Identity{
            .secret_key = secret_key,
            .our_public_key = public_key,
        };
    }

    fn unwrap(context: *const anyopaque, stanzas: []const Stanza) anyerror!?[file_key_size]u8 {
        const self: *const X25519Identity = @ptrCast(@alignCast(context));

        for (stanzas) |stanza| {
            if (!std.mem.eql(u8, stanza.type, identity_type)) {
                continue;
            }

            if (stanza.args.len != 1) {
                return Error.InvalidStanza;
            }

            const ephemeral_share_encoded = stanza.args[0];
            const decrypted_len = base64Decoder.calcSizeForSlice(ephemeral_share_encoded) catch {
                return Error.InvalidStanza;
            };
            if (decrypted_len != X25519.public_length) {
                return Error.InvalidStanza;
            }

            var ephemeral_share: [X25519.public_length]u8 = undefined;
            base64Decoder.decode(&ephemeral_share, ephemeral_share_encoded) catch |err| switch (err) {
                b64Error.InvalidCharacter, b64Error.InvalidPadding => {
                    return Error.InvalidStanza;
                },
                else => unreachable,
            };

            var salt: [X25519.public_length * 2]u8 = undefined;
            @memcpy(salt[0..ephemeral_share.len], &ephemeral_share);
            @memcpy(salt[ephemeral_share.len..], &self.our_public_key);

            const shared_secret = X25519.scalarmult(self.secret_key, ephemeral_share) catch {
                return Error.ShareSecretIsZero;
            };

            const wrap_key = computeHkdfKey(&shared_secret, &salt, x25519_label);

            const overhead_size = file_key_size + ChaCha20Poly1305.tag_length;

            if (stanza.body.len != overhead_size) {
                return Error.InvalidCipherTextSize;
            }

            const nonce = [_]u8{0x00} ** ChaCha20Poly1305.nonce_length;

            var dest: [file_key_size]u8 = undefined;
            ChaCha20Poly1305.decrypt(
                &dest,
                stanza.body[0..file_key_size],
                stanza.body[file_key_size..overhead_size].*,
                "",
                nonce,
                wrap_key,
            ) catch {
                continue;
            };
            return dest;
        }

        return null;
    }

    pub fn any(self: *const X25519Identity) AnyIdentity {
        return AnyIdentity{ .context = self, .unwrapFn = unwrap, .destroyFn = null };
    }
};

test "encrypt/decrypt file_key" {
    var expected_key: [file_key_size]u8 = undefined;
    random.bytes(&expected_key);

    const public_key = "age17mt2y8v5f3chc5dv22jz4unfcqey37v9jtxlcq834hx5cytjvp6s9txfk0";
    const recipient = (try X25519Recipient.parse(test_allocator, public_key)).any();
    const wrapped_key = try recipient.wrap(test_allocator, &expected_key);
    defer wrapped_key.destroy();

    const secret_key = "AGE-SECRET-KEY-1QGN768HAM3H3SDL9WRZZYNP9JESEMEQFLFSJYLZE5A52U55WM2GQH8PMPW";
    const x25519 = try X25519Identity.parse(test_allocator, secret_key);
    const key = try x25519.any().unwrap(&.{wrapped_key});

    try testing.expectEqualSlices(u8, &expected_key, &key.?);
}

test "Identity parsing" {
    const expected_sec_key = "AGE-SECRET-KEY-1QGN768HAM3H3SDL9WRZZYNP9JESEMEQFLFSJYLZE5A52U55WM2GQH8PMPW";
    const expected_pub_key = "age17mt2y8v5f3chc5dv22jz4unfcqey37v9jtxlcq834hx5cytjvp6s9txfk0";
    const x25519 = try X25519Identity.parse(test_allocator, expected_sec_key);
    const sec_key = try bech32.encode(test_allocator, secret_key_hrp, &x25519.secret_key);
    defer test_allocator.free(sec_key);
    const pub_key = try bech32.encode(test_allocator, public_key_hrp, &x25519.our_public_key);
    defer test_allocator.free(pub_key);
    try testing.expectEqualStrings(pub_key, expected_pub_key);
    try testing.expectEqualStrings(sec_key, expected_sec_key);
}

test "encrypt/decrypt file" {
    const AgeEncryptor = @import("age.zig").AgeEncryptor;
    const AgeDecryptor = @import("age.zig").AgeDecryptor;

    const test_str = "Hello World!";
    const public_key = "age17mt2y8v5f3chc5dv22jz4unfcqey37v9jtxlcq834hx5cytjvp6s9txfk0";
    const recipient = (try X25519Recipient.parse(test_allocator, public_key)).any();
    var array = ArrayList(u8).init(test_allocator);
    errdefer array.deinit();
    var encryptor = try AgeEncryptor.encryptInit(test_allocator, &.{recipient}, array.writer().any());
    try encryptor.update(test_str[0..]);
    try encryptor.finish();

    const secret_key = "AGE-SECRET-KEY-1QGN768HAM3H3SDL9WRZZYNP9JESEMEQFLFSJYLZE5A52U55WM2GQH8PMPW";
    const identity = try X25519Identity.parse(test_allocator, secret_key);

    const owned = try array.toOwnedSlice();
    defer test_allocator.free(owned);
    var encrypt_file = std.io.fixedBufferStream(owned);

    var decryptarray = ArrayList(u8).init(test_allocator);
    errdefer decryptarray.deinit();
    try AgeDecryptor.decryptFromReaderToWriter(
        test_allocator,
        &.{identity.any()},
        decryptarray.writer().any(),
        encrypt_file.reader().any(),
    );

    const got = try decryptarray.toOwnedSlice();
    defer test_allocator.free(got);
    try testing.expectEqualStrings(test_str, got);
}
