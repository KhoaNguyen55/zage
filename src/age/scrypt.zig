const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const scrypt = std.crypto.pwhash.scrypt;
const kdfError = std.crypto.errors;

const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const random = std.crypto.random;

const base64Decoder = std.base64.standard_no_pad.Decoder;
const base64Encoder = std.base64.standard_no_pad.Encoder;
const b64Error = std.base64.Error;

const format = @import("format.zig");
const AnyIdentity = format.AnyIdentity;
const AnyRecipient = format.AnyRecipient;
const Stanza = format.Stanza;
const file_key_size = format.file_key_size;

const testing = std.testing;
const test_allocator = std.testing.allocator;

const scrypt_label = "age-encryption.org/v1/scrypt";
const identity_type = "scrypt";
const salt_length = 16;

const Error = error{
    InvalidStanza,
    InvalidCipherTextSize,
    InvalidFileKeySize,
    ScryptStanzaMustBeAlone,
    WorkFactorLeadingZero,
    WorkFactorTooBig,
} || Allocator.Error;

pub const ScryptRecipient = struct {
    allocator: Allocator,
    passphrase: []const u8,
    work_factor: u6,

    /// Create `ScryptRecipient` from passhprase.
    ///
    /// Caller owns the returned memory, must be free with `AnyRecipient.destroy()`.
    pub fn create(allocator: Allocator, passphrase: []const u8, work_factor: ?u6) Allocator.Error!ScryptRecipient {
        const duped_passphrase = try allocator.dupe(u8, passphrase);
        return ScryptRecipient{
            .allocator = allocator,
            .passphrase = duped_passphrase,
            .work_factor = work_factor orelse 18,
        };
    }

    pub fn wrap(self: ScryptRecipient, _: Allocator, file_key: []const u8) anyerror!Stanza {
        var scrypt_salt: [salt_length]u8 = undefined;
        random.bytes(&scrypt_salt);

        const size = base64Encoder.calcSize(scrypt_salt.len);
        const scrypt_salt_encoded = try self.allocator.alloc(u8, size);
        defer self.allocator.free(scrypt_salt_encoded);
        _ = base64Encoder.encode(scrypt_salt_encoded, &scrypt_salt);

        var salt: [scrypt_label.len + salt_length]u8 = undefined;
        @memcpy(salt[0..scrypt_label.len], scrypt_label);
        @memcpy(salt[scrypt_label.len..], &scrypt_salt);

        var wrap_key: [ChaCha20Poly1305.key_length]u8 = undefined;
        try scrypt.kdf(
            self.allocator,
            &wrap_key,
            self.passphrase,
            &salt,
            .{ .ln = self.work_factor, .p = 1, .r = 8 },
        );

        const overhead_size = file_key_size + ChaCha20Poly1305.tag_length;

        const nonce = [_]u8{0x00} ** ChaCha20Poly1305.nonce_length;

        var body: [overhead_size]u8 = undefined;
        ChaCha20Poly1305.encrypt(
            body[0..file_key_size],
            body[file_key_size..],
            file_key,
            "",
            nonce,
            wrap_key,
        );

        var work_factor_str: [2]u8 = undefined;
        _ = try std.fmt.bufPrint(&work_factor_str, "{}", .{self.work_factor});

        return Stanza.create(
            self.allocator,
            identity_type,
            &.{ scrypt_salt_encoded, &work_factor_str },
            &body,
        );
    }

    pub fn destroy(self: ScryptRecipient) void {
        self.allocator.free(self.passphrase);
    }
};

pub const ScryptIdentity = struct {
    allocator: Allocator,
    passphrase: []const u8,

    /// Create a `ScryptIdentity` from passphrase.
    ///
    /// Caller owns the returned memory, must be free with `AnyIdentity.destroy()`.
    pub fn create(allocator: Allocator, passphrase: []const u8) Allocator.Error!ScryptIdentity {
        const duped_passphrase = try allocator.dupe(u8, passphrase);
        return ScryptIdentity{ .allocator = allocator, .passphrase = duped_passphrase };
    }

    pub fn unwrap(self: ScryptIdentity, stanzas: []const Stanza) anyerror!?[file_key_size]u8 {
        if (stanzas.len != 1) {
            return Error.ScryptStanzaMustBeAlone;
        }

        for (stanzas) |stanza| {
            if (!std.mem.eql(u8, stanza.type, identity_type)) {
                continue;
            }

            if (stanza.args.len != 2) {
                return Error.InvalidStanza;
            }

            const scrypt_salt_encoded = stanza.args[0];
            const decrypted_len = base64Decoder.calcSizeForSlice(scrypt_salt_encoded) catch {
                return Error.InvalidStanza;
            };
            if (decrypted_len != salt_length) {
                return Error.InvalidStanza;
            }

            var scrypt_salt: [salt_length]u8 = undefined;
            base64Decoder.decode(&scrypt_salt, scrypt_salt_encoded) catch |err| switch (err) {
                b64Error.InvalidCharacter, b64Error.InvalidPadding => {
                    return Error.InvalidStanza;
                },
                else => unreachable,
            };

            var salt: [scrypt_label.len + salt_length]u8 = undefined;
            @memcpy(salt[0..scrypt_label.len], scrypt_label);
            @memcpy(salt[scrypt_label.len..], &scrypt_salt);

            const work_factor_str = stanza.args[1];

            // check for leading zeros
            if (work_factor_str[0] == '0') {
                return Error.WorkFactorLeadingZero;
            }

            const work_factor = std.fmt.parseUnsigned(u6, work_factor_str, 10) catch {
                return Error.InvalidStanza;
            };

            if (work_factor > 20) {
                return Error.WorkFactorTooBig;
            }

            var wrap_key: [ChaCha20Poly1305.key_length]u8 = undefined;
            scrypt.kdf(
                self.allocator,
                &wrap_key,
                self.passphrase,
                &salt,
                .{ .ln = work_factor, .p = 1, .r = 8 },
            ) catch {
                continue;
            };

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

    pub fn destroy(self: ScryptIdentity) void {
        self.allocator.free(self.passphrase);
    }
};

test "encrypt/decrypt file_key" {
    var expected_key: [file_key_size]u8 = undefined;
    random.bytes(&expected_key);
    const password = "hunter3";

    const recipient = try ScryptRecipient.create(test_allocator, password, null);
    defer recipient.destroy();

    const wrapped_key = try recipient.wrap(test_allocator, &expected_key);
    defer wrapped_key.destroy();

    const identity = try ScryptIdentity.create(test_allocator, password);
    defer identity.destroy();

    const key = try identity.unwrap(&.{wrapped_key});
    try testing.expectEqualSlices(u8, &expected_key, &key.?);
}
