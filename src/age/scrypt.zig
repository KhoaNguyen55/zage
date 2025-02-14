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

// pub const ScryptRecipient = struct {
// };

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

    fn unwrap(context: *const anyopaque, stanzas: []const Stanza) anyerror!?[file_key_size]u8 {
        const self: *const ScryptIdentity = @ptrCast(@alignCast(context));

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

    fn destroy(context: *const anyopaque) void {
        const self: *const ScryptIdentity = @ptrCast(@alignCast(context));
        self.allocator.free(self.passphrase);
    }

    pub fn any(self: *const ScryptIdentity) AnyIdentity {
        return AnyIdentity{ .context = self, .unwrapFn = unwrap, .destroyFn = destroy };
    }
};
