const std = @import("std");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub fn computeHkdfKey(ikm: []const u8, salt: []const u8, info: []const u8) [ChaCha20Poly1305.key_length]u8 {
    const prk = HkdfSha256.extract(salt, ikm);
    var key: [ChaCha20Poly1305.key_length]u8 = undefined;
    HkdfSha256.expand(&key, info, prk);
    return key;
}
