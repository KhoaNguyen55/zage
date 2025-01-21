const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const bech32 = @import("bech32.zig");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;

const structs = @import("structs.zig");
const AnyIdentity = structs.AnyIdentity;
const Stanza = structs.Stanza;

const testing = std.testing;
const test_allocator = std.testing.allocator;

const secret_key_hrp = "AGE-SECRET-KEY-";
const public_key_hrp = "age";
const identity_type = "X25519";

const Error = error{
    WrongKeyHrp,
    InvalidX25519SecretKey,
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
            return Error.WrongKeyHrp;
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

    pub fn unwrap(context: *const anyopaque, stanzas: []Stanza) ![]u8 {
        const self: *const X25519Identity = @ptrCast(@alignCast(context));
        for (stanzas) |stanza| {
            if (std.mem.eql(
                stanza.type,
            )) {}
        }
        // TODO: parse stanzas and get out file key
        return undefined;
    }

    pub fn any(self: *const X25519Identity) AnyIdentity {
        return AnyIdentity{ .context = self, .unwrapFn = unwrap };
    }
};

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
