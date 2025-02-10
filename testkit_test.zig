const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const SHA256 = std.crypto.hash.sha2.Sha256;

const testing = std.testing;
const test_alloctor = testing.allocator;

const age = @import("age/age.zig");
const x25519 = @import("age/x25519.zig");

const TestExpect = enum {
    Success,
    NoMatch,
    HmacFailure,
    HeaderFailure,
    PayloadFailure,
    ArmorFailure,
};

const TestVector = struct {
    allocator: Allocator,
    expect: TestExpect,
    /// X25519 identities
    identities: ArrayList(x25519.X25519Identity),
    /// hex-encoded SHA-256 of the decrypted payload
    payload_hash: [32]u8,
    /// content of the age file
    file: []const u8,
    /// not implemented
    /// Passphrase for scrypt recipient stanzas,
    passphrase: bool,
    /// Ascii armor
    armored: bool,
    /// gzip compression
    compressed: bool,

    pub fn deinit(self: TestVector) void {
        self.identities.deinit();
        //TODO: same for passphrase when it get implemented
        self.allocator.free(self.file);
    }
};

fn parseExpect(expect: []const u8) TestExpect {
    if (std.mem.eql(u8, expect, "success")) {
        return TestExpect.Success;
    } else if (std.mem.eql(u8, expect, "no match")) {
        return TestExpect.NoMatch;
    } else if (std.mem.eql(u8, expect, "HMAC failure")) {
        return TestExpect.HmacFailure;
    } else if (std.mem.eql(u8, expect, "header failure")) {
        return TestExpect.HeaderFailure;
    } else if (std.mem.eql(u8, expect, "payload failure")) {
        return TestExpect.PayloadFailure;
    } else if (std.mem.eql(u8, expect, "armor failure")) {
        return TestExpect.ArmorFailure;
    } else unreachable;
}

fn parseVector(allocator: Allocator, content: std.io.AnyReader) TestVector {
    var test_vector: TestVector = .{
        .expect = undefined,
        .identities = ArrayList(x25519.X25519Identity).init(allocator),
        .payload_hash = undefined,
        .file = undefined,
        .armored = false,
        .compressed = false,
        .passphrase = false,
        .allocator = undefined,
    };

    var buffer = ArrayList(u8).init(allocator);
    defer buffer.deinit();
    while (true) {
        content.streamUntilDelimiter(buffer.writer(), '\n', null) catch unreachable;
        var split = std.mem.splitSequence(u8, buffer.items, ": ");
        const header_key = split.first();
        if (split.next()) |header_value| {
            if (std.mem.eql(u8, header_key, "expect")) {
                test_vector.expect = parseExpect(header_value);
            } else if (std.mem.eql(u8, header_key, "payload")) {
                test_vector.payload_hash = header_value[0..32].*;
            } else if (std.mem.eql(u8, header_key, "identity")) {
                const identity = x25519.X25519Identity.parse(header_value) catch {
                    @panic("Can't parse identity, is test file correct? or spec version matched?");
                };
                test_vector.identities.append(identity) catch {
                    @panic("Out of memory");
                };
            } else if (std.mem.eql(u8, header_key, "passphrase")) {
                test_vector.passphrase = true;
            } else if (std.mem.eql(u8, header_key, "armored")) {
                test_vector.armored = true;
            } else if (std.mem.eql(u8, header_key, "compressed")) {
                test_vector.compressed = true;
            } else if (std.mem.eql(u8, header_key, "file key")) {
                // ignore
            } else if (std.mem.eql(u8, header_key, "comment")) {
                // ignore
            } else unreachable;

            buffer.clearAndFree();
        } else if (std.mem.eql(u8, "", header_key)) {
            const file = content.readAllAlloc(allocator, std.math.maxInt(usize)) catch unreachable;
            test_vector.file = file;
            break;
        } else unreachable;
    }

    test_vector.allocator = allocator;
    return test_vector;
}

fn parseVectorFolder(allocator: Allocator) []TestVector {
    var testkit = std.fs.cwd().openDir("testkit", .{ .iterate = true }) catch {
        @panic("Unable to open `testkit` folder under the current working directory.");
    };
    defer testkit.close();

    var vector_array = ArrayList(TestVector).init(allocator);
    errdefer vector_array.deinit();
    var iter = testkit.iterate();
    while (iter.next() catch unreachable) |file| {
        const test_file = testkit.openFile(file.name, .{}) catch unreachable;
        defer test_file.close();
        vector_array.append(parseVector(allocator, test_file.reader().any())) catch {
            @panic("Out of memory");
        };
    }

    return vector_array.toOwnedSlice() catch unreachable;
}

fn testSuccess(allocator: Allocator, test_vector: TestVector) !void {
    var buffer = std.io.fixedBufferStream(test_vector.file);
    var decrypted = ArrayList(u8).init(allocator);
    defer decrypted.deinit();

    var any_identities = try allocator.alloc(age.AnyIdentity, test_vector.identities.items.len);
    defer allocator.free(any_identities);

    for (test_vector.identities.items, 0..) |x25519_identity, i| {
        any_identities[i] = x25519_identity.any();
    }

    try age.AgeDecryptor.decryptFromReaderToWriter(
        allocator,
        any_identities,
        decrypted.writer().any(),
        buffer.reader().any(),
    );

    var hashed: [SHA256.digest_length]u8 = undefined;
    SHA256.hash(decrypted.items, &hashed, .{});
    const hexed = std.fmt.bytesToHex(hashed, .lower);
    const trunc_hexed = hexed[0..test_vector.payload_hash.len];

    if (!std.mem.eql(u8, &test_vector.payload_hash, trunc_hexed)) {
        std.debug.print("\nIncorrect Payload Hash\n", .{});
        std.debug.print("Expected: {s}\nGot: {s}\n", .{ test_vector.payload_hash, trunc_hexed });
        std.debug.print("\n\n", .{});
        return error.WrongPayloadHash;
    }
}

test "testkit" {
    const vectors = parseVectorFolder(test_alloctor);
    defer {
        for (vectors) |vector| {
            vector.deinit();
        }
        test_alloctor.free(vectors);
    }

    for (vectors) |vector| {
        if (vector.armored or vector.compressed or vector.passphrase) {
            // unsupported
            continue;
        }

        switch (vector.expect) {
            .Success => {
                try testSuccess(test_alloctor, vector);
            },
            else => {
                // unsupported so skipping
            },
        }
    }
}
