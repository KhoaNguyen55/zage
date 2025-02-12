const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const SHA256 = std.crypto.hash.sha2.Sha256;

const testing = std.testing;
const test_alloctor = testing.allocator;

const age = @import("src/age/age.zig");
const x25519 = @import("src/age/x25519.zig");

const TestExpect = enum {
    Success,
    NoMatch,
    HmacFailure,
    HeaderFailure,
    PayloadFailure,
    ArmorFailure,
};

const Vector = struct {
    allocator: Allocator,
    expect: TestExpect,
    /// X25519 identities
    identities: ArrayList(x25519.X25519Identity),
    /// hex-encoded SHA-256 of the decrypted payload
    payload_hash: [32]u8,
    /// content of the age file
    file: []const u8,
    /// path of the test file
    test_file_name: []const u8,
    /// not implemented
    /// Passphrase for scrypt recipient stanzas,
    passphrase: bool,
    /// Ascii armor
    armored: bool,
    /// gzip compression
    compressed: bool,

    pub fn deinit(self: Vector) void {
        self.identities.deinit();
        //TODO: same for passphrase when it get implemented
        self.allocator.free(self.file);
        self.allocator.free(self.test_file_name);
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

fn parseVector(allocator: Allocator, content: std.io.AnyReader, file_name: []const u8) Vector {
    var test_vector: Vector = .{
        .expect = undefined,
        .test_file_name = undefined,
        .identities = ArrayList(x25519.X25519Identity).init(allocator),
        .payload_hash = undefined,
        .file = undefined,
        .armored = false,
        .compressed = false,
        .passphrase = false,
        .allocator = undefined,
    };
    test_vector.test_file_name = allocator.dupe(u8, file_name) catch @panic("Out of memory");

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
                const identity = x25519.X25519Identity.parse(allocator, header_value) catch {
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

fn parseVectorFolder(allocator: Allocator) []Vector {
    var testkit = std.fs.cwd().openDir("testkit", .{ .iterate = true }) catch {
        @panic("Unable to open `testkit` folder under the current working directory.");
    };
    defer testkit.close();

    var vector_array = ArrayList(Vector).init(allocator);
    errdefer vector_array.deinit();
    var iter = testkit.iterate();
    while (iter.next() catch unreachable) |file| {
        const test_file = testkit.openFile(file.name, .{}) catch unreachable;
        defer test_file.close();
        vector_array.append(parseVector(allocator, test_file.reader().any(), file.name)) catch {
            @panic("Out of memory");
        };
    }

    return vector_array.toOwnedSlice() catch unreachable;
}

fn expectErrorSet(ErrorSet: type, result: anytype, set_name: []const u8) !void {
    if (result) |_| {
        std.debug.print("\nNot an error\n", .{});
        return error.NotAnError;
    } else |err| {
        if (@typeInfo(ErrorSet).ErrorSet) |set| for (set) |err_info| {
            if (std.mem.eql(u8, @errorName(err), err_info.name)) {
                return;
            }
        };

        std.debug.print("\nError: '{s}' not in set '{s}'\n", .{ @errorName(err), set_name });
        return error.NotInErrorSet;
    }
}

fn checkHash(values: []const u8, hash: []const u8) !void {
    var hashed: [SHA256.digest_length]u8 = undefined;
    SHA256.hash(values, &hashed, .{});
    const hexed = std.fmt.bytesToHex(hashed, .lower);
    const trunc_hexed = hexed[0..hash.len];

    try testing.expectEqualSlices(u8, hash, trunc_hexed);
}

fn testVector(allocator: Allocator, test_vector: Vector) !void {
    var buffer = std.io.fixedBufferStream(test_vector.file);
    var decrypted = ArrayList(u8).init(allocator);
    defer decrypted.deinit();

    var any_identities = try allocator.alloc(age.AnyIdentity, test_vector.identities.items.len);
    defer allocator.free(any_identities);

    for (test_vector.identities.items, 0..) |x25519_identity, i| {
        any_identities[i] = x25519_identity.any();
    }

    const decrypt_error = age.AgeDecryptor.decryptFromReaderToWriter(
        allocator,
        any_identities,
        decrypted.writer().any(),
        buffer.reader().any(),
    );

    switch (test_vector.expect) {
        .Success => {
            try testing.expectEqual(void{}, decrypt_error);
            try checkHash(decrypted.items, &test_vector.payload_hash);
        },
        .NoMatch => {
            try testing.expectError(age.HeaderError.NoValidIdentities, decrypt_error);
        },
        .HmacFailure => {
            try testing.expectError(age.HeaderError.MacsNotEqual, decrypt_error);
        },
        .HeaderFailure => {
            try expectErrorSet(age.HeaderError, decrypt_error, "HeaderError");
        },
        .PayloadFailure => {
            try expectErrorSet(age.PayloadError, decrypt_error, "PayloadError");
            try checkHash(decrypted.items, &test_vector.payload_hash);
        },
        else => unreachable,
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

    var failed = false;

    for (vectors) |vector| {
        if (vector.armored or vector.compressed or vector.passphrase or vector.expect == .ArmorFailure) {
            // unsupported
            continue;
        }

        testVector(test_alloctor, vector) catch {
            failed = true;
            std.debug.print("Failed test: {s}\n\n", .{vector.test_file_name});
            std.debug.print("++++++++++++++++++++++++++++++++++++++++\n", .{});
        };
    }

    if (failed) return error.FailedTestKit;
}
