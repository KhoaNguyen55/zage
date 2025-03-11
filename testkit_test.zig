const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;

const SHA256 = std.crypto.hash.sha2.Sha256;

const testing = std.testing;
const test_alloctor = testing.allocator;

const age = @import("age");
const x25519 = age.x25519;
const scrypt = age.scrypt;

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
    identities: ?ArrayList(x25519.X25519Identity),
    /// Passphrase for scrypt recipient stanzas,
    passphrase: ?ArrayList(scrypt.ScryptIdentity),
    /// hex-encoded SHA-256 of the decrypted payload
    payload_hash: [32]u8,
    /// content of the age file
    file: []const u8,
    /// path of the test file
    test_file_name: []const u8,
    /// Ascii armor
    armored: bool,
    /// gzip compression
    compressed: bool,

    pub fn destroy(self: *Vector) void {
        if (self.identities) |*identities| {
            identities.deinit(self.allocator);
        }
        if (self.passphrase) |*passphrase| {
            for (passphrase.items) |p| {
                p.destroy();
            }
            passphrase.deinit(self.allocator);
        }

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
        .identities = null,
        .passphrase = null,
        .payload_hash = undefined,
        .file = undefined,
        .armored = false,
        .compressed = false,
        .allocator = undefined,
    };
    test_vector.test_file_name = allocator.dupe(u8, file_name) catch @panic("Out of memory");

    var buffer: ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);
    while (true) {
        content.streamUntilDelimiter(buffer.writer(allocator), '\n', null) catch unreachable;
        var split = std.mem.splitSequence(u8, buffer.items, ": ");
        const header_key = split.first();
        if (split.next()) |header_value| {
            if (std.mem.eql(u8, header_key, "expect")) {
                test_vector.expect = parseExpect(header_value);
            } else if (std.mem.eql(u8, header_key, "payload")) {
                test_vector.payload_hash = header_value[0..32].*;
            } else if (std.mem.eql(u8, header_key, "identity")) {
                if (test_vector.identities) |_| {} else {
                    test_vector.identities = .empty;
                }

                const identity = x25519.X25519Identity.parse(allocator, header_value) catch {
                    @panic("Can't parse identity, is test file correct? or spec version matched?");
                };
                test_vector.identities.?.append(allocator, identity) catch {
                    @panic("Out of memory");
                };
            } else if (std.mem.eql(u8, header_key, "passphrase")) {
                if (test_vector.passphrase) |_| {} else {
                    test_vector.passphrase = .empty;
                }

                const identity = scrypt.ScryptIdentity.create(allocator, header_value) catch {
                    @panic("Out of memory");
                };
                test_vector.passphrase.?.append(allocator, identity) catch {
                    @panic("Out of memory");
                };
            } else if (std.mem.eql(u8, header_key, "armored")) {
                test_vector.armored = true;
            } else if (std.mem.eql(u8, header_key, "compressed")) {
                test_vector.compressed = true;
            } else if (std.mem.eql(u8, header_key, "file key")) {
                // ignore
            } else if (std.mem.eql(u8, header_key, "comment")) {
                // ignore
            } else unreachable;

            buffer.clearAndFree(allocator);
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

    var vector_array: ArrayList(Vector) = .empty;
    errdefer vector_array.deinit(allocator);
    var iter = testkit.iterate();
    while (iter.next() catch unreachable) |file| {
        const test_file = testkit.openFile(file.name, .{}) catch unreachable;
        defer test_file.close();
        vector_array.append(allocator, parseVector(allocator, test_file.reader().any(), file.name)) catch {
            @panic("Out of memory");
        };
    }

    return vector_array.toOwnedSlice(allocator) catch unreachable;
}

fn expectErrorSet(ErrorSet: type, result: anytype, set_name: []const u8) !void {
    if (result) |_| {
        std.debug.print("\nExpects: '{s}', got no errors\n", .{set_name});
        return error.NotAnError;
    } else |err| {
        if (@typeInfo(ErrorSet).error_set) |set| for (set) |err_info| {
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

    var decrypted: ArrayList(u8) = .empty;
    defer decrypted.deinit(allocator);

    const decrypt_error = blk: {
        var decryptor = age.AgeDecryptor.decryptInit(allocator, buffer.reader().any()) catch |err| break :blk err;

        if (test_vector.identities) |identities| {
            for (identities.items) |identity| {
                decryptor.addIdentity(identity) catch |err| break :blk err;
            }
        }

        if (test_vector.passphrase) |pass| {
            for (pass.items) |identity| {
                decryptor.addIdentity(identity) catch |err| break :blk err;
            }
        }

        decryptor.finalizeIdentities() catch |err| break :blk err;

        while (decryptor.next() catch |err| break :blk err) |value| {
            try decrypted.appendSlice(allocator, value);
        }
    };

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
        for (vectors) |*vector| {
            vector.destroy();
        }
        test_alloctor.free(vectors);
    }

    var failed = false;

    for (vectors) |vector| {
        if (vector.armored or vector.compressed) {
            // unsupported
            continue;
        }

        testVector(test_alloctor, vector) catch |err| {
            failed = true;
            std.debug.print("Error: {s}\n", .{@errorName(err)});
            std.debug.print("Failed test: {s}\n\n", .{vector.test_file_name});
            std.debug.print("++++++++++++++++++++++++++++++++++++++++\n", .{});
        };
    }

    if (failed) return error.FailedTestKit;
}
