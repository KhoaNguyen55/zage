const std = @import("std");
const Allocator = std.mem.Allocator;

const bech32 = @import("bech32");

/// Parse a recipient bech32 encoded string
/// Caller owned the returned memory
pub fn parseRecipient(
    allocator: Allocator,
    string: []const u8,
) anyerror!struct { []const u8, []const u8 } {
    const plugin_recipient = try bech32.decode(allocator, string);
    defer {
        allocator.free(plugin_recipient.hrp);
    }
    errdefer {
        allocator.free(plugin_recipient.data);
    }

    const name = std.mem.trimLeft(u8, plugin_recipient.hrp, "age1");
    const plugin_name = try allocator.dupe(u8, name);
    errdefer {
        allocator.free(plugin_name);
    }

    return .{ plugin_name, plugin_recipient.data };
}

pub fn parseIdentity(
    allocator: Allocator,
    string: []const u8,
) anyerror!struct { []const u8, []const u8 } {
    const plugin_identity = try bech32.decode(allocator, string);
    defer {
        allocator.free(plugin_identity.hrp);
    }
    errdefer {
        allocator.free(plugin_identity.data);
    }

    const name = std.mem.trimLeft(u8, plugin_identity.hrp, "AGE-PLUGIN-");
    const trim = std.mem.trimRight(u8, name, "-");
    const plugin_name = try std.ascii.allocLowerString(allocator, trim);
    errdefer {
        allocator.free(plugin_name);
    }

    return .{ plugin_name, plugin_identity.data };
}

test "parse recipient" {
    const testing = std.testing;
    const test_alloc = testing.allocator;

    const recipient_string = try bech32.encode(test_alloc, "age1testname", "testdata");
    defer test_alloc.free(recipient_string);

    const name, const data = try parseRecipient(test_alloc, recipient_string);
    defer {
        test_alloc.free(name);
        test_alloc.free(data);
    }

    try testing.expectEqualStrings("testname", name);
    try testing.expectEqualStrings("testdata", data);
}

test "parse identity" {
    const testing = std.testing;
    const test_alloc = testing.allocator;

    const identity_string = try bech32.encode(test_alloc, "AGE-PLUGIN-TESTNAME-", "testdata");
    defer test_alloc.free(identity_string);

    const name, const data = try parseIdentity(test_alloc, identity_string);
    defer {
        test_alloc.free(name);
        test_alloc.free(data);
    }

    try testing.expectEqualStrings("testname", name);
    try testing.expectEqualStrings("testdata", data);
}
