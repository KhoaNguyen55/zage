const std = @import("std");
const Allocator = std.mem.Allocator;

// pub const PluginInstance = @import("plugin_instance.zig");
// pub const Client = @import("client.zig");
const bech32 = @import("bech32");

pub const StateMachine = struct {
    pub const V1 = enum([]const u8) {
        recipient = "recipient-v1",
        identity = "identity-v1",
    };
};

/// Parse a recipient bech32 encoded string
/// Caller owned the returned memory
pub fn parseRecipient(
    allocator: Allocator, 
    string: []const u8,
) anyerror!struct {name: []const u8, data:[]const u8} {
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

    return .{.name = plugin_name, .data = plugin_recipient.data};
}


pub fn parseIdentity(
    allocator: Allocator, 
    string: []const u8,
) anyerror!struct {name: []const u8, data:[]const u8} {
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

    return .{.name = plugin_name, .data = plugin_identity.data};
}

test "parse recipient" {
    const testing = std.testing;
    const test_alloc = testing.allocator;

    const recipient_string = try bech32.encode(test_alloc, "age1testname", "testdata");
    defer test_alloc.free(recipient_string);

    const plugin = try parseRecipient(test_alloc, recipient_string);
    defer {
        test_alloc.free(plugin.name);
        test_alloc.free(plugin.data);
    }

    try testing.expectEqualStrings("testname", plugin.name);
    try testing.expectEqualStrings("testdata", plugin.data);
}


test "parse identity" {
    const testing = std.testing;
    const test_alloc = testing.allocator;

    const identity_string = try bech32.encode(test_alloc, "AGE-PLUGIN-TESTNAME-", "testdata");
    defer test_alloc.free(identity_string);

    const plugin = try parseIdentity(test_alloc, identity_string);
    defer {
        test_alloc.free(plugin.name);
        test_alloc.free(plugin.data);
    }

    try testing.expectEqualStrings("testname", plugin.name);
    try testing.expectEqualStrings("testdata", plugin.data);
}

