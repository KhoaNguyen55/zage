const std = @import("std");
const Allocator = std.mem.Allocator;

const age = @import("age");
const Stanza = age.Stanza;

const plugin = @import("plugin.zig");
const PluginInstance = @import("plugin_instance.zig");

const Error = std.process.Child.SpawnError || Allocator.Error;

pub const ClientRecipient = struct {
    plugin: PluginInstance,

    /// `recipient` is bech32 encoded string
    /// Use ClientRecipient.destroy()
    pub fn create(allocator: Allocator, recipient: []const u8) Error!ClientRecipient {
        const parsed = try plugin.parseRecipient(recipient);
        defer {
            allocator.free(parsed.name);
            allocator.free(parsed.data);
        };

        // TODO: make the handler
        const handle = .{};

        const plugin = PluginInstance.create(allocator, parsed.name, handler);
        try plugin.sendRecipient(recipient);
        return ClientRecipient{
            .plugin = plugin,
        };
    }

    pub fn wrap(self: ClientRecipient, allocator: Allocator, file_key: []const u8) anyerror!Stanza {

        // if read_size == 0 return error.BrokenPipe
    }

    // extension lables

    pub fn destroy(self: ClientRecipient) void {
        // TODO: maybe log the output of plugin or ignore it.
        _ = self.plugin.kill();
    }
};

// pub fn RecipientV1(Recipient: anytype) type {
//     // do type reflection to check for available functions
//
//     return struct {};
// }
