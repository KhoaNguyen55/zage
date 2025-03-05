const std = @import("std");
const Allocator = std.mem.Allocator;

const age = @import("age");
const Stanza = age.Stanza;

const PluginInstance = @import("plugin_instance.zig");

const Error = std.process.Child.SpawnError || Allocator.Error;

const ClientRecipient = struct {
    allocator: Allocator,
    plugin: PluginInstance,

    pub fn create(allocator: Allocator, plugin_name: []const u8) Error!ClientRecipient {
        const plugin = PluginInstance.create(allocator, plugin_name);
        return ClientRecipient{
            .plugin = plugin,
        };
    }

    pub fn wrap(self: ClientRecipient, _: Allocator, file_key: []const u8) anyerror!Stanza {

        // if read_size == 0 return error.BrokenPipe
    }

    // extension lables

    pub fn destroy(self: ClientRecipient) void {
        self.plugin.wait();
    }
};

// pub fn RecipientV1(Recipient: anytype) type {
//     // do type reflection to check for available functions
//
//     return struct {};
// }
