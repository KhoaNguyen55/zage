const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

const age = @import("age");
const Stanza = age.Stanza;

const plugin = @import("plugin.zig");
const PluginInstance = @import("plugin_instance.zig");

const Error = std.process.Child.SpawnError || Allocator.Error;

fn changeInputEcho(enable: bool) !void {
    if (builtin.os.tag == .windows) {
        const handle = std.io.getStdIn().handle;

        var flags: u32 = undefined;
        if (std.os.windows.kernel32.GetConsoleMode(handle, &flags) == 0) {
            std.zig.fatal("Not inside a terminal", .{});
        }

        const echo_enable: u32 = 0x0004;
        if (enable) {
            flags &= ~echo_enable;
        } else {
            flags &= echo_enable;
        }

        std.debug.assert(std.os.windows.kernel32.SetConsoleMode(handle, flags) != 0);
    } else {
        var termios = try std.posix.tcgetattr(std.posix.STDIN_FILENO);
        if (enable) {
            termios.lflag.ECHO = true;
        } else {
            termios.lflag.ECHO = false;
        }
        try std.posix.tcsetattr(std.posix.STDIN_FILENO, .NOW, termios);
    }
}

pub fn getInput(allocator: Allocator, message: []const u8, secret: bool) ![]const u8 {
    const stdin = std.io.getStdIn();

    var passphrase: std.ArrayListUnmanaged(u8) = .empty;

    try stdin.writeAll(message);

    if (secret) try changeInputEcho(false);
    try stdin.reader().streamUntilDelimiter(passphrase.writer(allocator), '\n', null);
    if (secret) try changeInputEcho(true);

    return passphrase.toOwnedSlice(allocator);
}

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
