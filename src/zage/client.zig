const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

const age = @import("age");
const Stanza = age.Stanza;
const file_key_size = age.file_key_size;

const plugin = @import("age_plugin");
const PluginInstance = plugin.PluginInstance;
const Handler = plugin.ClientHandler;

const Error = Allocator.Error || error{
    BadBech32String,
    UnableToStartPlugin,
};

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

pub const ClientUI = struct {
    plugin: PluginInstance,
    bech32: []const u8,
    identity: bool,
    stanza: ?Stanza = null,

    /// Use `ClientUI.destroy()` to close the plugin instance
    pub fn create(allocator: Allocator, bech32: []const u8, identity: bool) Error!ClientUI {
        const name, const data = switch (identity) {
            true => plugin.parser.parseRecipient(allocator, bech32) catch return Error.BadBech32String,
            false => plugin.parser.parseIdentity(allocator, bech32) catch return Error.BadBech32String,
        };

        defer {
            allocator.free(name);
            allocator.free(data);
        }

        const plugin_instance = blk: {
            if (identity) {
                break :blk PluginInstance.create(allocator, name, plugin.StateMachine.V1.identity);
            } else {
                break :blk PluginInstance.create(allocator, name, plugin.StateMachine.V1.recipient);
            }
        } catch {
            return Error.UnableToStartPlugin;
        };

        return ClientUI{
            .plugin = plugin_instance,
            .bech32 = bech32,
            .identity = identity,
        };
    }

    pub fn wrap(self: *ClientUI, _: Allocator, file_key: []const u8) anyerror!Stanza {
        if (self.identity) {
            try self.plugin.sendIdentity(self.bech32);
        } else {
            try self.plugin.sendRecipient(self.bech32);
        }
        try self.plugin.wrapFileKey(file_key);
        try self.plugin.sendGrease();
        try self.plugin.sendDone();

        // phase 2
        var loop = true;
        while (loop) : ({
            loop = !(self.plugin.handleResponse(self.handler()) catch |err| {
                std.log.err("zage error: {s}", .{@errorName(err)});
                return err;
            });
        }) {}

        return self.stanza orelse error.DidNotRecieveStanza;
    }

    pub fn unwrap(self: *ClientUI, stanzas: []const Stanza) anyerror!?[file_key_size]u8 {
        _ = self;
        _ = stanzas;
        return [_]u8{0} ** file_key_size;
    }

    // TODO: extension lables

    pub fn destroy(self: *ClientUI) void {
        self.plugin.destroy();
        if (self.stanza) |stanza| {
            stanza.destroy();
        }
    }

    // handlers

    fn handler(self: *ClientUI) Handler {
        return Handler{
            .context = self,
            .message = messageHandler,
            .confirm = confirm,
            .request = request,
            .stanza = stanzaHandler,
            .labels = undefined,
            .errors = errors,
        };
    }

    fn messageHandler(_: *anyopaque, _: Allocator, message: []const u8) anyerror!void {
        std.debug.print("{s}\n", .{message});
    }
    fn confirm(_: *anyopaque, allocator: Allocator, yes_string: []const u8, no_string: ?[]const u8, message: []const u8) anyerror!bool {
        while (true) {
            const input = try getInput(allocator, message, false);
            if (std.mem.eql(u8, input, yes_string)) {
                return true;
            }
            if (no_string) |no| {
                if (std.mem.eql(u8, input, no)) {
                    return false;
                } else {
                    std.debug.print("Unrecognized input, only '{s}' or '{s}' are accepted\n", .{ yes_string, no });
                }
            } else {
                return false;
            }
        }
    }
    fn request(_: *anyopaque, allocator: Allocator, message: []const u8, secret: bool) anyerror![]const u8 {
        return getInput(allocator, message, secret);
    }
    fn stanzaHandler(ctx: *anyopaque, _: Allocator, _: usize, stanza: Stanza) anyerror!void {
        const self: *ClientUI = @ptrCast(@alignCast(ctx));

        if (self.stanza != null) {
            return error.MultipleStanzaIsNotAccepted;
        } else {
            self.stanza = stanza;
        }
    }
    // fn labels (_, lables: []const []const u8) anyerror!void {}
    fn errors(_: *anyopaque, allocator: Allocator, error_type: Handler.ErrorType, index: ?usize, message: []const u8) anyerror!void {
        const file_error = blk: {
            if (index) |idx| {
                break :blk try std.fmt.allocPrint(allocator, "at file {}", .{idx});
            } else break :blk "";
        };

        defer if (index) |_| allocator.free(file_error);

        std.log.err("Plugin {s} error {s}: {s}", .{ @tagName(error_type), file_error, message });
    }
};

// pub fn RecipientV1(Recipient: anytype) type {
//     // do type reflection to check for available functions
//
//     return struct {};
// }
