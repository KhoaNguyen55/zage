const std = @import("std");
const StateMachine = @import("plugin.zig");
const Allocator = std.mem.Allocator;
const age = @import("age");
const Stanza = age.Stanza;
const base64Encoder = std.base64.standard_no_pad.Encoder;
const base64Decoder = std.base64.standard_no_pad.Decoder;

pub const PluginStdInError = std.fs.File.WriteError || Allocator.Error;

pub const Handler = struct {
    pub const ErrorType = enum {
        Recipient,
        Identity,
        Internal,
    };

    context: *const anyopaque,

    message: *const fn (self: *const anyopaque, message: []const u8) anyerror!void,
    confirm: *const fn (self: *const anyopaque, yes_string: []const u8, no_string: ?[]const u8, message: []const u8) anyerror!bool,
    request: *const fn (self: *const anyopaque, message: []const u8, secret: bool) anyerror![]const u8,
    stanza: *const fn (self: *const anyopaque, file_index: usize, stanza: Stanza) anyerror!void,
    // labels: *const fn (self: *const anyopaque, lables: []const []const u8) anyerror!void,
    errors: *const fn (self: *const anyopaque, error_type: ErrorType, index: ?usize, message: []const u8) anyerror!void,
};

// the plugin instance

allocator: Allocator,
handler: Handler,
plugin: std.process.Child,
stdin: std.fs.File,
stdout: std.fs.File,
stderr: std.fs.File,

const PluginInstance = @This();

pub fn create(allocator: Allocator, plugin_name: []const u8, handler: Handler) PluginInstance {
    const plugin_exec = try std.fmt.allocPrint(allocator, "age-plugin-{s}", .{plugin_name});
    const plugin_args = try std.fmt.allocPrint(allocator, "--age-plugin={s}", .{StateMachine.V1.recipient});
    var plugin = std.process.Child.init(&[_][]u8{ plugin_exec, plugin_args }, allocator);
    plugin.stdin_behavior = .Pipe;
    plugin.stdout_behavior = .Pipe;
    plugin.stderr_behavior = .Pipe;
    try plugin.spawn();

    return PluginInstance{
        .allocator = allocator,
        .handler = handler,
        .plugin = plugin,
        .stdin = plugin.stdin.?,
        .stdout = plugin.stdoput.?,
        .stderr = plugin.stderr.?,
    };
}

/// `Not Implemented`
pub fn extensionLabels(self: PluginInstance) void {
    try self.stdin.writeAll("(extension-labels)");
    @panic("Not Implemented");
}

pub fn wrapFileKey(self: PluginInstance, file_key: []const u8) PluginStdInError!void {
    const size = base64Encoder.calcSize(file_key);
    const body_encode = try self.allocator.alloc(u8, size);
    defer self.allocator.free(body_encode);
    _ = base64Encoder.encode(body_encode, file_key);

    const data = try std.fmt.allocPrint(self.allocator, "-> wrap-file-key\n{s}\n", .{file_key});
    defer self.allocator.free(data);
    try self.stdin.writeAll(data);
}

/// `identity` is a Bech32 encoded string
pub fn addIdentity(self: PluginInstance, identity: []const u8) PluginStdInError!void {
    const data = try std.fmt.allocPrint(self.allocator, "-> add-identity {s}\n", .{identity});
    defer self.allocator.free(data);
    try self.stdin.writeAll(data);
}

/// `recipient` is a Bech32 encoded string
pub fn addRecipient(self: PluginInstance, recipient: []const u8) PluginStdInError!void {
    const data = try std.fmt.allocPrint(self.allocator, "-> add-recipient {s}\n", .{recipient});
    defer self.allocator.free(data);
    try self.stdin.writeAll(data);
}

pub fn sendDone(self: PluginInstance) PluginStdInError!void {
    try self.stdin.writeAll("-> done\n");
}

fn sendCommand(self: PluginInstance, command: []const u8, args: []const []const u8, data: []const u8) PluginStdInError!void {
    const stanza = try Stanza.create(self.allocator, command, args, data);
    defer stanza.destroy();

    try std.fmt.format(self.stdin.writer(), "{s}\n", .{stanza});
}

fn sendFail(self: PluginInstance) PluginStdInError!void {
    return self.stdin.writeAll("-> fail\n");
}

fn sendOk(self: PluginInstance) PluginStdInError!void {
    return self.stdin.writeAll("-> ok\n");
}

pub fn handleResponse(self: PluginInstance) PluginStdInError!void {
    const response = try Stanza.parseFromReader(self.allocator, self.stdout.reader().any());
    defer response.destroy();

    if (std.mem.eql(u8, response.type, "msg")) {
        self.handler.message(self.handler.context, response.body) catch {
            return self.sendFail();
        };
        return self.sendOk();
    } else if (std.mem.eql(u8, response.type, "confirm")) {
        const size = try base64Decoder.calcSizeForSlice(response.args[0]);
        const yes_string = try self.allocator.alloc(u8, size);
        defer self.allocator.free(yes_string);
        _ = base64Decoder.decode(&yes_string, response.args[0]);

        var no_string: ?[]u8 = null;
        if (response.args.len == 2) {
            const no_size = try base64Decoder.calcSizeForSlice(response.args[1]);
            no_string = try self.allocator.alloc(u8, no_size);
            _ = base64Decoder.decode(&no_string.?, response.args[1]);
        }
        defer {
            if (no_string) |str| {
                self.allocator.free(str);
            }
        }

        const confirmation = self.handler.confirm(
            self.handler.context,
            yes_string,
            no_string,
            response.body,
        ) catch {
            return self.sendFail();
        };

        return self.sendCommand("ok", &.{if (confirmation) "yes" else "no"}, &.{});
    } else if (std.mem.eql(u8, response.type, "request-public")) {
        //
    } else if (std.mem.eql(u8, response.type, "request-secret")) {
        //
    } else if (std.mem.eql(u8, response.type, "recipient-stanza")) {
        //
    } else if (std.mem.eql(u8, response.type, "error")) {
        //
    } else if (std.mem.eql(u8, response.type, "labels")) {
        // not implemented
    } else if (std.mem.eql(u8, response.type, "done")) {
        //
    } else {
        return error.UnknownResponseCommand;
    }
}

pub fn destroy(self: PluginInstance) void {
    self.plugin.wait();
}
