const std = @import("std");
const Allocator = std.mem.Allocator;
const age = @import("age");
const Stanza = age.Stanza;
const base64Encoder = std.base64.standard_no_pad.Encoder;
const base64Decoder = std.base64.standard_no_pad.Decoder;

pub const ClientHandler = struct {
    pub const ErrorType = enum {
        Recipient,
        Identity,
        Internal,
    };

    context: *anyopaque,

    message: *const fn (context: *anyopaque, allocator: Allocator, message: []const u8) anyerror!void,
    confirm: *const fn (context: *anyopaque, allocator: Allocator, yes_string: []const u8, no_string: ?[]const u8, message: []const u8) anyerror!bool,
    request: *const fn (context: *anyopaque, allocator: Allocator, message: []const u8, secret: bool) anyerror![]const u8,
    stanza: *const fn (context: *anyopaque, allocator: Allocator, file_index: usize, stanza: Stanza) anyerror!void,
    labels: *const fn (context: *anyopaque, allocator: Allocator, lables: []const []const u8) anyerror!void,
    errors: *const fn (context: *anyopaque, allocator: Allocator, error_type: ErrorType, index: ?usize, message: []const u8) anyerror!void,
};

// the plugin instance
pub const PluginStdInError = std.fs.File.WriteError || Allocator.Error;
pub const PluginHandleError = error{
    MalformedCommandFromPlugin,
};

pub const ClientInterface = struct {
    allocator: Allocator,
    plugin: std.process.Child,
    stdin: std.fs.File,
    stdout: std.fs.File,
    stderr: std.fs.File,

    pub fn create(allocator: Allocator, plugin_name: []const u8, version: []const u8) !ClientInterface {
        const plugin_exec = try std.fmt.allocPrint(allocator, "age-plugin-{s}", .{plugin_name});
        const plugin_args = try std.fmt.allocPrint(allocator, "--age-plugin={s}", .{version});
        var plugin = std.process.Child.init(&[_][]u8{ plugin_exec, plugin_args }, allocator);
        plugin.stdin_behavior = .Pipe;
        plugin.stdout_behavior = .Pipe;
        plugin.stderr_behavior = .Pipe;
        try plugin.spawn();

        return ClientInterface{
            .allocator = allocator,
            .plugin = plugin,
            .stdin = plugin.stdin.?,
            .stdout = plugin.stdout.?,
            .stderr = plugin.stderr.?,
        };
    }

    /// `Not Implemented`
    pub fn extensionLabels(self: *ClientInterface) void {
        _ = self;
        @panic("Not Implemented");
        // try self.stdin.writeAll("(extension-labels)");
    }

    pub fn wrapFileKey(self: *ClientInterface, file_key: [age.file_key_size]u8) PluginStdInError!void {
        var body_encode: [base64Encoder.calcSize(age.file_key_size)]u8 = undefined;
        _ = base64Encoder.encode(&body_encode, &file_key);

        try self.stdin.writer().print("-> wrap-file-key\n{s}\n", .{body_encode});
    }

    /// `identity` is a Bech32 encoded string
    pub fn sendIdentity(self: *ClientInterface, identity: []const u8) PluginStdInError!void {
        try self.stdin.writer().print("-> add-identity {s}\n", .{identity});
    }

    /// `recipient` is a Bech32 encoded string
    pub fn sendRecipient(self: *ClientInterface, recipient: []const u8) PluginStdInError!void {
        try self.stdin.writer().print("-> add-recipient {s}\n", .{recipient});
    }

    pub fn sendDone(self: *ClientInterface) PluginStdInError!void {
        try self.stdin.writeAll("-> done\n");
    }

    pub fn sendGrease(self: *ClientInterface) PluginStdInError!void {
        var random = std.Random.DefaultPrng.init(@as(u64, @bitCast(std.time.milliTimestamp())));

        var args_bytes: [16]u8 = undefined;
        random.random().bytes(&args_bytes);

        var args_encoded: [22]u8 = undefined;
        _ = base64Encoder.encode(&args_encoded, &args_bytes);

        var body_bytes: [256]u8 = undefined;
        random.random().bytes(&body_bytes);

        try self.sendCommand("grease", &.{&args_encoded}, &body_bytes);
    }

    fn sendCommand(self: *ClientInterface, command: []const u8, args: []const []const u8, data: []const u8) PluginStdInError!void {
        const stanza = try Stanza.create(self.allocator, command, args, data);
        defer stanza.destroy();

        try self.stdin.writer().print("{s}\n", .{stanza});
    }

    fn sendFail(self: *ClientInterface) PluginStdInError!void {
        return self.stdin.writeAll("-> fail\n");
    }

    fn sendOk(self: *ClientInterface) PluginStdInError!void {
        return self.stdin.writeAll("-> ok\n");
    }

    /// Handle responses from the plugin, return `true` if the plugin sent `(done)` otherwise `false`
    pub fn handleResponse(self: *ClientInterface, handler: ClientHandler) (PluginStdInError || PluginHandleError)!bool {
        const response = Stanza.parseFromReader(self.allocator, self.stdout.reader().any()) catch {
            return PluginHandleError.MalformedCommandFromPlugin;
        };
        defer response.destroy();

        handle: {
            if (std.mem.eql(u8, response.type, "msg")) {
                handler.message(handler.context, self.allocator, response.body) catch {
                    try self.sendFail();
                    break :handle;
                };
                try self.sendOk();
            } else if (std.mem.eql(u8, response.type, "confirm")) {
                if (response.args.len == 0 or response.args.len > 2) {
                    return PluginHandleError.MalformedCommandFromPlugin;
                }

                const size = base64Decoder.calcSizeForSlice(response.args[0]) catch {
                    return PluginHandleError.MalformedCommandFromPlugin;
                };
                const yes_string = try self.allocator.alloc(u8, size);
                defer self.allocator.free(yes_string);
                base64Decoder.decode(yes_string, response.args[0]) catch {
                    return PluginHandleError.MalformedCommandFromPlugin;
                };

                var no_string: ?[]u8 = null;
                if (response.args.len == 2) {
                    const no_size = base64Decoder.calcSizeForSlice(response.args[1]) catch {
                        return PluginHandleError.MalformedCommandFromPlugin;
                    };
                    no_string = try self.allocator.alloc(u8, no_size);
                    base64Decoder.decode(no_string.?, response.args[1]) catch {
                        return PluginHandleError.MalformedCommandFromPlugin;
                    };
                }
                defer {
                    if (no_string) |str| {
                        self.allocator.free(str);
                    }
                }

                const confirmation = handler.confirm(
                    handler.context,
                    self.allocator,
                    yes_string,
                    no_string,
                    response.body,
                ) catch {
                    try self.sendFail();
                    break :handle;
                };

                try self.sendCommand("ok", &.{if (confirmation) "yes" else "no"}, &.{});
            } else if (std.mem.eql(u8, response.type, "request-public")) {
                const public = handler.request(
                    handler.context,
                    self.allocator,
                    response.body,
                    false,
                ) catch {
                    try self.sendFail();
                    break :handle;
                };
                try self.sendCommand("ok", &.{}, public);
            } else if (std.mem.eql(u8, response.type, "request-secret")) {
                const secret = handler.request(
                    handler.context,
                    self.allocator,
                    response.body,
                    true,
                ) catch {
                    try self.sendFail();
                    break :handle;
                };
                try self.sendCommand("ok", &.{}, secret);
            } else if (std.mem.eql(u8, response.type, "recipient-stanza")) {
                if (response.args.len < 2) {
                    return PluginHandleError.MalformedCommandFromPlugin;
                }

                const stanza = try age.Stanza.create(
                    self.allocator,
                    response.args[1],
                    response.args[2..],
                    response.body,
                );
                const file_idx = std.fmt.parseInt(usize, response.args[0], 10) catch {
                    return PluginHandleError.MalformedCommandFromPlugin;
                };
                handler.stanza(
                    handler.context,
                    self.allocator,
                    file_idx,
                    stanza,
                ) catch {
                    try self.sendFail();
                    break :handle;
                };
                try self.sendOk();
            } else if (std.mem.eql(u8, response.type, "error")) {
                if (response.args.len > 2) {
                    return PluginHandleError.MalformedCommandFromPlugin;
                }

                var file_idx: ?usize = null;
                if (response.args.len == 2) {
                    file_idx = std.fmt.parseInt(usize, response.args[1], 10) catch {
                        return PluginHandleError.MalformedCommandFromPlugin;
                    };
                }

                var error_type: ClientHandler.ErrorType = undefined;
                if (std.mem.eql(u8, response.args[0], "recipient")) {
                    error_type = ClientHandler.ErrorType.Recipient;
                } else if (std.mem.eql(u8, response.args[0], "identity")) {
                    error_type = ClientHandler.ErrorType.Identity;
                } else if (std.mem.eql(u8, response.args[0], "internal")) {
                    error_type = ClientHandler.ErrorType.Internal;
                } else {
                    return PluginHandleError.MalformedCommandFromPlugin;
                }

                handler.errors(
                    handler.context,
                    self.allocator,
                    error_type,
                    file_idx,
                    response.body,
                ) catch {
                    @panic("Something have gone horribly wrong, theres errors when handling errors");
                };

                try self.sendOk();
            } else if (std.mem.eql(u8, response.type, "labels")) {
                try self.sendCommand("unsupported", &.{}, &.{});
            } else if (std.mem.eql(u8, response.type, "done")) {
                try self.sendOk();
                return true;
            } else {
                try self.sendCommand("unsupported", &.{}, &.{});
            }
        }

        return false;
    }

    pub fn destroy(self: *ClientInterface) void {
        // TODO: maybe log the output of plugin or ignore it.
        _ = self.plugin.kill() catch |err| {
            std.zig.fatal("Unable to kill plugin process: {s}\n", .{@errorName(err)});
        };
    }
};
