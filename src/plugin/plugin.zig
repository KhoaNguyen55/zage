const std = @import("std");
const Allocator = std.mem.Allocator;
const age = @import("age");
const Stanza = age.Stanza;
const base64Encoder = std.base64.standard_no_pad.Encoder;
const base64Decoder = std.base64.standard_no_pad.Decoder;

pub const parser = @import("parser.zig");
pub const client = @import("client.zig");

pub const Error = Allocator.Error || std.fs.File.WriteError || error{
    MalformedCommandFromClient,
    UnknownResponseFromClient,
};

pub const StateMachine = struct {
    pub const V1 = struct {
        pub const recipient = "recipient-v1";
        pub const identity = "identity-v1";
    };
};

pub const PluginHandler = struct {
    context: *anyopaque,

    recipient: *const fn (context: *anyopaque, allocator: Allocator, recipient: []const u8) anyerror!void,
    identity: *const fn (context: *anyopaque, allocator: Allocator, identity: []const u8) anyerror!void,
    fileKey: *const fn (context: *anyopaque, allocator: Allocator, file_key: []const u8) anyerror!void,
};

pub const PluginInterface = struct {
    allocator: Allocator,
    stdin: std.io.File,
    stdout: std.io.File,
    stderr: std.io.File,

    pub fn create(allocator: Allocator) PluginInterface {
        return PluginInterface{
            .allocator = allocator,
            .stdin = std.io.getStdIn(),
            .stdout = std.io.getStdOut(),
            .stderr = std.io.getStdErr(),
        };
    }

    fn sendCommand(self: PluginInterface, command: []const u8, args: []const []const u8, data: []const u8) Error!void {
        const stanza = try Stanza.create(self.allocator, command, args, data);
        defer stanza.destroy();

        try self.stdout.writer().print("{s}\n", .{stanza});
    }

    fn getResponse(self: PluginInterface) Error!Stanza {
        const response = Stanza.parseFromReader(self.allocator, self.stdin.reader().any()) catch {
            return Error.MalformedCommandFromClient;
        };
        errdefer response.destroy();

        if (!std.mem.eql(u8, response.type, "ok") and
            !std.mem.eql(u8, response.type, "fail"))
        {
            return Error.UnknownResponseFromClient;
        }

        return response;
    }

    pub fn done(self: PluginInterface) Error!void {
        try self.stdout.writeAll("-> done\n");
    }

    /// Request the client to display a message
    /// Return `true` if message is displays successfully, `false` otherwise.
    pub fn msg(self: PluginInterface, message: []const u8) Error!bool {
        try self.sendCommand("message", &.{}, message);
        const res = try self.getResponse();
        defer res.destroy();

        return std.mem.eql(u8, res.type, "ok");
    }

    /// Request confirmation from the client
    /// Return `null` if the request failed
    pub fn confirm(self: PluginInterface, yes_string: []const u8, no_string: ?[]const u8, message: []const u8) Error!?bool {
        const size = base64Encoder.calcSize(yes_string.len);
        const yes_encode = try self.allocator.alloc(u8, size);
        defer self.allocator.free(yes_encode);
        base64Encoder.encode(yes_encode, yes_string);

        var no_encode: ?[]u8 = null;
        if (no_string) |str| {
            const no_size = base64Encoder.calcSize(str.len);
            no_encode = try self.allocator.alloc(u8, no_size);
            base64Encoder.encode(no_encode.?, str);
        }
        defer if (no_string) |_| self.allocator.free(no_encode.?);

        try self.sendCommand("confirm", &.{ yes_encode, no_encode orelse "" }, message);
        const res = try self.getResponse();
        defer res.destroy();

        if (std.mem.eql(u8, res.type, "fail")) return null;

        if (res.args.len != 1) return Error.MalformedCommandFromClient;

        if (std.mem.eql(u8, res.args[0], "yes")) {
            return true;
        } else if (std.mem.eql(u8, res.args[0], "no")) {
            return false;
        }
    }

    /// Request the client for an input from the user
    /// Return `null` if the request failed
    /// Caller owns the returned memory.
    pub fn requestInput(self: PluginInterface, message: []const u8, secret: bool) Error!?[]const u8 {
        if (secret) {
            try self.sendCommand("request-secret", &.{}, message);
        } else {
            try self.sendCommand("request-public", &.{}, message);
        }

        const res = try self.getResponse();
        defer res.destroy();

        if (std.mem.eql(u8, res.type, "fail")) return null;

        return try self.allocator.dupe(u8, res.body);
    }

    pub fn recipientStanza(self: PluginInterface, file_index: usize, stanza: Stanza) Error!void {
        try self.stdout.writer().print("-> recipient-stanza {} {s}\n", .{ file_index, stanza });

        const res = try self.getResponse();
        defer res.destroy();

        if (!std.mem.eql(u8, res.type, "ok")) return Error.UnknownResponseFromClient;
    }

    /// Send error to client
    /// `index` is ignored if `error_type` is `.Internal`
    pub fn errors(self: PluginInterface, error_type: client.ClientHandler.ErrorType, index: usize, message: []const u8) Error!void {
        switch (error_type) {
            .Recipient => try self.sendCommand("error", &.{ "recipient", index }, message),
            .Identity => try self.sendCommand("error", &.{ "identity", index }, message),
            .Internal => try self.sendCommand("error", &.{"internal"}, message),
        }
    }

    // pub fn labels(self: PluginInterface, label: []const []const u8) Error!void {}
};
