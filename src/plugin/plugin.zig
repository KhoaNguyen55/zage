const std = @import("std");
const Allocator = std.mem.Allocator;
const age = @import("age");
const Stanza = age.Stanza;
const base64Encoder = std.base64.standard_no_pad.Encoder;
const base64Decoder = std.base64.standard_no_pad.Decoder;
const ArrayList = std.ArrayListUnmanaged;

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

pub const StateMachineHandler = struct {
    v1_recipient: V1RecipientHandler,
    v1_identity: V1IdentityHandler,
};

pub fn runStateMachine(allocator: Allocator, state: []const u8, state_handler: StateMachineHandler) anyerror!void {
    const interface = PluginInterface.create(allocator);

    if (std.mem.eql(u8, state, StateMachine.V1.recipient)) {
        var file_keys: ArrayList([age.file_key_size]u8) = .empty;
        errdefer file_keys.deinit(allocator);

        const ctx = state_handler.v1_identity.context;

        while (true) {
            const response = interface.waitForResponse() catch |err| {
                const err_msg = try std.fmt.allocPrint(allocator, "Unable to read response: {s}", .{@errorName(err)});
                defer allocator.free(err_msg);
                return try interface.errors(.Internal, 0, err_msg);
            };
            defer response.destroy();

            if (std.mem.eql(u8, response.type, "add-recipient")) {
                if (response.args.len != 1) {
                    return Error.MalformedCommandFromClient;
                }

                try state_handler.v1_recipient.recipient(ctx, allocator, response.args[0]);
            } else if (std.mem.eql(u8, response.type, "add-identity")) {
                if (response.args.len != 1) {
                    return Error.MalformedCommandFromClient;
                }

                try state_handler.v1_recipient.identity(ctx, allocator, response.args[0]);
            } else if (std.mem.eql(u8, response.type, "wrap-file-key")) {
                try file_keys.append(allocator, response.body[0..16].*);
            } else if (std.mem.eql(u8, response.type, "extension-labels")) {
                // TODO:
            } else if (std.mem.eql(u8, response.type, "done")) {
                const keys = try file_keys.toOwnedSlice(allocator);
                defer allocator.free(keys);

                try state_handler.v1_recipient.wrapFileKeys(ctx, allocator, interface, keys);
                break;
            }
        }
    } else if (std.mem.eql(u8, state, StateMachine.V1.identity)) {
        const ctx = state_handler.v1_identity.context;
        while (true) {
            const response = try interface.waitForResponse();
            defer response.destroy();

            if (std.mem.eql(u8, response.type, "add-identity")) {
                if (response.args.len != 1) {
                    return Error.MalformedCommandFromClient;
                }

                try state_handler.v1_recipient.identity(ctx, allocator, response.args[0]);
            } else if (std.mem.eql(u8, response.type, "recipient-stanza")) {
                if (response.args.len < 2) {
                    return Error.MalformedCommandFromClient;
                }

                const stanza = try age.Stanza.create(
                    allocator,
                    response.args[1],
                    response.args[2..],
                    response.body,
                );

                _ = stanza;

                @panic("Not implemented");
            } else if (std.mem.eql(u8, response.type, "done")) {
                break;
            }
        }
    }
}
pub const V1RecipientHandler = struct {
    context: *anyopaque,

    recipient: *const fn (context: *anyopaque, allocator: Allocator, recipient: []const u8) anyerror!void,
    identity: *const fn (context: *anyopaque, allocator: Allocator, identity: []const u8) anyerror!void,
    wrapFileKeys: *const fn (context: *anyopaque, allocator: Allocator, interface: PluginInterface, file_keys: []const [age.file_key_size]u8) anyerror!void,
};

pub const V1IdentityHandler = struct {
    context: *anyopaque,

    identity: *const fn (context: *anyopaque, allocator: Allocator, identity: []const u8) anyerror!void,
    unwrapFileKey: *const fn (context: *anyopaque, allocator: Allocator, interface: PluginInterface, stanzas: []const []const Stanza) anyerror!void,
};

pub const PluginInterface = struct {
    allocator: Allocator,
    stdin: std.fs.File,
    stdout: std.fs.File,
    stderr: std.fs.File,

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

    pub fn waitForResponse(self: PluginInterface) anyerror!Stanza {
        const response = try Stanza.parseFromReader(self.allocator, self.stdin.reader().any());
        errdefer response.destroy();

        return response;
    }

    pub fn done(self: PluginInterface) Error!void {
        try self.sendCommand("done", &.{}, "");
    }

    /// Request the client to display a message
    /// Return `true` if message is displays successfully, `false` otherwise.
    pub fn msg(self: PluginInterface, message: []const u8) Error!bool {
        try self.sendCommand("msg", &.{}, message);
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
        try self.stdout.writer().print("-> recipient-stanza {} {no-prefix}\n", .{ file_index, stanza });

        const res = try self.getResponse();
        defer res.destroy();

        if (!std.mem.eql(u8, res.type, "ok")) return Error.UnknownResponseFromClient;
    }

    /// Send error to client
    /// `index` is ignored if `error_type` is `.Internal`
    pub fn errors(self: PluginInterface, error_type: client.ClientHandler.ErrorType, index: u8, message: []const u8) Error!void {
        switch (error_type) {
            .Recipient => {
                const idx = std.fmt.digits2(index);
                try self.sendCommand("error", &.{ "recipient", &idx }, message);
            },
            .Identity => {
                const idx = std.fmt.digits2(index);
                try self.sendCommand("error", &.{ "identity", &idx }, message);
            },
            .Internal => try self.sendCommand("error", &.{"internal"}, message),
        }
    }

    // pub fn labels(self: PluginInterface, label: []const []const u8) Error!void {}
};
