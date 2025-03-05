const std = @import("std");
const StateMachine = @import("plugin.zig");
const Allocator = std.mem.Allocator;
const age = @import("age");
const Stanza = age.Stanza;
const base64Encoder = std.base64.standard_no_pad.Encoder;

pub const PluginStdInError = std.fs.File.WriteError || Allocator.Error;

// type of responses the plugin can make
pub const Message = []const u8;

pub const Confirm = struct {
    yes_string: []const u8,
    no_string: ?[]const u8,
    message: []const u8,
};

pub const RecipientStanza = struct {
    file_index: usize,
    stanza: Stanza,
};

const Labels = []const []const u8;

pub const PluginResponse = union(enum) {
    msg: Message,
    confirm: Confirm,
    requestPublic: Message,
    requestSecret: Message,
    recipientStanza: RecipientStanza,
};

// the plugin instance

allocator: Allocator,
plugin: std.process.Child,
stdin: std.fs.File,
stdout: std.fs.File,
stderr: std.fs.File,

const PluginInstance = @This();

pub fn create(allocator: Allocator, plugin_name: []const u8) PluginInstance {
    const plugin_exec = try std.fmt.allocPrint(allocator, "age-plugin-{s}", .{plugin_name});
    const plugin_args = try std.fmt.allocPrint(allocator, "--age-plugin={s}", .{StateMachine.V1.recipient});
    var plugin = std.process.Child.init(&[_][]u8{ plugin_exec, plugin_args }, allocator);
    plugin.stdin_behavior = .Pipe;
    plugin.stdout_behavior = .Pipe;
    plugin.stderr_behavior = .Pipe;
    try plugin.spawn();

    return PluginInstance{
        .allocator = allocator,
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

    const data = try std.fmt.allocPrint(self.allocator, "-> wrap-file-key\n{s}", .{file_key});
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

pub fn readResponse(self: PluginInstance) anyerror!PluginResponse {
    return Stanza.parseFromReader(self.allocator, self.stdout.reader().any());
}

pub fn destroy(self: PluginInstance) void {
    self.plugin.wait();
}
