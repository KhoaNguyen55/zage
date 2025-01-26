const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const bech32 = @import("bech32.zig");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;

const base64Decoder = std.base64.standard_no_pad.Decoder;
const base64Encoder = std.base64.standard_no_pad.Encoder;

const assert = std.debug.assert;

const testing = std.testing;
const test_allocator = std.testing.allocator;

const version_line = "age-encryption.org/v1";

const stanza_columns = 64;

const version_prefix = "age";
const stanza_prefix = "-> ";
const mac_prefix = "---";

pub const string = []const u8;

pub const Error = error{
    MalformedHeader,
    UnsupportedVersion,
    WrongSection,
};

/// Split a string by space( ) and duplicate each substring into an array.
///
/// Caller owns the returned array of string.
fn splitArgs(allocator: Allocator, src: []const u8) anyerror![]string {
    var iter = std.mem.splitScalar(u8, src, ' ');
    var args = ArrayList([]const u8).init(allocator);
    errdefer args.deinit();

    while (iter.next()) |value| {
        const copy = try allocator.dupe(u8, value);
        try args.append(copy);
    }

    return args.toOwnedSlice();
}

pub const Stanza = struct {
    type: string,
    args: []const string,
    body: []const u8,
    arena: ArenaAllocator,
    /// Parse a stanza string.
    ///
    /// Caller owns the returned memory, must be free with `Stanza.deinit()`.
    pub fn parse(
        allocator: Allocator,
        /// input string must start with '-> ', end with a line fewer than 64 characters with no newline.
        input: []const u8,
    ) anyerror!Stanza {
        var arena_alloc = ArenaAllocator.init(allocator);
        errdefer arena_alloc.deinit();
        const alloc = arena_alloc.allocator();

        var lines = std.mem.splitScalar(u8, input, '\n');
        const args = try splitArgs(alloc, lines.first());

        assert(std.mem.eql(u8, args[0], stanza_prefix[0..2]));
        var body = ArrayList(u8).init(alloc);
        var final_len: usize = stanza_columns;
        while (lines.next()) |line| {
            if (line.len > stanza_columns) {
                return Error.MalformedHeader;
            }
            try body.appendSlice(line);
            final_len = line.len;
        }

        if (final_len >= stanza_columns) {
            return Error.MalformedHeader;
        }

        const body_slice = try body.toOwnedSlice();
        defer alloc.free(body_slice);
        const size = try base64Decoder.calcSizeForSlice(body_slice);
        const decoded_body = try alloc.alloc(u8, size);
        try base64Decoder.decode(decoded_body, body_slice);

        return Stanza{
            .type = args[0],
            .args = args[1..],
            .body = decoded_body,
            .arena = arena_alloc,
        };
    }

    pub fn create(
        allocator: Allocator,
        stanza_type: string,
        args: []const []const u8,
        body: []const u8,
    ) anyerror!Stanza {
        var arena_alloc = ArenaAllocator.init(allocator);
        errdefer arena_alloc.deinit();
        const alloc = arena_alloc.allocator();

        var args_encoded = try alloc.alloc(string, args.len);

        for (args, 0..) |arg, i| {
            const size = base64Encoder.calcSize(arg.len);
            const encoded = try alloc.alloc(u8, size);
            _ = base64Encoder.encode(encoded, arg);
            args_encoded[i] = encoded;
        }

        const body_copy = try alloc.dupe(u8, body);

        return Stanza{
            .type = stanza_type,
            .args = args_encoded,
            .body = body_copy,
            .arena = arena_alloc,
        };
    }

    pub fn format(
        self: Stanza,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) anyerror!void {
        try writer.print("{s}{s}", .{ stanza_prefix, self.type });
        for (self.args) |arg| {
            try writer.print(" {s}", .{arg});
        }
        try writer.writeAll("\n");

        const alloc = self.arena.child_allocator;
        const size = base64Encoder.calcSize(self.body.len);
        const body_encode = try alloc.alloc(u8, size);
        defer alloc.free(body_encode);
        _ = base64Encoder.encode(body_encode, self.body);

        var start: usize = 0;
        var end: usize = stanza_columns;
        var length: usize = size;
        while (length > stanza_columns) {
            try writer.print("{s}\n", .{body_encode[start..end]});
            length -= stanza_columns;
            start += stanza_columns;
            end += stanza_columns;
        }
        try writer.print("{s}", .{body_encode[start..]});
    }

    pub fn deinit(self: Stanza) void {
        self.arena.deinit();
    }
};

test "Stanza parsing" {
    const test_string = "ssh-ed25519 fCt7bg 6Dk4AxifdNgIiX0YTBMlm41egmTLbuztNbMMEajOFCw\nSs8s5qOqkOzvz/3SURSvRLIs3qyQ4Qxf+G1sK9O7L4Y\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const stanza = try Stanza.parse(test_allocator, buffer.reader().any());
    defer stanza.deinit();
    var args = [_]string{ "fCt7bg", "6Dk4AxifdNgIiX0YTBMlm41egmTLbuztNbMMEajOFCw" };
    const expect = Stanza{
        .type = "ssh-ed25519",
        .args = &args,
        .body = undefined,
        .allocator = undefined,
    };

    try testing.expectEqualStrings(expect.type, stanza.type);
    try testing.expectEqualDeep(expect.args, stanza.args);
    // try testing.expectEqualStrings(expect.body, stanza.body);
}

pub const Header = struct {
    recipients: []Stanza,
    mac: []const u8,
    // TODO: rewrite this function when peeking api get implemented, see https://github.com/ziglang/zig/issues/4501
    pub fn parse(allocator: Allocator, reader: std.io.AnyReader) anyerror!Header {
        var input = ArrayList(u8).init(allocator);
        defer input.deinit();
        var start_idx: usize = 0;

        try reader.streamUntilDelimiter(input.writer(), '\n', null);
        try parseVersion(input.items[start_idx..]);
        start_idx = input.items.len;

        var recipients = ArrayList(Stanza).init(allocator);
        errdefer recipients.deinit();

        var parsing_stanzas = false;

        while (true) {
            const in_len = input.items.len;
            try reader.streamUntilDelimiter(input.writer(), '\n', null);

            if (parsing_stanzas) {
                if (std.mem.eql(u8, input.items[in_len .. in_len + 3], stanza_prefix) or
                    std.mem.eql(u8, input.items[in_len .. in_len + 3], mac_prefix))
                {
                    parsing_stanzas = false;
                    const stanza = try Stanza.parse(allocator, input.items[start_idx..in_len]);
                    errdefer stanza.deinit();
                    try recipients.append(stanza);
                    start_idx = in_len;
                }
            } else if (std.mem.eql(u8, input.items[start_idx .. start_idx + 3], stanza_prefix)) {
                parsing_stanzas = true;
            }
            if (std.mem.eql(u8, input.items[in_len .. in_len + 3], mac_prefix)) {
                break;
            }
            try input.append('\n');
        }

        const mac = try parseMac(allocator, input.items[start_idx..]);
        errdefer allocator.free(mac);

        return Header{
            .recipients = try recipients.toOwnedSlice(),
            .mac = mac,
        };
    }

    fn parseMac(
        allocator: Allocator,
        /// Mac string, must start with `---` and ends without a newline.
        input: []const u8,
    ) anyerror![]const u8 {
        var args = std.mem.splitScalar(u8, input, ' ');

        assert(std.mem.eql(u8, args.first(), mac_prefix));

        if (args.next()) |mac_line| {
            if (args.next() != null) {
                return Error.MalformedHeader;
            }

            const size = try base64Decoder.calcSizeForSlice(mac_line);
            const mac = try allocator.alloc(u8, size);
            errdefer allocator.free(mac);
            try base64Decoder.decode(mac, mac_line);
            return mac;
        }
        return Error.MalformedHeader;
    }
    /// Return `error` if the version string are not `version_line`
    fn parseVersion(
        /// Version string, must start with `age` and ends without a newline.
        input: []const u8,
    ) anyerror!void {
        assert(std.mem.eql(u8, input[0..3], version_prefix));

        if (input.len < version_line.len) {
            return Error.MalformedHeader;
        }
        if (input.len > version_line.len or !std.mem.eql(u8, input, version_line)) {
            return Error.UnsupportedVersion;
        }
    }
};

test "Parse mac" {
    const test_string = "--- RAnz3UnrF3uSP2d0GVlHgRC81knulcIF5Yl+HENyn0M\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const parse_success = try Header.parseMac(buffer.reader().any(), test_allocator);
    defer test_allocator.free(parse_success);
    try testing.expectEqualStrings("RAnz3UnrF3uSP2d0GVlHgRC81knulcIF5Yl+HENyn0M", parse_success);
}

test "Correct version string parsing" {
    const test_string = "age-encryption.org/v1\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const parse_success = Header.parseVersion(buffer.reader().any());
    try testing.expectEqual(void{}, parse_success);
}

test "Too short version string parsing" {
    const test_string = "age-encryption.org/";
    var buffer = std.io.fixedBufferStream(test_string);
    const parse_success = Header.parseVersion(buffer.reader().any());
    try testing.expectError(Error.MalformedHeader, parse_success);
}

test "Wrong version section string parsing" {
    const test_string = "----encryption.org/v3\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const parse_success = Header.parseVersion(buffer.reader().any());
    try testing.expectError(Error.WrongSection, parse_success);
}

test "Different version string parsing" {
    const test_string = "age-encryption.org/v3\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const parse_success = Header.parseVersion(buffer.reader().any());
    try testing.expectError(Error.UnsupportedVersion, parse_success);
}

test "Too long version string parsing" {
    const test_string = "age-encryption.org/v123\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const parse_success = Header.parseVersion(buffer.reader().any());
    try testing.expectError(Error.UnsupportedVersion, parse_success);
}

fn splitArgs(allocator: Allocator, src: std.io.AnyReader) anyerror![]string {
    var arguments = ArrayList(u8).init(allocator);
    errdefer arguments.deinit();

    try src.streamUntilDelimiter(arguments.writer(), '\n', null);

    const arguments_array = try arguments.toOwnedSlice();
    defer allocator.free(arguments_array);

    var iter = std.mem.splitScalar(u8, arguments_array, ' ');
    var args = ArrayList([]const u8).init(allocator);
    errdefer args.deinit();

    while (iter.next()) |value| {
        const copy = try allocator.dupe(u8, value);
        try args.append(copy);
    }

    return args.toOwnedSlice();
}

test "Split args" {
    const test_string = "age-encrypt ion.org/v123\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const args = try splitArgs(test_allocator, buffer.reader().any());
    defer {
        for (args) |slice| {
            test_allocator.free(slice);
        }
        test_allocator.free(args);
    }
    try testing.expectEqualStrings("age-encrypt", args[0]);
    try testing.expectEqualStrings("ion.org/v123", args[1]);
}

pub const AnyRecipient = struct {
    context: *const anyopaque,
    wrapFn: *const fn (context: *const anyopaque, allocator: Allocator, file_key: []const u8) anyerror!Stanza,

    pub fn wrap(self: AnyRecipient, allocator: Allocator, file_key: []const u8) anyerror!Stanza {
        return self.wrapFn(self.context, allocator, file_key);
    }
};

pub const AnyIdentity = struct {
    context: *const anyopaque,
    unwrapFn: *const fn (context: *const anyopaque, dest: []u8, stanzas: []const Stanza) anyerror!void,

    pub fn unwrap(self: AnyIdentity, dest: []u8, stanzas: []const Stanza) anyerror!void {
        return self.unwrapFn(self.context, dest, stanzas);
    }
};

fn decrypt(identity: AnyIdentity) !void {
    _ = try identity.unwrap(undefined);
}
