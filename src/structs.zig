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
            .type = args[1],
            .args = args[2..],
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
    const test_string =
        \\-> X25519 n5jfZ5WXT3uBFWFS6ec1CxlfCXh/odc1VMiOllTUuEk
        \\En8W8T7XL6kXsqG4JcehRyePRDZyqVNCzivRj0sL+4M
    ;
    const stanza = try Stanza.parse(test_allocator, test_string);
    defer stanza.deinit();
    var args = [_]string{"n5jfZ5WXT3uBFWFS6ec1CxlfCXh/odc1VMiOllTUuEk"};
    const expect = Stanza{
        .type = "X25519",
        .args = &args,
        .body = undefined,
        .arena = undefined,
    };

    try testing.expectEqualStrings(expect.type, stanza.type);
    try testing.expectEqualDeep(expect.args, stanza.args);
    // try testing.expectEqualStrings(expect.body, stanza.body);
    // TODO: write expected body output in bytes
}

pub const Header = struct {
    recipients: []const Stanza,
    mac: []const u8,
    allocator: Allocator,
    /// Parse the header of an age file.
    ///
    /// Caller owned the memory of the returned `Header`, must be free with `Header.deinit()`.
    pub fn parse(allocator: Allocator, reader: std.io.AnyReader) anyerror!Header {
        // TODO: rewrite this function when peeking api get implemented, see https://github.com/ziglang/zig/issues/4501
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
            .allocator = allocator,
        };
    }

    pub fn format(
        self: Header,
        comptime fmt: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) anyerror!void {
        const print_mac = comptime if (std.mem.eql(u8, fmt, print_with_mac) or
            std.mem.eql(u8, fmt, "any"))
            true
        else if (std.mem.eql(u8, fmt, print_without_mac))
            false
        else {
            @compileError("Unsupported specifier '" ++ fmt ++ "', use '" ++ print_with_mac ++ "' or '" ++ print_without_mac ++ "'");
        };

        try writer.writeAll(version_line ++ "\n");
        for (self.recipients) |stanza| {
            try writer.print("{s}\n", .{stanza});
        }

        try writer.writeAll(mac_prefix);

        if (print_mac) {
            const mac = self.mac orelse @panic("Header mac is empty");
            const alloc = self.allocator;
            const size = base64Encoder.calcSize(mac.len);
            const mac_encode = try alloc.alloc(u8, size);
            defer alloc.free(mac_encode);
            _ = base64Encoder.encode(mac_encode, &mac);

            try writer.print(" {s}", .{mac_encode});
        }
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

    pub fn deinit(self: Header) void {
        for (self.recipients) |value| {
            value.deinit();
        }
        test_allocator.free(self.recipients);
        test_allocator.free(self.mac);
    }
};

test "Parse header" {
    const test_string =
        \\age-encryption.org/v1
        \\-> X25519 A76ighm6OB6DbLMzD8SA1Ozg7lAbyG6qNNaNoEC+m1w
        \\p0OFXKOnut5HGzfUsfu26JLBPzOJAokn41L5kLvkNtI
        \\--- 61illhf/7ouLPIIEnJ8sRtxd9Up/DjGqHYRCEh0HI5Y
        \\
    ;
    var buffer = std.io.fixedBufferStream(test_string);
    const parse_success = try Header.parse(test_allocator, buffer.reader().any());
    defer parse_success.deinit();
    // TODO: write the expected output in bytes
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
