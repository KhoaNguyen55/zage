const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const bech32 = @import("bech32.zig");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;

const base64Decoder = std.base64.standard_no_pad.Decoder;
const base64Encoder = std.base64.standard_no_pad.Encoder;

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

pub const Stanza = struct {
    type: string,
    args: []const string,
    body: []const u8,
    arena: ArenaAllocator,
    pub fn parse(allocator: Allocator, src: std.io.AnyReader) anyerror!Stanza {
        var arena_alloc = ArenaAllocator.init(allocator);
        errdefer arena_alloc.deinit();
        const alloc = arena_alloc.allocator();

        const args = try splitArgs(alloc, src);

        var body = ArrayList(u8).init(alloc);
        var old_len = body.items.len;
        while (true) {
            src.streamUntilDelimiter(body.writer(), '\n', stanza_columns) catch return Error.MalformedHeader;
            if (body.items.len != 0 and (body.items.len - old_len < stanza_columns)) {
                break;
            }
            old_len = body.items.len;
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
    pub fn parse(allocator: Allocator, src: std.fs.File) anyerror!Header {
        try parseVersion(src.reader());

        var recipients = ArrayList(Stanza).init(allocator);
        errdefer recipients.deinit();

        var prefix: [stanza_prefix.len]u8 = undefined;
        while (true) {
            const bytes = try src.read(&prefix);
            if (bytes < 3) {
                return Error.MalformedHeader;
            }
            if (std.mem.eql(u8, &prefix, stanza_prefix)) {
                try recipients.append(try Stanza.parse(allocator, src));
            } else if (recipients.items.len == 0) {
                return Error.WrongSection;
            } else {
                break;
            }
        }

        const mac = try parseMac(src, allocator);
        errdefer allocator.free(mac);

        return Header{
            .recipients = recipients,
            .mac = mac,
        };
    }

    fn parseMac(allocator: Allocator, src: std.io.AnyReader) anyerror![]const u8 {
        // discard the space which is after the prefix
        var prefix: [mac_prefix.len + 1]u8 = undefined;

        if (try src.read(&prefix) != mac_prefix.len + 1) {
            return Error.MalformedHeader;
        }

        if (!std.mem.eql(u8, prefix[0..3], mac_prefix)) {
            return Error.WrongSection;
        }

        var mac = ArrayList(u8).init(allocator);
        errdefer mac.deinit();

        src.streamUntilDelimiter(mac.writer(), '\n', stanza_columns) catch return Error.MalformedHeader;

        return mac.toOwnedSlice();
    }

    /// Return `error` if the version string are wrong
    fn parseVersion(src: std.io.AnyReader) anyerror!void {
        var buf: std.BoundedArray(u8, version_line.len + 1) = .{};

        src.streamUntilDelimiter(buf.writer(), '\n', buf.capacity()) catch |err| switch (err) {
            error.EndOfStream => return Error.MalformedHeader,
            error.StreamTooLong => return Error.UnsupportedVersion,
            else => unreachable,
        };

        if (!std.mem.eql(u8, buf.slice()[0..3], version_prefix)) {
            return Error.WrongSection;
        }

        if (!std.mem.eql(u8, buf.slice(), version_line)) {
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
