const std = @import("std");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;

const testing = std.testing;
const test_allocator = std.testing.allocator;

const version_line = "age-encryption.org/v1";

const stanza_columns = 64;

const version_prefix = "age";
const stanza_prefix = "-> ";
const mac_prefix = "---";

const ParseError = error{ MalformedHeader, UnsupportedVersion, WrongSection };

const Stanza = struct {
    type: []const u8,
    args: [][]const u8,
    body: []const u8,
    arena_alloc: ArenaAllocator,
    pub fn parse(src: std.io.AnyReader, allocator: Allocator) !Stanza {
        var arena_alloc = ArenaAllocator.init(allocator);
        errdefer arena_alloc.deinit();
        const alloc = arena_alloc.allocator();

        const args = try splitArgs(src, alloc);

        var body = ArrayList(u8).init(alloc);
        var old_len = body.items.len;
        while (old_len == 0 or (body.items.len - old_len >= stanza_columns)) {
            src.streamUntilDelimiter(body.writer(), '\n', stanza_columns) catch return ParseError.MalformedHeader;
            old_len = body.items.len;
        }

        return Stanza{
            .type = args[0],
            .args = args[1..],
            .body = try body.toOwnedSlice(),
            .arena_alloc = arena_alloc,
        };
    }

    pub fn deinit(self: Stanza) void {
        self.arena_alloc.deinit();
    }
};

test "Stanza parsing" {
    const test_string = "ssh-ed25519 fCt7bg 6Dk4AxifdNgIiX0YTBMlm41egmTLbuztNbMMEajOFCw\nSs8s5qOqkOzvz/3SURSvRLIs3qyQ4Qxf+G1sK9O7L4Y\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const stanza = try Stanza.parse(buffer.reader().any(), test_allocator);
    defer stanza.deinit();
    var args = [_][]const u8{ "fCt7bg", "6Dk4AxifdNgIiX0YTBMlm41egmTLbuztNbMMEajOFCw" };
    const expect = Stanza{
        .type = "ssh-ed25519",
        .args = &args,
        .body = "Ss8s5qOqkOzvz/3SURSvRLIs3qyQ4Qxf+G1sK9O7L4Y",
        .arena_alloc = undefined,
    };

    try testing.expectEqualStrings(expect.type, stanza.type);
    try testing.expectEqualDeep(expect.args, stanza.args);
    try testing.expectEqualStrings(expect.body, stanza.body);
}

const Header = struct {
    recipients: []Stanza,
    mac: []const u8,
    pub fn parse(src: std.fs.File, allocator: Allocator) !Header {
        try parseVersion(src.reader());

        var recipients = ArrayList(Stanza).init(allocator);
        errdefer recipients.deinit();

        var prefix: [stanza_prefix.len]u8 = undefined;
        while (true) {
            const bytes = try src.read(&prefix);
            if (bytes < 3) {
                return ParseError.MalformedHeader;
            }
            if (std.mem.eql(u8, &prefix, stanza_prefix)) {
                try recipients.append(try Stanza.parse(src, allocator));
            } else if (recipients.items.len == 0) {
                return ParseError.WrongSection;
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

    fn parseMac(src: std.io.AnyReader, allocator: Allocator) ![]const u8 {
        // discard the space which is after the prefix
        var prefix: [mac_prefix.len + 1]u8 = undefined;

        if (try src.read(&prefix) != mac_prefix.len + 1) {
            return ParseError.MalformedHeader;
        }

        if (!std.mem.eql(u8, prefix[0..3], mac_prefix)) {
            return ParseError.WrongSection;
        }

        var mac = ArrayList(u8).init(allocator);
        errdefer mac.deinit();

        src.streamUntilDelimiter(mac.writer(), '\n', stanza_columns) catch return ParseError.MalformedHeader;

        return mac.toOwnedSlice();
    }

    /// Return `error` if the version string are wrong
    fn parseVersion(src: std.io.AnyReader) !void {
        var buf: std.BoundedArray(u8, version_line.len + 1) = .{};

        src.streamUntilDelimiter(buf.writer(), '\n', buf.capacity()) catch |err| switch (err) {
            error.EndOfStream => return ParseError.MalformedHeader,
            error.StreamTooLong => return ParseError.UnsupportedVersion,
            else => unreachable,
        };

        if (!std.mem.eql(u8, buf.slice()[0..3], version_prefix)) {
            return ParseError.WrongSection;
        }

        if (!std.mem.eql(u8, buf.slice(), version_line)) {
            return ParseError.UnsupportedVersion;
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
    try testing.expectError(ParseError.MalformedHeader, parse_success);
}

test "Wrong version section string parsing" {
    const test_string = "----encryption.org/v3\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const parse_success = Header.parseVersion(buffer.reader().any());
    try testing.expectError(ParseError.WrongSection, parse_success);
}

test "Different version string parsing" {
    const test_string = "age-encryption.org/v3\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const parse_success = Header.parseVersion(buffer.reader().any());
    try testing.expectError(ParseError.UnsupportedVersion, parse_success);
}

test "Too long version string parsing" {
    const test_string = "age-encryption.org/v123\n";
    var buffer = std.io.fixedBufferStream(test_string);
    const parse_success = Header.parseVersion(buffer.reader().any());
    try testing.expectError(ParseError.UnsupportedVersion, parse_success);
}

fn splitArgs(src: std.io.AnyReader, allocator: Allocator) ![][]const u8 {
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
    const args = try splitArgs(buffer.reader().any(), test_allocator);
    defer {
        for (args) |slice| {
            test_allocator.free(slice);
        }
        test_allocator.free(args);
    }
    try testing.expectEqualStrings("age-encrypt", args[0]);
    try testing.expectEqualStrings("ion.org/v123", args[1]);
}
