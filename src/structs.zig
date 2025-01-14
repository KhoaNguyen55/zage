const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const testing = std.testing;
const test_allocator = std.testing.allocator;

const version_line = "age-encryption.org/v1";

const stanza_columns = 64;

const version_prefix = "age";
const stanza_prefix = "-> ";
const mac_prefix = "---";

const ParseError = error{ HeaderTooSmall, UnsupportedVersion, WrongSection };

const Stanza = struct { type: []u8, args: [][]u8, body: []u8 };

const Header = struct {
    recipients: []Stanza,
    mac: []u8,
    pub fn parse(src: std.io.AnyReader, _: Allocator) !Header {
        try parseVersion(src);
        // loop
        //  if prefix = "-> "
        //   parse stanzas
        //  else if stanzas == empty
        //   error
        //  else
        //   break

        // const section_prefix = try allocator.alloc(u8, 3);
        // defer allocator.free(section_prefix);

        // if (std.mem.eql(u8, section_prefix, "-> ")) {
        //     // parse stanza
        // }
        //
        // if (std.mem.eql(u8, section_prefix, "---")) {
        //     // check for accuracy
        // }
    }

    fn parseStanza(src: std.io.AnyReader, allocator: Allocator) !Stanza {
        // var stanza: Stanza = .{};

        // should be move to function that parse multiple stanzas
        const prefix: [3]u8 = .{};
        const bytes = try src.read(prefix);
        if (bytes < 3) {
            return ParseError.HeaderTooSmall;
        }
        if (!std.mem.eql(u8, prefix, stanza_prefix)) {
            return ParseError.WrongSection;
        }
        //

        // var stanza_type = ArrayList(u8).init(allocator);
        // errdefer stanza_type.deinit();
        //
        // try src.streamUntilDelimiter(stanza_type.writer(), " ", null);
        // stanza.type = try stanza_type.toOwnedSlice();

        var body = ArrayList(u8).init(allocator);
        errdefer body.deinit();
    }

    /// Return `error` if the version string are wrong
    fn parseVersion(src: std.io.AnyReader) !void {
        var buf: std.BoundedArray(u8, version_line.len + 1) = .{};

        src.streamUntilDelimiter(buf.writer(), '\n', buf.capacity()) catch |err| switch (err) {
            error.EndOfStream => return ParseError.HeaderTooSmall,
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
    try testing.expectError(ParseError.HeaderTooSmall, parse_success);
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
    std.debug.print("{s}\n", .{args});
    try testing.expectEqualStrings("age-encrypt", args[0]);
    try testing.expectEqualStrings("ion.org/v123", args[1]);
}
