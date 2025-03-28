const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const bech32 = @import("bech32");
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayListUnmanaged;

const base64Decoder = std.base64.standard_no_pad.Decoder;
const base64Encoder = std.base64.standard_no_pad.Encoder;
const b64Error = std.base64.Error;

const computeHkdfKey = @import("primitives.zig").computeHkdfKey;

const assert = std.debug.assert;

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const mac_length = HmacSha256.mac_length;
const decoded_mac_length = 43;
const stanza_columns = 64;

const print_with_mac = "mac";
const print_without_mac = "nomac";

pub const file_key_size = 16;
pub const version_line = "age-encryption.org/v1";
pub const version_prefix = "age";
pub const stanza_prefix = "-> ";
pub const mac_prefix = "---";
pub const header_label = "header";

pub const Error = error{
    MalformedHeader,
    CantReadInput,
    DoesNotExpectPrefix,
    WrongPrefix,
    StanzaTooShort,
    UnsupportedCharacters,
    UnsupportedVersion,
} || Allocator.Error;

/// Split a string by space( ) and duplicate each substring into an array.
/// Caller owns the returned array of string.
fn splitArgs(allocator: Allocator, src: []const u8) Allocator.Error![][]const u8 {
    var iter = std.mem.splitScalar(u8, src, ' ');
    var args: ArrayList([]const u8) = .empty;
    errdefer args.deinit(allocator);

    while (iter.next()) |value| {
        const copy = try allocator.dupe(u8, value);
        try args.append(allocator, copy);
    }

    return args.toOwnedSlice(allocator);
}

pub const Stanza = struct {
    /// String repesenting the type of the stanza
    type: []const u8,
    /// Argruments of the stanza represented with a slice of base64 encoded string
    args: []const []const u8,
    /// Encrypted file key represented with a slice of bytes
    body: []const u8,
    arena: ArenaAllocator,

    /// Parse a stanza string.
    /// Caller owns the returned memory, must be free with `Stanza.destroy()`.
    pub fn parse(
        allocator: Allocator,
        /// input string must start with '-> ', end with a line fewer than 64 characters with no newline.
        input: []const u8,
    ) Error!Stanza {
        var buf = std.io.fixedBufferStream(input);
        return Stanza.parseFromReader(allocator, buf.reader().any());
    }

    pub fn parseFromReader(
        allocator: Allocator,
        input: std.io.AnyReader,
    ) Error!Stanza {
        var arena_alloc = ArenaAllocator.init(allocator);
        errdefer arena_alloc.deinit();
        const alloc = arena_alloc.allocator();

        var line: ArrayList(u8) = .empty;
        defer line.deinit(alloc);
        input.streamUntilDelimiter(line.writer(alloc), '\n', null) catch {
            return Error.CantReadInput;
        };

        const args = try splitArgs(alloc, line.items);

        for (args) |arg| {
            if (arg.len == 0) {
                return Error.StanzaTooShort;
            }

            for (arg) |c| {
                if (c < 33 or c > 126) {
                    return Error.UnsupportedCharacters;
                }
            }
        }

        if (!std.mem.startsWith(u8, args[0], stanza_prefix[0..2])) return Error.WrongPrefix;

        var body: ArrayList(u8) = .empty;
        var body_size: usize = 0;
        while (true) : (body_size = body.items.len) {
            input.streamUntilDelimiter(body.writer(alloc), '\n', stanza_columns + 1) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return Error.MalformedHeader,
            };

            if (std.mem.startsWith(u8, body.items[body_size..], mac_prefix) or
                std.mem.startsWith(u8, body.items[body_size..], stanza_prefix))
            {
                return Error.DoesNotExpectPrefix;
            }

            if (body.items.len - body_size < stanza_columns) {
                break;
            }
        }

        const body_slice = try body.toOwnedSlice(alloc);
        defer alloc.free(body_slice);

        const size = base64Decoder.calcSizeForSlice(body_slice) catch return Error.MalformedHeader;
        const decoded_body = try alloc.alloc(u8, size);
        base64Decoder.decode(decoded_body, body_slice) catch |err| switch (err) {
            b64Error.InvalidCharacter, b64Error.InvalidPadding => {
                return Error.MalformedHeader;
            },
            else => unreachable,
        };

        return Stanza{
            .type = args[1],
            .args = args[2..],
            .body = decoded_body,
            .arena = arena_alloc,
        };
    }

    /// Create a stanza
    /// `args` and `body` memory are copied and managed internally
    /// Caller owns the returned memory, must be free with `Stanza.destroy()`.
    pub fn create(
        allocator: Allocator,
        /// String repesenting the type of the stanza
        stanza_type: []const u8,
        /// Slices of string representing arguments of the stanza
        args: []const []const u8,
        /// Slice of bytes representing the encrypted file key
        body: []const u8,
    ) Allocator.Error!Stanza {
        var arena_alloc = ArenaAllocator.init(allocator);
        errdefer arena_alloc.deinit();
        const alloc = arena_alloc.allocator();

        var args_duped = try alloc.alloc([]const u8, args.len);

        for (args, 0..) |arg, i| {
            args_duped[i] = try alloc.dupe(u8, arg);
        }

        const stanza_copy = try alloc.dupe(u8, stanza_type);
        const body_copy = try alloc.dupe(u8, body);

        return Stanza{
            .type = stanza_copy,
            .args = args_duped,
            .body = body_copy,
            .arena = arena_alloc,
        };
    }

    pub fn format(
        self: Stanza,
        comptime fmt: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) anyerror!void {
        const prefix = comptime blk: {
            if (std.mem.eql(u8, fmt, "no-prefix")) {
                break :blk false;
            } else if (std.mem.eql(u8, fmt, "s")) {
                break :blk true;
            } else {
                @compileError("Unknown format specifier '" ++ fmt ++ "' use 's' or 'no-prefix'");
            }
        };

        if (prefix) {
            try writer.print("{s}", .{stanza_prefix});
        }

        try writer.print("{s}", .{self.type});
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
        while (length >= stanza_columns) {
            try writer.print("{s}\n", .{body_encode[start..end]});
            length -= stanza_columns;
            start += stanza_columns;
            end += stanza_columns;
        }
        try writer.print("{s}", .{body_encode[start..]});
    }

    pub fn destroy(self: Stanza) void {
        self.arena.deinit();
    }
};

test "Stanza parsing" {
    const testing = std.testing;
    const test_allocator = std.testing.allocator;

    const test_string =
        \\-> X25519 A76ighm6OB6DbLMzD8SA1Ozg7lAbyG6qNNaNoEC+m1w
        \\p0OFXKOnut5HGzfUsfu26JLBPzOJAokn41L5kLvkNtI
    ;
    const stanza = try Stanza.parse(test_allocator, test_string);
    defer stanza.destroy();
    var args = [_][]const u8{"A76ighm6OB6DbLMzD8SA1Ozg7lAbyG6qNNaNoEC+m1w"};

    const body = "p0OFXKOnut5HGzfUsfu26JLBPzOJAokn41L5kLvkNtI";
    const size = try base64Decoder.calcSizeForSlice(body);
    const decoded_body = try test_allocator.alloc(u8, size);
    defer test_allocator.free(decoded_body);
    try base64Decoder.decode(decoded_body, body);

    const expect = Stanza{
        .type = "X25519",
        .args = &args,
        .body = decoded_body,
        .arena = undefined,
    };

    try testing.expectEqualStrings(expect.type, stanza.type);
    try testing.expectEqualStrings(expect.args[0], stanza.args[0]);
    try testing.expectEqualSlices(u8, expect.body, stanza.body);
}

pub const Header = struct {
    recipients: ArrayList(Stanza),
    mac: ?[mac_length]u8,
    allocator: Allocator,
    /// Parse the header of an age file.
    /// After the function returned, `reader` position will be at the start of the payload.
    /// Caller owns the memory of the returned `Header`, must be free with `Header.destroy()`.
    pub fn parse(
        allocator: Allocator,
        reader: std.io.AnyReader,
    ) Error!Header {
        // TODO: rewrite this function when peeking api get implemented, see https://github.com/ziglang/zig/issues/4501
        var input: ArrayList(u8) = .empty;
        defer input.deinit(allocator);
        var start_idx: usize = 0;

        reader.streamUntilDelimiter(input.writer(allocator), '\n', null) catch {
            return Error.MalformedHeader;
        };

        try parseVersion(input.items[start_idx..]);
        start_idx = input.items.len;

        var recipients: ArrayList(Stanza) = .empty;
        errdefer {
            for (recipients.items) |stanza| {
                stanza.destroy();
            }
            recipients.deinit(allocator);
        }

        var parsing_stanzas = false;

        while (true) {
            const in_len = input.items.len;
            reader.streamUntilDelimiter(input.writer(allocator), '\n', null) catch {
                return Error.MalformedHeader;
            };

            if (parsing_stanzas) {
                if (std.mem.startsWith(u8, input.items[in_len..], stanza_prefix) or
                    std.mem.startsWith(u8, input.items[in_len..], mac_prefix))
                {
                    parsing_stanzas = false;
                    const stanza = try Stanza.parse(allocator, input.items[start_idx..in_len]);
                    try recipients.append(allocator, stanza);
                    start_idx = in_len;
                }
            }
            if (std.mem.startsWith(u8, input.items[start_idx..], stanza_prefix)) {
                parsing_stanzas = true;
            }
            if (std.mem.startsWith(u8, input.items[in_len..], mac_prefix)) {
                break;
            }
            try input.append(allocator, '\n');
        }

        const mac = try parseMac(input.items[start_idx..]);

        return Header{
            .recipients = recipients,
            .mac = mac,
            .allocator = allocator,
        };
    }

    /// Initialize a partial Header
    /// Use `Header.update()` to add a recipient and `Header.final()` to finalizes the header.
    /// Caller owns the memory of the returned `Header`, must be free with `Header.destroy()`.
    pub fn init(allocator: Allocator) Header {
        return Header{
            .recipients = .empty,
            .mac = null,
            .allocator = allocator,
        };
    }

    /// Add a single recipient to a partial Header
    /// The function assert it is a partial header.
    pub fn update(self: *Header, recipient: anytype, file_key: [file_key_size]u8) anyerror!void {
        assert(self.mac == null);

        const stanza = try recipient.wrap(self.allocator, file_key);
        try self.*.recipients.append(self.allocator, stanza);
    }

    /// Finalize a partial header
    pub fn final(self: *Header, file_key: [file_key_size]u8) Allocator.Error!void {
        const header_no_mac = try std.fmt.allocPrint(self.allocator, "{nomac}", .{self});
        defer self.allocator.free(header_no_mac);

        const hmac_key = computeHkdfKey(&file_key, "", header_label);
        var hmac: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&hmac, header_no_mac, &hmac_key);

        self.*.mac = hmac;
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
        for (self.recipients.items) |stanza| {
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
        /// Mac string, must start with `---` and ends without a newline.
        /// Must equal to `decoded_mac_length`
        input: []const u8,
    ) Error![mac_length]u8 {
        var args = std.mem.splitScalar(u8, input, ' ');

        if (!std.mem.startsWith(u8, args.first(), mac_prefix)) return Error.MalformedHeader;

        if (args.next()) |mac_line| {
            if (args.next() != null or mac_line.len != decoded_mac_length) {
                return Error.MalformedHeader;
            }

            var mac: [mac_length]u8 = undefined;
            base64Decoder.decode(&mac, mac_line) catch |err| switch (err) {
                b64Error.InvalidCharacter, b64Error.InvalidPadding => {
                    return Error.MalformedHeader;
                },
                else => unreachable,
            };

            return mac;
        }
        return Error.MalformedHeader;
    }
    /// Return `error` if the version string are not `version_line`
    fn parseVersion(
        /// Version string, must start with `age` and ends without a newline.
        input: []const u8,
    ) Error!void {
        if (!std.mem.startsWith(u8, input, version_prefix)) return Error.MalformedHeader;

        if (input.len < version_line.len) {
            return Error.MalformedHeader;
        }
        if (input.len > version_line.len or !std.mem.eql(u8, input, version_line)) {
            return Error.UnsupportedVersion;
        }
    }

    pub fn destroy(self: *Header) void {
        for (self.recipients.items) |value| {
            value.destroy();
        }
        self.recipients.deinit(self.allocator);
    }
};
