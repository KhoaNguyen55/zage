const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const testing = std.testing;
const test_allocator = testing.allocator;

const shl = std.math.shl;
const shr = std.math.shr;

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const generator: []const u32 = &.{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
const max_characters = 90;

pub const Bech32 = struct {
    hrp: []u8,
    data: []u8,
};

pub const Error = error{
    InvalidData,
    InvalidHrp,
    InvalidSeperator,
    InvalidChecksum,
    BadChar,
    IllegalZeroPadding,
    NonZeroPadding,
    MixedCase,
};

fn isStringLower(string: []const u8) ?bool {
    var lower: ?bool = null;
    for (string) |c| {
        if (std.ascii.isAlphabetic(c)) {
            if (lower == null) {
                lower = std.ascii.isLower(c);
            } else if (lower != std.ascii.isLower(c)) {
                return null;
            }
        }
    }
    if (lower == null) {
        return true;
    }
    return lower;
}

fn polymod(values: []const u8) u32 {
    var chk: u32 = 1;
    for (values) |value| {
        const top = shr(u32, chk, 25);
        chk = shl(u32, (chk & 0x1ffffff), 5);
        chk = chk ^ @as(u32, value);
        for (0..5) |i| {
            const bit = shr(u32, top, i) & 1;
            if (bit == 1) {
                chk ^= generator[i];
            }
        }
    }
    return chk;
}

fn hrpExpand(allocator: Allocator, hrp: []const u8) ![]const u8 {
    const hrp_lower = try std.ascii.allocLowerString(allocator, hrp);
    defer allocator.free(hrp_lower);

    var ret = try ArrayList(u8).initCapacity(allocator, (hrp_lower.len * 2) + 1);
    errdefer ret.deinit();

    for (hrp_lower) |c| {
        try ret.append(shr(u8, c, 5));
    }
    try ret.append(0);

    for (hrp_lower) |c| {
        try ret.append(c & 31);
    }

    return ret.toOwnedSlice();
}

fn createChecksum(allocator: Allocator, hrp: []const u8, data: []const u8) ![]u8 {
    const expanded_hrp = try hrpExpand(allocator, hrp);
    defer allocator.free(expanded_hrp);
    const padding: []const u8 = &.{ 0, 0, 0, 0, 0, 0 };
    const arrays: []const []const u8 = &.{ expanded_hrp, data, padding };

    const values = try std.mem.concat(allocator, u8, arrays);
    defer allocator.free(values);

    const mod = polymod(values) ^ 1;

    var ret = try allocator.alloc(u8, 6);
    errdefer allocator.free(ret);

    for (0..ret.len) |p| {
        const shift = 5 * (5 - p);
        ret[p] = @intCast(shr(u32, mod, shift) & 31);
    }

    return ret;
}

fn convertBits(allocator: Allocator, data: []const u8, frombits: u8, tobits: u8, pad: bool) ![]u8 {
    var ret = ArrayList(u8).init(allocator);
    errdefer ret.deinit();
    var acc: u32 = 0;
    var bits: u8 = 0;
    const maxv: u8 = shl(u8, 1, tobits) -% 1;

    for (data) |value| {
        if (shr(u8, value, frombits) != 0) {
            return Error.InvalidData;
        }

        acc = shl(u32, acc, frombits) | @as(u32, value);
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            try ret.append(@intCast(shr(u32, acc, bits) & maxv));
        }
    }

    if (pad) {
        if (bits > 0) {
            try ret.append(@intCast(shl(u32, acc, (tobits - bits)) & maxv));
        }
    } else if (bits >= frombits) {
        return Error.IllegalZeroPadding;
    } else if (shl(u32, acc, (tobits - bits)) & maxv != 0) {
        return Error.NonZeroPadding;
    }

    return ret.toOwnedSlice();
}

pub fn encode(allocator: Allocator, hrp: []const u8, data: []const u8) ![]const u8 {
    const values = try convertBits(allocator, data, 8, 5, true);
    defer allocator.free(values);

    if (hrp.len < 1) {
        return Error.InvalidHrp;
    }

    for (hrp) |c| {
        if (c < 33 or c > 126) {
            return Error.BadChar;
        }
    }

    const lower = isStringLower(hrp) orelse return Error.MixedCase;

    const hrp_lower = try std.ascii.allocLowerString(allocator, hrp);
    defer allocator.free(hrp_lower);

    var ret = ArrayList(u8).init(allocator);
    errdefer ret.deinit();
    try ret.appendSlice(hrp_lower);
    try ret.append('1');
    for (values) |p| {
        try ret.append(charset[p]);
    }
    const checksum = try createChecksum(allocator, hrp_lower, values);
    defer allocator.free(checksum);
    for (checksum) |p| {
        try ret.append(charset[p]);
    }

    const encoded_str = try ret.toOwnedSlice();
    errdefer allocator.free(encoded_str);

    if (lower) {
        return encoded_str;
    }
    const upper_str = std.ascii.allocUpperString(allocator, encoded_str);
    allocator.free(encoded_str);
    return upper_str;
}

pub fn decode(allocator: Allocator, string: []const u8) !Bech32 {
    if (isStringLower(string) == null) {
        return Error.MixedCase;
    }

    const pos = std.mem.lastIndexOfScalar(u8, string, '1') orelse return Error.InvalidSeperator;
    if (pos < 1 or pos + 7 > string.len) {
        return Error.InvalidSeperator;
    }

    const hrp = try allocator.dupe(u8, string[0..pos]);
    errdefer allocator.free(hrp);
    for (hrp) |c| {
        if (c < 33 or c > 126) {
            return Error.BadChar;
        }
    }

    var data_array = ArrayList(u8).init(allocator);
    errdefer data_array.deinit();

    const lower_str = try std.ascii.allocLowerString(allocator, string[pos + 1 ..]);
    defer allocator.free(lower_str);
    for (lower_str) |c| {
        const d = std.mem.indexOfScalar(u8, charset, c) orelse return Error.InvalidData;
        try data_array.append(@intCast(d));
    }

    const data = try data_array.toOwnedSlice();
    defer allocator.free(data);

    // verify checksum
    const hrp_expanded = try hrpExpand(allocator, hrp);
    defer allocator.free(hrp_expanded);

    const arrays: []const []const u8 = &.{ hrp_expanded, data };

    const combined = try std.mem.concat(allocator, u8, arrays);
    defer allocator.free(combined);
    if (polymod(combined) != 1) {
        return Error.InvalidChecksum;
    }

    const converted_data = try convertBits(
        allocator,
        data[0 .. data.len - 6],
        5,
        8,
        false,
    );
    errdefer allocator.free(converted_data);

    return Bech32{ .hrp = hrp, .data = converted_data };
}

test "decode valid strings" {
    const valid_bech32: []const []const u8 = &.{
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        // long vectors that we do accept despite the spec see `https://github.com/FiloSottile/age/issues/453`
        "long10pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7qfcsvr0",
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    };

    for (valid_bech32) |str| {
        const bech_decoded = try decode(test_allocator, str);
        defer {
            test_allocator.free(bech_decoded.hrp);
            test_allocator.free(bech_decoded.data);
        }
        const bech_encoded = try encode(
            test_allocator,
            bech_decoded.hrp,
            bech_decoded.data,
        );
        defer test_allocator.free(bech_encoded);
        try testing.expectEqualStrings(str, bech_encoded);
    }
}

test "decode invalid strings" {
    const invalid_seperator: []const []const u8 = &.{
        "li1dgmt3",
        "split1a2y9w", // too short data part
        "pzry9x0s0muk",
        "1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", // empty hrp
        "1pzry9x0s0muk",
        "10a06t8",
        "1qzzfhee",
    };

    const invalid_checksum: []const []const u8 = &.{
        // invalid checksum
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e2w",
        "A1G7SGD8",
    };

    const invalid_data: []const []const u8 = &.{
        "split1cheo2y9e2w", // invalid character (o) in data part
        "de1lg7wt\xff",
        "x1b4n0q5v",
    };

    const bad_char: []const []const u8 = &.{
        // invalid character (DEL) in hrp
        "spl\x7ft1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        // invalid character (space) in hrp
        "s lit1checkupstagehandshakeupstreamerranterredcaperredp8hs2p",
    };

    for (invalid_seperator) |str| {
        const bech_decoded = decode(test_allocator, str);
        try testing.expectError(Error.InvalidSeperator, bech_decoded);
    }

    for (invalid_checksum) |str| {
        const bech_decoded = decode(test_allocator, str);
        try testing.expectError(Error.InvalidChecksum, bech_decoded);
    }

    for (invalid_data) |str| {
        const bech_decoded = decode(test_allocator, str);
        try testing.expectError(Error.InvalidData, bech_decoded);
    }

    for (bad_char) |str| {
        const bech_decoded = decode(test_allocator, str);
        try testing.expectError(Error.BadChar, bech_decoded);
    }
}
