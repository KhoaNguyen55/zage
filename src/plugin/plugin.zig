const std = @import("std");
const Allocator = std.mem.Allocator;
const age = @import("age");
const Stanza = age.Stanza;
const base64Encoder = std.base64.standard_no_pad.Encoder;
const base64Decoder = std.base64.standard_no_pad.Decoder;

pub const parser = @import("parser.zig");
pub const client = @import("client.zig");

pub const StateMachine = struct {
    pub const V1 = struct {
        pub const recipient = "recipient-v1";
        pub const identity = "identity-v1";
    };
};
