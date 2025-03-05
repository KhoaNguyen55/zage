pub const StateMachine = struct {
    pub const V1 = enum([]const u8) {
        recipient = "recipient-v1",
        identity = "identity-v1",
    };
};
