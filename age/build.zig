const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("age", .{
        .root_source_file = b.path("age.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("age.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_test = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "run tests");
    test_step.dependOn(&run_test.step);
}
