const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const build_cli = b.option(bool, "build-cli", "Build zage, the command line interface for age encryption") orelse false;

    const age = b.addModule("age", .{
        .root_source_file = b.path("src/age/age.zig"),
        .target = target,
        .optimize = optimize,
    });

    const bech32 = b.addModule("bech32", .{
        .root_source_file = b.path("src/age/bech32.zig"),
        .target = target,
        .optimize = optimize,
    });

    const age_plugin = b.addModule("age_plugin", .{
        .root_source_file = b.path("src/plugin/plugin.zig"),
        .target = target,
        .optimize = optimize,
    });
    age_plugin.addImport("age", age);
    age_plugin.addImport("bech32", bech32);

    if (build_cli) {
        const buildZage = @import("build-zage.zig").buildZage;
        buildZage(b, target, optimize, age);
    }

    const lib_unit_tests = b.addTest(.{
        .name = "unit_test",
        .root_module = age,
    });

    const lib_plugin_unit_tests = b.addTest(.{
        .name = "unit_test",
        .root_module = age_plugin,
    });

    const lib_testkit = b.addTest(.{
        .root_source_file = b.path("testkit_test.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "run tests");
    test_step.dependOn(&b.addRunArtifact(lib_unit_tests).step);
    test_step.dependOn(&b.addRunArtifact(lib_plugin_unit_tests).step);
    test_step.dependOn(&b.addRunArtifact(lib_testkit).step);

    const lldb = b.addSystemCommand(&.{
        "lldb",
        "--",
    });

    lldb.addArtifactArg(lib_unit_tests);

    const lldb_step = b.step("debug", "debug unit tests with lldb");
    lldb_step.dependOn(&lldb.step);
}
