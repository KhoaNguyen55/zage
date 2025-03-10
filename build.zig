const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const build_cli = b.option(bool, "build-cli", "Build zage, the command line interface for age encryption") orelse false;

    const module = b.addModule("age", .{
        .root_source_file = b.path("src/age/age.zig"),
        .target = target,
        .optimize = optimize,
    });

    if (build_cli) {
        const buildZage = @import("build-zage.zig").buildZage;
        buildZage(b, target, optimize, module);
    }

    const lib_unit_tests = b.addTest(.{
        .name = "unit_test",
        .root_module = module,
    });

    const lib_testkit = b.addTest(.{
        .root_source_file = b.path("testkit_test.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_unit_test = b.addRunArtifact(lib_unit_tests);
    const run_testkit = b.addRunArtifact(lib_testkit);

    const test_step = b.step("test", "run tests");
    test_step.dependOn(&run_unit_test.step);
    test_step.dependOn(&run_testkit.step);

    const lldb = b.addSystemCommand(&.{
        "lldb",
        "--",
    });

    lldb.addArtifactArg(lib_unit_tests);

    const lldb_step = b.step("debug", "debug unit tests with lldb");
    lldb_step.dependOn(&lldb.step);
}
