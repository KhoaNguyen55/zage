const std = @import("std");

pub fn buildZage(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    module: *std.Build.Module,
) void {
    const exe = b.addExecutable(.{
        .name = "zage",
        .root_source_file = b.path("src/zage/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("age", module);
    b.installArtifact(exe);
}
