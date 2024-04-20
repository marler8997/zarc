const std = @import("std");

const test_names = .{ "zip", "tar" };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zarc = b.addModule("zarc", .{
        .root_source_file = b.path("src/main.zig"),
    });

    const tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_tests = b.step("test", "Run library tests");
    run_tests.dependOn(&tests.step);

    inline for (test_names) |name| {
        const exe = b.addExecutable(.{
            .name = b.fmt("zarc-{s}", .{name}),
            .root_source_file = b.path("tests/" ++ name ++ ".zig"),
            .target = target,
            .optimize = optimize,
        });

        exe.root_module.addImport("zarc", zarc);
        b.installArtifact(exe);

        const run_exe = b.addRunArtifact(exe);
        run_exe.addDirectoryArg(b.path("tests/" ++ name));

        const run_step = b.step(b.fmt("run-{s}", .{name}), b.fmt("Run the {s} format tests", .{name}));
        run_step.dependOn(&run_exe.step);
    }
}
