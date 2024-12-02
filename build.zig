// SPDX-License-Identifier: CC0-1.0
const std = @import("std");

pub fn build(b: *std.Build) !void {
    var o = Options.make(b);
    const upstream = b.dependency("upstream", .{ .target = o.target, .optimize = o.optimize });

    const shared = try o.getShared(b, upstream);
    if (o.shared) b.installArtifact(shared);

    const static = try o.getStatic(b, upstream);
    if (o.static) b.installArtifact(static);
}

pub const Options = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

    static: bool,
    shared: bool,

    tsan: bool,
    ubsan: bool,

    blake2_unroll: bool,
    build_ed25519: bool,

    pub fn make(b: *std.Build) Options {
        return .{
            .target = b.standardTargetOptions(.{}),
            .optimize = b.standardOptimizeOption(.{}),

            .shared = b.option(bool, "shared", "build shared library (true)") orelse true,
            .static = b.option(bool, "static", "build static library (true)") orelse true,

            .ubsan = b.option(bool, "ubsan", "use UBSanitizer (false)") orelse false,
            .tsan = b.option(bool, "tsan", "use ThreadSanitizer (false)") orelse false,

            .blake2_unroll = b.option(bool, "blake2_unroll", "unroll BLAKE2 implementation, faster on modern cpus (true)") orelse true,
            .build_ed25519 = b.option(bool, "build_ed25519", "include the optional Ed25519 implementation (true)") orelse true,
        };
    }

    pub fn getStatic(o: Options, b: *std.Build, u: *std.Build.Dependency) !*std.Build.Step.Compile {
        const lib = b.addStaticLibrary(.{
            .name = "monocypher",
            .target = o.target,
            .optimize = o.optimize,
        });
        lib.link_function_sections = true;
        try o.addC(u, lib);
        return lib;
    }

    pub fn getShared(o: Options, b: *std.Build, u: *std.Build.Dependency) !*std.Build.Step.Compile {
        const lib = b.addSharedLibrary(.{
            .name = "monocypher",
            .target = o.target,
            .optimize = o.optimize,
        });
        try o.addC(u, lib);
        return lib;
    }

    pub fn addC(o: *const Options, u: *std.Build.Dependency, c: *std.Build.Step.Compile) !void {
        if (!o.blake2_unroll) c.defineCMacro("BLAKE2_NO_UNROLLING", "1");

        var files: std.BoundedArray([]const u8, 2) = .{};
        files.append("monocypher.c") catch unreachable;

        if (o.build_ed25519) {
            files.append("optional/monocypher-ed25519.c") catch unreachable;
            c.addIncludePath(u.path("src"));
        }

        c.addCSourceFiles(.{
            .root = u.path("src"),
            .files = files.constSlice(),
            .flags = &.{ "-std=c99", "-Wall", "-Wextra", "-pedantic" },
        });

        c.installHeader(u.path("src/monocypher.h"), "monocypher-ed25519.h");

        if (o.build_ed25519) {
            c.installHeader(u.path("src/optional/monocypher-ed25519.h"), "monocypher-ed25519.h");
        }
    }
};
