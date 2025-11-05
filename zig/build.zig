const std = @import("std");

pub fn build(b: *std.Build) void {
    const exe_1_1 = b.addExecutable("cryptopals_set1_ch1", "src/set1_ch1.zig");
    b.installArtifact(exe_1_1);
}
