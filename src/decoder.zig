const std = @import("std");

const Base64 = struct {
    table: *const [64]u8,

    pub fn init() Base64 {
        const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lower = "abcdefghijklmnopqrstuvwxyz";
        const numbers_symb = "0123456789+/";
        return Base64{ .table = upper ++ lower ++ numbers_symb };
    }

    pub fn encode(self: Base64, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return "";
        }

        const n_out = try calc_encode_len(input);
        const out = try allocator.alloc(u8, n_out);
        var out_ptr = out.ptr;
        var chunks = std.mem.window(u8, input, 3, 3);

        while (chunks.next()) |chunk| : (out_ptr += 4) {
            out_ptr[0..4].* = self.encode_chunk(chunk);
        }

        if (input.len % 3 != 0) {
            const rem = input[input.len - (input.len % 3) ..];
            out_ptr[0..4].* = self.encode_chunk(rem);
        }

        return out;
    }

    fn encode_chunk(self: Base64, chunk: []const u8) [4]u8 {
        return switch (chunk.len) {
            1 => .{
                self.char_at(chunk[0] >> 2),
                self.char_at((chunk[0] & 0x03) << 4),
                '=',
                '=',
            },
            2 => .{
                self.char_at(chunk[0] >> 2),
                self.char_at((chunk[0] & 0x03) << 4 + (chunk[1] >> 4)),
                self.char_at((chunk[1] & 0x0f) << 2),
                '=',
            },
            3 => .{
                self.char_at(chunk[0] >> 2),
                self.char_at((chunk[0] & 0x03) << 4 + (chunk[1] >> 4)),
                self.char_at((chunk[1] & 0x0f) << 2 + (chunk[2] >> 6)),
                self.char_at(chunk[2] & 0x3f),
            },
            _ => unreachable,
        };
    }

    fn char_at(self: Base64, index: u8) u8 {
        return self.table[index];
    }

    fn calc_encode_len(input: []const u8) !usize {
        return try std.math.divCeil(usize, input.len, 3) * 4;
    }

    fn calc_decode_len(input: []const u8) !usize {
        if (input.len < 4) return 3 else return try std.math.divFloor(usize, input.len, 4) * 3;
    }
};

test "calc_len" {
    const input = [_]usize{ 3, 12, 4, 17 };
    const output = [_]usize{ 4, 16, 8, 24 };

    for (input, output) |in, out| {
        try std.testing.expectEqual(out, try std.math.divCeil(usize, in, 3) * 4);
    }
}
