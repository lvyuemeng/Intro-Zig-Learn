const std = @import("std");

const Base64 = struct {
    const pad_char = '=';
    const pad_index = 64;

    table_char: *const [64]u8,

    pub fn init() Base64 {
        const table_char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        return Base64{
            .table_char = table_char,
        };
    }

    pub fn encode(self: Base64, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return "";
        }

        const n_out = try calc_encode_len(input);
        const out = try allocator.alloc(u8, n_out);
        errdefer allocator.free(out);

        var out_slice = out[0..];
        var chunks = std.mem.window(u8, input, 3, 3);

        while (chunks.next()) |chunk| {
            const encoded = self.encode_chunk(chunk);
            const valid_len = @min(4, out_slice.len);
            std.mem.copyForwards(u8, out_slice[0..valid_len], encoded[0..valid_len]);
            out_slice = out_slice[valid_len..];
        }

        return out;
    }

    fn encode_chunk(self: Base64, chunk: []const u8) [4]u8 {
        const b0 = chunk[0];
        const b1 = if (chunk.len > 1) chunk[1] else 0;
        const b2 = if (chunk.len > 2) chunk[2] else 0;

        return [4]u8{
            self.char_at(b0 >> 2),
            self.char_at((b0 & 0x03) << 4 | (b1 >> 4)),
            if (chunk.len > 1) self.char_at((b1 & 0x0f) << 2 | (b2 >> 6)) else pad_char,
            if (chunk.len > 2) self.char_at(b2 & 0x3f) else pad_char,
        };
    }

    pub fn decode(self: Base64, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return "";
        }

        const n_out = try calc_decode_len(input);
        const out = try allocator.alloc(u8, n_out);
        errdefer allocator.free(out);

        var chunks = std.mem.window(u8, input, 4, 4);
        var out_slice = out[0..];

        while (chunks.next()) |chunk| {
            const decoded = self.decode_chunk(chunk);
            const valid_len = @min(3, out_slice.len);
            std.mem.copyForwards(u8, out_slice[0..valid_len], decoded[0..valid_len]);
            out_slice = out_slice[valid_len..];
        }

        return out;
    }

    fn decode_chunk(self: Base64, chunk: []const u8) [3]u8 {
        var b: [4]u8 = undefined;
        for (0..4) |i| {
            b[i] = self.char_index(chunk[i]);
        }

        return [3]u8{
            (b[0] << 2) | (b[1] >> 4),
            if (b[2] != pad_index) (b[1] << 4) | (b[2] >> 2) else 0,
            if (b[3] != pad_index) (b[2] << 6) | b[3] else 0,
        };
    }

    fn char_at(self: Base64, index: u8) u8 {
        return self.table_char[index];
    }

    fn char_index(self: Base64, char: u8) u8 {
        _ = self;
        if (char == pad_char) return pad_index;

        if (char >= 'A' and char <= 'Z') {
            return char - 'A';
        }

        if (char >= 'a' and char <= 'z') {
            return char - 'a' + 26;
        }

        if (char >= '0' and char <= '9') {
            return char - '0' + 52;
        }

        if (char == '+') return 62;
        if (char == '/') return 63;

        return pad_index;
    }

    fn calc_encode_len(input: []const u8) !usize {
        return try std.math.divCeil(usize, input.len, 3) * 4;
    }

    fn calc_decode_len(input: []const u8) !usize {
        if (input.len % 4 != 0) {
            return error.InvalidInput;
        }
        const padding: u8 = blk: {
            var count: u8 = 0;
            for (input[input.len - 2 ..]) |c| {
                if (c == pad_char) count += 1 else break;
            }
            break :blk count;
        };
        return try std.math.divFloor(usize, input.len, 4) * 3 - padding;
    }
};

test "Table Index" {
    const base64 = Base64.init();

    std.debug.print("Index of 'A': {}\n", .{base64.char_index('A')});
    std.debug.print("Index of 'O': {}\n", .{base64.char_index('O')});
    std.debug.print("Index of 'Z': {}\n", .{base64.char_index('Z')});
    std.debug.print("Index of 'a': {}\n", .{base64.char_index('a')});
    std.debug.print("Index of 'z': {}\n", .{base64.char_index('z')});
    std.debug.print("Index of '0': {}\n", .{base64.char_index('0')});
    std.debug.print("Index of '9': {}\n", .{base64.char_index('9')});
    std.debug.print("Index of '+': {}\n", .{base64.char_index('+')});
    std.debug.print("Index of '/': {}\n", .{base64.char_index('/')});
    std.debug.print("Index of '=': {}\n", .{base64.char_index('=')});
}

test "Base64 Simple Tests" {
    var fix_buf: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fix_buf);
    const allocator = fba.allocator();

    const TestCase = struct {
        input: []const u8,
        expected: []const u8,
    };

    const test_cases = [_]TestCase{
        .{ .input = "A", .expected = "QQ==" },
        .{ .input = "AB", .expected = "QUI=" },
        .{ .input = "ABC", .expected = "QUJD" },
        .{ .input = "Hello", .expected = "SGVsbG8=" },
        .{ .input = "Hello, World!", .expected = "SGVsbG8sIFdvcmxkIQ==" },
    };

    const base64 = Base64.init();

    for (test_cases) |case| {
        const encoded = try base64.encode(allocator, case.input);
        defer allocator.free(encoded);

        std.debug.print("\nInput: {s}\n", .{case.input});
        std.debug.print("Encoded (actual): {s}\n", .{encoded});
        std.debug.print("Encoded (expected): {s}\n", .{case.expected});

        const decoded = try base64.decode(allocator, encoded);
        defer allocator.free(decoded);

        std.debug.print("Decoded: {s}\n", .{decoded});
    }
}
