const std = @import("std");
const os = std.os;
const IPv4 = std.x.os.IPv4;
const Allocator = std.mem.Allocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

const ParseError = error{
    FormatError,
};

fn parsec(c: u8) ParseError!u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 0x0A,
        'A'...'F' => c - 'A' + 0x0A,
        else => ParseError.FormatError,
    };
}

const MacAddr = struct {
    data: [6]u8,

    fn parse(text: []const u8) !MacAddr {
        if (text.len != 17) {
            return ParseError.FormatError;
        }
        var data: [6]u8 = undefined;

        for (text) |c, i| {
            const m = i % 3;
            switch (m) {
                0, 1 => {
                    const v = try parsec(c);
                    const r = &data[i / 3];
                    if (m == 0) {
                        r.* = v << 4;
                    } else {
                        r.* |= v;
                    }
                },
                2 => {
                    if (c != ':') {
                        return ParseError.FormatError;
                    }
                },
                else => unreachable,
            }
        }
        return MacAddr{
            .data = data,
        };
    }
};

test "parseMacAddr success1" {
    const expectEqual = std.testing.expectEqual;
    const text = "00:11:22:33:44:55";
    const addr = try MacAddr.parse(text);
    try expectEqual(MacAddr{
        .data = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
    }, addr);
}

test "parseMacAddr success2" {
    const expectEqual = std.testing.expectEqual;
    const text = "FF:FF:FF:FF:FF:FF";
    const addr = try MacAddr.parse(text);
    try expectEqual(MacAddr{
        .data = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    }, addr);
}

test "parseMacAddr err1" {
    const expectError = std.testing.expectError;
    const text = "";
    const err = MacAddr.parse(text);
    try expectError(ParseError.FormatError, err);
}

test "parseMacAddr err2" {
    const expectError = std.testing.expectError;
    const text = "00:11:22:33:44:55:66";
    const err = MacAddr.parse(text);
    try expectError(ParseError.FormatError, err);
}

test "parseMacAddr err3" {
    const expectError = std.testing.expectError;
    const text = "00.11.22.33.44.55";
    const err = MacAddr.parse(text);
    try expectError(ParseError.FormatError, err);
}

const CliOpts = struct {
    macaddr: MacAddr,
    network: IPv4,

    fn parseArgs() !CliOpts {
        var buf: [8192]u8 = undefined;
        const mem = FixedBufferAllocator.init(&buf).allocator();
        return parseArgsWithAllocator(mem);
    }

    const ParseError = error{
        InvalidArguments,
    };

    fn parseArgsWithAllocator(alloc: Allocator) !CliOpts {
        var macaddr: ?MacAddr = null;
        var network: ?IPv4 = null;

        var args = try std.process.argsWithAllocator(alloc);
        defer args.deinit();

        _ = args.skip();
        while (args.next(alloc)) |maybearg| {
            const arg = try maybearg;
            defer alloc.free(arg);

            if (macaddr == null) {
                macaddr = try MacAddr.parse(arg);
                continue;
            }
            if (network == null) {
                network = try IPv4.parse(arg);
                continue;
            }
            return CliOpts.ParseError.InvalidArguments;
        }

        if (macaddr == null) {
            return CliOpts.ParseError.InvalidArguments;
        }
        return CliOpts{
            .macaddr = macaddr.?,
            .network = network orelse IPv4.broadcast,
        };
    }
};

fn makePacket(mac: MacAddr) ![102]u8 {
    const mem = std.mem;

    var buf: [102]u8 = undefined;
    mem.copy(u8, buf[0..6], ([6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })[0..]);
    var p: u32 = 0;
    while (p < 16) : (p += 1) {
        const o = (p + 1) * 6;
        mem.copy(u8, buf[o..], mac.data[0..]);
    }
    return buf;
}

pub fn main() anyerror!void {
    const opts = try CliOpts.parseArgs();
    const pkt = try makePacket(opts.macaddr);

    const addr = os.sockaddr{
        .family = os.AF.INET,
        .data = [14]u8{
            0x00,                   0x07, // port
            opts.network.octets[0], opts.network.octets[1],
            opts.network.octets[2], opts.network.octets[3],
            0x00,                   0x00,
            0x00,                   0x00,
            0x00,                   0x00,
            0x00,                   0x00,
        },
    };

    const sock = try os.socket(os.AF.INET, os.SOCK.DGRAM | os.SOCK.CLOEXEC, os.IPPROTO.UDP);
    defer os.closeSocket(sock);

    try os.setsockopt(sock, os.SOL.SOCKET, os.SO.BROADCAST, ([4]u8{ 0x01, 0x00, 0x00, 0x00 })[0..]);
    const n = try os.sendto(sock, &pkt, 0, &addr, 16);
    if (n != 102) {
        unreachable;
    }
}
