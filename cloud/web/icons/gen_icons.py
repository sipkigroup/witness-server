"""Generates the PWA icons (no dependencies): python3 icons/gen_icons.py. A shield with a check mark on the brand blue.
Not served (only icons/*.png is public)."""
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
BG, FG = (0x24, 0x57, 0xd6), (0xff, 0xff, 0xff)


def inside_shield(x, y):
    # unit square coordinates; shield: flat top, round-ish sides, point at the bottom
    if not (0.2 <= x <= 0.8 and 0.16 <= y <= 0.86):
        return False
    if y <= 0.55:
        return True
    half = 0.3 * (1 - ((y - 0.55) / 0.31) ** 1.6)
    return abs(x - 0.5) <= half


def on_check(x, y, w=0.055):
    def seg(ax, ay, bx, by):
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
        return ((x - ax - t * dx) ** 2 + (y - ay - t * dy) ** 2) ** 0.5 <= w
    return seg(0.36, 0.48, 0.47, 0.6) or seg(0.47, 0.6, 0.66, 0.38)


def pixel(x, y, maskable):
    s = 0.8 if maskable else 1.0                      # maskable: content inside the 80 % safe zone
    u, v = 0.5 + (x - 0.5) / s, 0.5 + (y - 0.5) / s
    if inside_shield(u, v):
        return BG if on_check(u, v) else FG
    return BG


def png(size, maskable=False, ss=3):
    rows = []
    for j in range(size):
        row = bytearray(b"\x00")
        for i in range(size):
            acc = [0, 0, 0]
            for a in range(ss):
                for b in range(ss):
                    c = pixel((i + (a + 0.5) / ss) / size, (j + (b + 0.5) / ss) / size, maskable)
                    acc = [p + q for p, q in zip(acc, c)]
            row += bytes(p // (ss * ss) for p in acc)
        rows.append(bytes(row))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b""))


if __name__ == "__main__":
    for name, size, mask in (("icon-192.png", 192, False), ("icon-512.png", 512, False), ("maskable-512.png", 512, True),
                             ("apple-touch-icon.png", 180, True)):
        with open(os.path.join(HERE, name), "wb") as f:
            f.write(png(size, mask))
        print(name, size)
