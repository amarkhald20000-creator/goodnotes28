#!/usr/bin/env python3
"""Fast iterative dyld export-trie parser."""
import os
import struct
import sys

# Outputs land in analysis/data/ next to this tool.
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def uleb(b, p):
    r = 0
    sh = 0
    while True:
        x = b[p]
        p += 1
        r |= (x & 0x7f) << sh
        sh += 7
        if not (x & 0x80):
            return r, p


def parse(blob, limit=4_000_000):
    out = []
    stack = [(0, '')]
    seen = set()
    guard = 0
    while stack:
        off, prefix = stack.pop()
        guard += 1
        if guard > limit:
            break
        p = off
        tsize, p = uleb(blob, p)
        if tsize:
            out.append(prefix)
            p += tsize
        if p >= len(blob):
            continue
        child_count = blob[p]
        p += 1
        if child_count == 0:
            continue
        for _ in range(child_count):
            z = blob.find(b'\0', p)
            label = blob[p:z].decode('utf8', 'replace')
            p = z + 1
            child, p = uleb(blob, p)
            stack.append((child, prefix + label))
    return out


def main():
    path = 'Goodnotes'
    f = open(path, 'rb')
    hdr = f.read(1024 * 1024)
    n = struct.unpack('<I', hdr[16:20])[0]
    off = 32
    trie = None
    for _ in range(n):
        cmd, size = struct.unpack('<II', hdr[off:off + 8])
        if cmd == 0x80000033:
            trie = struct.unpack('<II', hdr[off + 8:off + 16])
        off += size
    f.seek(trie[0])
    blob = f.read(trie[1])
    syms = parse(blob)
    print('exports', len(syms))
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, 'exports.txt'), 'w') as fh:
        fh.write('\n'.join(syms))
    for s in syms[:20]:
        print(' ', s)


if __name__ == '__main__':
    main()
