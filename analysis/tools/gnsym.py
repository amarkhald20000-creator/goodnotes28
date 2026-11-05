#!/usr/bin/env python3
"""Goodnotes Mach-O Swift metadata parser: list types + class method descriptors."""
import struct, sys, json

BIN = 'Goodnotes'


class MachO:
    def __init__(self, path):
        self.f = open(path, 'rb')
        hdr = self.f.read(4 * 1024 * 1024)
        ncmds = struct.unpack('<I', hdr[16:20])[0]
        off = 32
        self.segs = []
        self.secs = {}
        self.symtab = None
        for _ in range(ncmds):
            cmd, size = struct.unpack('<II', hdr[off:off + 8])
            if cmd == 0x19:
                name = hdr[off + 8:off + 24].split(b'\0')[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', hdr[off + 24:off + 56])
                ns = struct.unpack('<I', hdr[off + 64:off + 68])[0]
                self.segs.append((name, vmaddr, vmsize, fileoff, filesize))
                for s in range(ns):
                    so = off + 72 + s * 80
                    sname = hdr[so:so + 16].split(b'\0')[0].decode()
                    addr, sz = struct.unpack('<QQ', hdr[so + 32:so + 48])
                    self.secs[f"{name},{sname}"] = (addr, sz)
            elif cmd == 0x2:
                self.symtab = struct.unpack('<IIII', hdr[off + 8:off + 24])
            off += size
        self.text = self.secs['__TEXT,__text']

    def v2o(self, addr):
        for name, vmaddr, vmsize, fileoff, filesize in self.segs:
            if vmaddr <= addr < vmaddr + filesize:
                return fileoff + (addr - vmaddr)
        return None

    def read(self, addr, n):
        o = self.v2o(addr)
        if o is None:
            return None
        self.f.seek(o)
        return self.f.read(n)

    def u32(self, addr):
        b = self.read(addr, 4)
        return struct.unpack('<I', b)[0] if b and len(b) == 4 else None

    def i32(self, addr):
        b = self.read(addr, 4)
        return struct.unpack('<i', b)[0] if b and len(b) == 4 else None

    def cstr(self, addr, limit=400):
        o = self.v2o(addr)
        if o is None:
            return None
        self.f.seek(o)
        b = self.f.read(limit)
        z = b.find(b'\0')
        if z < 0:
            return None
        try:
            s = b[:z].decode('utf8')
        except UnicodeDecodeError:
            return None
        return s

    def in_text(self, addr):
        a, sz = self.text
        return a <= addr < a + sz


def types(m):
    ta, ts = m.secs['__TEXT,__swift5_types']
    blob = m.read(ta, ts)
    out = []
    for i in range(ts // 4):
        rel = struct.unpack('<i', blob[i * 4:i * 4 + 4])[0]
        desc = ta + i * 4 + rel
        flags = m.u32(desc)
        if flags is None:
            continue
        kind = flags & 0x1f
        nrel = m.i32(desc + 8)
        if nrel is None:
            continue
        name = m.cstr(desc + 8 + nrel)
        if name is None:
            continue
        out.append((kind, name, desc))
    return out


def module_of(m, desc):
    """Walk parent chain to find module name."""
    cur = desc
    for _ in range(8):
        d = m.read(cur, 16)
        if not d:
            return None
        flags = struct.unpack('<I', d[:4])[0]
        kind = flags & 0x1f
        if kind == 0:
            rel = struct.unpack('<i', d[8:12])[0]
            return m.cstr(cur + 8 + rel)
        rel = struct.unpack('<i', d[4:8])[0]
        if rel == 0:
            return None
        cur = cur + 4 + rel
    return None


def parse_methods(m, desc):
    """Scan for a valid MethodDescriptor array reachable from class descriptor."""
    best = None
    for k in range(0, 24):
        base = desc + 12 + k * 4
        rel = m.i32(base)
        if rel is None:
            continue
        arr = base + rel
        # walk forward collecting valid entries
        entries = []
        p = arr
        while True:
            nrel = m.i32(p)
            irel = m.i32(p + 4)
            fl = m.u32(p + 8)
            if nrel is None or irel is None or fl is None:
                break
            nm = m.cstr(p + nrel)
            impl = p + 4 + irel
            kind = fl & 0xf
            if not nm or kind > 4 or not m.in_text(impl):
                break
            if not all(32 <= ord(c) < 127 for c in nm[:1]) and nm[:1] != '_':
                break
            entries.append({'name': nm, 'impl': hex(impl), 'fileoff': hex(m.v2o(impl) or 0),
                            'kind': kind, 'instance': (fl >> 4) & 1, 'flags': fl})
            p += 12
            if len(entries) > 3000:
                break
        if len(entries) >= 3 and (best is None or len(entries) > len(best)):
            best = entries
    return best


if __name__ == '__main__':
    m = MachO(BIN)
    tl = types(m)
    if len(sys.argv) > 1 and sys.argv[1] == 'list':
        pat = sys.argv[2].lower() if len(sys.argv) > 2 else ''
        for kind, name, desc in tl:
            if kind != 16 or pat not in name.lower():
                continue
            mod = module_of(m, desc)
            print(f"{mod}.{name}\t{hex(desc)}")
    elif len(sys.argv) > 2 and sys.argv[1] == 'methods':
        target = sys.argv[2]
        for kind, name, desc in tl:
            if kind != 16:
                continue
            mod = module_of(m, desc)
            full = f"{mod}.{name}"
            if target not in full:
                continue
            ms = parse_methods(m, desc)
            print(f"=== {full} @ {hex(desc)}  methods={len(ms) if ms else 0}")
            if ms:
                for e in ms:
                    print(f"  {'i' if e['instance'] else 'c'} k{e['kind']} {e['impl']} {e['name']}")
