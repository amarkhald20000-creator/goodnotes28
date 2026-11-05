#!/usr/bin/env python3
"""Decode dyld chained fixups + dump ObjC classes/methods from the Goodnotes binary."""
import os
import struct

# Outputs land in analysis/data/ next to this tool.
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


class MachO:
    def __init__(self, path):
        self.f = open(path, 'rb')
        hdr = self.f.read(4 * 1024 * 1024)
        ncmds = struct.unpack('<I', hdr[16:20])[0]
        off = 32
        self.segs = []
        self.secs = {}
        self.chained = None
        for _ in range(ncmds):
            cmd, size = struct.unpack('<II', hdr[off:off + 8])
            if cmd == 0x19:
                name = hdr[off + 8:off + 24].split(b'\0')[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack('<QQQQ', hdr[off + 24:off + 56])
                ns = struct.unpack('<I', hdr[off + 64:off + 68])[0]
                self.segs.append({'name': name, 'vmaddr': vmaddr, 'vmsize': vmsize,
                                  'fileoff': fileoff, 'filesize': filesize})
                for s in range(ns):
                    so = off + 72 + s * 80
                    sname = hdr[so:so + 16].split(b'\0')[0].decode()
                    addr, sz = struct.unpack('<QQ', hdr[so + 32:so + 48])
                    self.secs[f"{name},{sname}"] = (addr, sz)
            elif cmd == 0x80000034:
                dataoff, datasize = struct.unpack('<II', hdr[off + 8:off + 16])
                self.chained = (dataoff, datasize)
            off += size
        self.base = [x['vmaddr'] for x in self.segs if x['name'] == '__TEXT'][0]

    def v2o(self, addr):
        for s in self.segs:
            if s['vmaddr'] <= addr < s['vmaddr'] + s['filesize']:
                return s['fileoff'] + (addr - s['vmaddr'])
        return None

    def read(self, addr, n):
        o = self.v2o(addr)
        if o is None:
            return None
        self.f.seek(o)
        return self.f.read(n)

    def cstr(self, addr, limit=400):
        o = self.v2o(addr)
        if o is None:
            return None
        self.f.seek(o)
        b = self.f.read(limit)
        z = b.find(b'\0')
        if z <= 0:
            return None
        try:
            return b[:z].decode('utf8')
        except UnicodeDecodeError:
            return None

    def decode_fixups(self):
        dataoff, datasize = self.chained
        self.f.seek(dataoff)
        blob = self.f.read(datasize)
        (version, starts_off, imports_off, symbols_off, imports_count,
         imports_fmt, symbols_fmt) = struct.unpack('<7I', blob[:28])
        imports = []
        for i in range(imports_count):
            if imports_fmt == 1:
                v = struct.unpack('<I', blob[imports_off + i * 4:imports_off + i * 4 + 4])[0]
                imports.append(self._sym(blob, symbols_off + (v >> 9)))
            elif imports_fmt == 2:
                v = struct.unpack('<i', blob[imports_off + i * 8:imports_off + i * 8 + 4])[0]
                imports.append(self._sym(blob, symbols_off + (v >> 9)))
            elif imports_fmt == 3:
                v = struct.unpack('<Q', blob[imports_off + i * 16:imports_off + i * 16 + 8])[0]
                imports.append(self._sym(blob, symbols_off + (v >> 32)))
            else:
                imports.append('?')
        seg_count = struct.unpack('<I', blob[starts_off:starts_off + 4])[0]
        seg_info_offsets = struct.unpack('<%dI' % seg_count,
                                         blob[starts_off + 4:starts_off + 4 + 4 * seg_count])
        fixups = {}
        for i, so in enumerate(seg_info_offsets):
            if so == 0:
                continue
            p = starts_off + so
            (size, page_size, pointer_format, seg_offset,
             max_valid, page_count) = struct.unpack('<IHHQIH', blob[p:p + 22])
            page_start = struct.unpack('<%dH' % page_count, blob[p + 22:p + 22 + 2 * page_count])
            for pg in range(page_count):
                start = page_start[pg]
                if start == 0xFFFF:
                    continue
                addr = seg_offset + pg * page_size + start
                while True:
                    _b = self.read(self.base + addr, 8)
                    if not _b or len(_b) != 8:
                        break
                    raw = struct.unpack('<Q', _b)[0]
                    if pointer_format in (2, 6):
                        bind = raw >> 63
                        nxt = (raw >> 51) & 0xFFF
                        if bind:
                            ordinal = raw & 0xFFFFFF
                            fixups[self.base + addr] = ('bind', imports[ordinal] if ordinal < len(imports) else '?')
                        else:
                            target = raw & 0xFFFFFFFFF
                            tv = self.base + target if pointer_format == 6 else target
                            fixups[self.base + addr] = ('rebase', tv)
                        if nxt == 0:
                            break
                        addr += nxt * 4
                    elif pointer_format == 1:
                        auth = raw >> 63
                        bind = (raw >> 62) & 1
                        nxt = (raw >> 51) & 0x7FF
                        if auth or bind:
                            ordinal = raw & 0xFFFF
                            fixups[self.base + addr] = ('bind', imports[ordinal] if ordinal < len(imports) else '?')
                        else:
                            fixups[self.base + addr] = ('rebase', self.base + (raw & 0x7FFFFFFFFFF))
                        if nxt == 0:
                            break
                        addr += nxt * 8
                    elif pointer_format == 3:
                        # PTR_32 cache? skip
                        break
                    else:
                        break
        return fixups

    @staticmethod
    def _sym(blob, off):
        z = blob.find(b'\0', off)
        try:
            return blob[off:z].decode('utf8')
        except Exception:
            return '?'


def main():
    m = MachO('Goodnotes')
    fx = m.decode_fixups()
    print('fixups decoded:', len(fx))

    def dec(addr):
        e = fx.get(addr)
        if e and e[0] == 'rebase':
            return e[1]
        return None

    cl_addr, cl_sz = m.secs['__DATA_CONST,__objc_classlist']
    lines = []
    for i in range(cl_sz // 8):
        cls = dec(cl_addr + i * 8)
        if not cls:
            continue
        data = dec(cls + 32)
        if not data:
            continue
        ro = data & 0x00007FFFFFFFFFF8
        namePtr = dec(ro + 24)
        baseMethods = dec(ro + 32)
        cname = m.cstr(namePtr) if namePtr else None
        if not cname:
            continue
        methods = []
        if baseMethods:
            b = m.read(baseMethods, 8)
            if b:
                eaf, count = struct.unpack('<II', b[:8])
                relative = bool(eaf & 0x80000000)
                entsize = (eaf & 0xFFFC) or 12
                for k in range(count):
                    p = baseMethods + 8 + k * entsize
                    if relative:
                        nb = m.read(p, 12)
                        if not nb:
                            break
                        noff = struct.unpack('<i', nb[0:4])[0]
                        nm = m.cstr(p + noff)
                        methods.append(nm or '?')
                    else:
                        sel = dec(p)
                        nm = m.cstr(sel) if sel else None
                        ent = fx.get(sel) if sel else None
                        if nm:
                            methods.append(nm)
                        elif ent and ent[0] == 'bind':
                            methods.append(ent[1])
                        else:
                            methods.append('?')
        lines.append(f"{cname}\t{' '.join(methods)}")
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, 'objc_classes.txt'), 'w') as fh:
        fh.write('\n'.join(lines))
    print('written', len(lines))


if __name__ == '__main__':
    main()
