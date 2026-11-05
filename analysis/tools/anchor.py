#!/usr/bin/env python3
"""Find arm64 code that references a cstring, resolve the enclosing function start,
and emit offsets that scripts/gnstatic.py can patch offline.

Why this chains into gnstatic.py: with a Distribution certificate the only place
you may change app code is in the Mach-O, before it is signed. This tool finds
the address, gnstatic.py applies the bytes - and refuses if the bytes it finds
there are not the ones you expected.

usage:
    # 1. survey: where is this string referenced, and which function owns it
    python3 analysis/tools/anchor.py Goodnotes --string missing_active_pro_entitlement

    # 2. turn one hit into a ready-to-use patch file
    python3 analysis/tools/anchor.py Goodnotes \\
            --string missing_active_pro_entitlement --hit 0 \\
            --bytes 20008052c0035fd6 --json patches.json

    # 3. apply it
    python3 scripts/gnstatic.py patch in.ipa -o out.ipa --patches patches.json

Offsets are printed relative to the __TEXT base (0x100000000 in the file, 0 in
gnstatic.py), which is the same number the runtime anchor log prints as
"(static 0x...)".
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gnobjc import MachO  # noqa: E402

try:
    import numpy as np
except ImportError:  # numpy is optional; the scan is just slower without it
    np = None

# Instructions we care about
ADRP_MASK = 0x9F000000
ADRP_VALUE = 0x90000000
ADD_IMM_MASK = 0xFF800000
ADD_IMM_VALUE = 0x91000000


def find_cstrings(image: MachO, needle: str) -> list[int]:
    """Every vmaddr of an exact, NUL terminated occurrence of `needle`."""
    section = image.secs.get("__TEXT,__cstring")
    if not section:
        return []
    addr, size = section
    data = image.read(addr, size)
    if not data:
        return []

    wanted = needle.encode() + b"\0"
    found = []
    start = 0
    while True:
        index = data.find(wanted, start)
        if index < 0:
            break
        if index == 0 or data[index - 1] == 0:
            found.append(addr + index)
        start = index + 1
    return found


def decode_adrp(word: int, pc: int) -> int | None:
    if (word & ADRP_MASK) != ADRP_VALUE:
        return None
    immediate = ((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 0x3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    return ((pc & ~0xFFF) + (immediate << 12)) & 0xFFFFFFFFFFFFFFFF


def find_references(image: MachO, targets: set[int], window: int = 4) -> list[tuple[int, int]]:
    """(instruction index, referenced address) for ADRP+ADD pairs pointing at a target."""
    section = image.secs.get("__TEXT,__text")
    if not section:
        return []
    text_addr, text_size = section
    raw = image.read(text_addr, text_size)
    if not raw:
        return []

    hits = []
    if np is not None:
        words = np.frombuffer(raw, dtype="<u4")
        candidates = np.nonzero((words & np.uint32(ADRP_MASK)) == np.uint32(ADRP_VALUE))[0]
        indices = [int(i) for i in candidates]
    else:
        count = len(raw) // 4
        words = struct.unpack_from("<%dI" % count, raw, 0)
        indices = [i for i in range(count) if (words[i] & ADRP_MASK) == ADRP_VALUE]

    total = len(raw) // 4
    for index in indices:
        pc = text_addr + index * 4
        page = decode_adrp(int(words[index]), pc)
        if page is None:
            continue
        rd = int(words[index]) & 0x1F

        for step in range(1, window + 1):
            probe = index + step
            if probe >= total:
                break
            word = int(words[probe])
            if (word & ADD_IMM_MASK) != ADD_IMM_VALUE:
                continue
            if ((word >> 5) & 0x1F) != rd:
                continue
            immediate = (word >> 10) & 0xFFF
            if (word >> 22) & 1:
                immediate <<= 12
            if (page + immediate) in targets:
                hits.append((index, page + immediate))
                break

    return hits


def function_start(words, index: int, text_addr: int) -> int:
    """Walk back to the instruction after the previous terminator / padding."""
    limit = max(0, index - 1500)
    cursor = index
    while cursor > limit:
        previous = int(words[cursor - 1])
        if previous == 0xD65F03C0:                       # ret
            return cursor
        if (previous & 0xFFE0001F) == 0xD65F0000:        # retaa / retab
            return cursor
        if previous == 0xD4200000:                       # brk
            return cursor
        if previous == 0xD503201F:                       # nop padding
            return cursor
        cursor -= 1
    return index


def main(argv) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", help="the decrypted app executable")
    parser.add_argument("--string", action="append", required=True,
                        help="cstring to anchor on (repeatable)")
    parser.add_argument("--hit", type=int, default=None,
                        help="with --bytes: which hit to emit as a patch (default: all)")
    parser.add_argument("--bytes", help="replacement bytes, e.g. 20008052c0035fd6")
    parser.add_argument("--json", help="write a gnstatic.py patch file here (default: stdout)")
    parser.add_argument("--max", type=int, default=40, help="stop after N hits per string")
    parser.add_argument("--image-name",
                        help="CFBundleExecutable value to put in the patch file "
                             "(default: the binary's file name)")
    args = parser.parse_args(argv)

    image = MachO(args.binary)
    base = image.base

    section = image.secs.get("__TEXT,__text")
    if not section:
        print("error: no __TEXT,__text section", file=sys.stderr)
        return 1
    text_addr, text_size = section
    raw = image.read(text_addr, text_size)
    count = len(raw) // 4
    words = np.frombuffer(raw, dtype="<u4") if np is not None else struct.unpack_from("<%dI" % count, raw, 0)

    report = {"binary": os.path.basename(args.binary), "base": hex(base), "anchors": []}
    patches = []

    print(f"image  : {os.path.basename(args.binary)}")
    print(f"base   : 0x{base:x}")
    print(f"__text : 0x{text_addr:x} ({text_size:,} bytes, {count:,} instructions)")
    print(f"scanner: {'numpy' if np is not None else 'pure python (slower)'}")
    print()

    for needle in args.string:
        addresses = find_cstrings(image, needle)
        print(f'"{needle}"  cstrings={[hex(a) for a in addresses] or "none"}')
        if not addresses:
            continue

        hits = find_references(image, set(addresses))
        if not hits:
            print("   no ADRP+ADD reference found")
            continue

        for order, (index, address) in enumerate(hits[: args.max]):
            start = function_start(words, index, text_addr)
            start_addr = text_addr + start * 4
            existing = image.read(start_addr, 4) or b"\0" * 4
            relative = start_addr - base

            print(f"   hit {order:<3} ref=0x{index * 4:x}  func static=0x{relative:x}"
                  f"  first bytes={existing.hex(' ')}")

            report["anchors"].append({
                "string": needle, "hit": order,
                "reference_offset": index * 4,
                "function_offset": relative,
                "first_bytes": existing.hex(" "),
            })

            if args.bytes and (args.hit is None or args.hit == order):
                patches.append({
                    "name": f"{needle}-hit{order}",
                    "image": args.image_name or os.path.basename(args.binary),
                    "offset": hex(relative),
                    "expect": existing.hex(" "),
                    "bytes": args.bytes,
                })
        print()

    if args.bytes and not patches:
        print("error: --bytes given but no hit matched", file=sys.stderr)
        return 1

    payload = {"patches": patches} if patches else report
    text = json.dumps(payload, indent=2)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        print(f"wrote {args.json} ({len(patches)} patch(es))" if patches else f"wrote {args.json}")
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
