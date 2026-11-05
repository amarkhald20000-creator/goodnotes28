#!/usr/bin/env python3
"""Apply byte patches and remove foreign dylibs inside an IPA, offline.

Why this exists
---------------
A Distribution signed app cannot be patched in memory: the page you write to
loses its code signature and the first instruction fetched from it kills the
process (CODESIGNING / Invalid Page). But the same edit applied to the Mach-O
*before* it is signed is perfectly legal - the new signature covers the new
bytes. So the only way to change app code with a Distribution certificate is
this file.

Everything here is pure python, no dependencies, and every patch is verified
against the bytes it expects to find. If the IPA is not the build you patched
for, it refuses instead of writing garbage into a 260 MB binary.

usage:
    gnstatic.py info   app.ipa
    gnstatic.py strip  app.ipa -o clean.ipa
    gnstatic.py patch  app.ipa -o patched.ipa --patches patches.json

patches.json:
    {
      "patches": [
        {
          "name": "pro-entitlement-getter",
          "image": "Goodnotes",
          "vmaddr": "0x1002331b60",       # or "offset": "0x2331b60" (text relative)
          "expect": "fd 7b bf a9",        # refuse if the bytes differ
          "bytes": "20 00 80 52 c0 03 5f d6"   # mov w0, #1 ; ret
        }
      ]
    }
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import sys
import tempfile
import zipfile

# --------------------------------------------------------------------------- #
# Mach-O basics
# --------------------------------------------------------------------------- #

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC = 0xFEEDFACE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

MH_EXECUTE = 0x2

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_ENCRYPTION_INFO_64 = 0x2C

DYLIB_COMMANDS = {
    LC_LOAD_DYLIB: "load",
    LC_LOAD_WEAK_DYLIB: "weak",
    LC_REEXPORT_DYLIB: "reexport",
    LC_LOAD_UPWARD_DYLIB: "upward",
}

DEFAULT_FOREIGN = ("substrate", "LoadControl", "Substrate", "cycript", "frida")


class MachOError(Exception):
    pass


class MachO:
    """Just enough Mach-O to move between vmaddr, file offset and load commands."""

    def __init__(self, data: bytes, name: str = "?"):
        self.data = bytearray(data)
        self.name = name
        if len(data) < 32:
            raise MachOError(f"{name}: too small to be a Mach-O")

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in (FAT_MAGIC, FAT_MAGIC_64):
            raise MachOError(f"{name}: universal binary - run lipo first")
        if magic == MH_CIGAM_64 or magic == MH_MAGIC:
            raise MachOError(f"{name}: not a 64-bit little-endian Mach-O")
        if magic != MH_MAGIC_64:
            raise MachOError(f"{name}: unexpected magic 0x{magic:08x}")

        self.cputype = struct.unpack_from("<I", data, 4)[0]
        self.filetype = struct.unpack_from("<I", data, 12)[0]
        self.ncmds, self.sizeofcmds = struct.unpack_from("<II", data, 16)

        self.segments = []      # dicts
        self.dylibs = []        # dicts: {'cmd','kind','name','offset','size'}
        self.encryption = None
        self._parse_load_commands()

    # -- load commands ----------------------------------------------------- #

    def _parse_load_commands(self) -> None:
        offset = 32
        for index in range(self.ncmds):
            if offset + 8 > len(self.data):
                raise MachOError(f"{self.name}: truncated load command {index}")
            cmd, size = struct.unpack_from("<II", self.data, offset)
            if size < 8 or offset + size > len(self.data):
                raise MachOError(f"{self.name}: bad cmdsize {size} at {offset}")

            if cmd == LC_SEGMENT_64:
                name = self.data[offset + 8:offset + 24].split(b"\0")[0].decode("ascii", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.data, offset + 24)
                self.segments.append({
                    "name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                    "fileoff": fileoff, "filesize": filesize,
                    "command_offset": offset, "command_size": size,
                })
            elif cmd in DYLIB_COMMANDS:
                name_offset = struct.unpack_from("<I", self.data, offset + 8)[0]
                start = offset + name_offset
                end = self.data.find(b"\0", start, offset + size)
                if end < 0:
                    end = offset + size
                self.dylibs.append({
                    "cmd": cmd,
                    "kind": DYLIB_COMMANDS[cmd],
                    "name": self.data[start:end].decode("utf-8", "replace"),
                    "command_offset": offset,
                    "command_size": size,
                })
            elif cmd == LC_ENCRYPTION_INFO_64:
                cryptoff, cryptsize, cryptid = struct.unpack_from("<III", self.data, offset + 8)
                self.encryption = {"cryptoff": cryptoff, "cryptsize": cryptsize, "cryptid": cryptid}

            offset += size

    # -- addressing -------------------------------------------------------- #

    @property
    def text_segment(self) -> dict:
        for segment in self.segments:
            if segment["name"] == "__TEXT":
                return segment
        raise MachOError(f"{self.name}: no __TEXT segment")

    @property
    def base(self) -> int:
        return self.text_segment["vmaddr"]

    def section(self, segname: str, sectname: str):
        """Returns (vmaddr, size) of a section, or None."""
        for segment in self.segments:
            if segment["name"] != segname:
                continue
            offset = segment["command_offset"] + 72
            nsects = struct.unpack_from("<I", self.data, segment["command_offset"] + 64)[0]
            for index in range(nsects):
                entry = offset + index * 80
                name = self.data[entry:entry + 16].split(b"\0")[0].decode("ascii", "replace")
                if name != sectname:
                    continue
                addr, size = struct.unpack_from("<QQ", self.data, entry + 32)
                return addr, size
        return None

    def vmaddr_to_offset(self, vmaddr: int) -> int:
        for segment in self.segments:
            start = segment["vmaddr"]
            if start <= vmaddr < start + segment["filesize"]:
                return segment["fileoff"] + (vmaddr - start)
        raise MachOError(f"{self.name}: 0x{vmaddr:x} is not inside any file-backed segment")

    # -- inspection -------------------------------------------------------- #

    def describe(self) -> str:
        arch = f"cputype 0x{self.cputype:x}"
        if self.cputype == 0x0100000C:
            arch = "arm64"
        elif self.cputype == 0x0200000C:
            arch = "arm64e"
        elif self.cputype == 0x01000007:
            arch = "x86_64"

        lines = [f"image      : {self.name}",
                 f"arch       : {arch}",
                 f"filetype   : {'MH_EXECUTE' if self.filetype == MH_EXECUTE else hex(self.filetype)}",
                 f"base       : 0x{self.base:x}",
                 f"size       : {len(self.data):,} bytes",
                 f"load cmds  : {self.ncmds} ({self.sizeofcmds} bytes)"]

        if self.encryption:
            state = "decrypted" if self.encryption["cryptid"] == 0 else "ENCRYPTED (cryptid=%d)" % self.encryption["cryptid"]
            lines.append(f"crypt      : {state}")

        text = self.section("__TEXT", "__text")
        if text:
            lines.append(f"__text     : vmaddr 0x{text[0]:x}  size {text[1]:,}")

        if self.dylibs:
            lines.append("dylibs     :")
            for entry in self.dylibs:
                lines.append(f"  [{entry['kind']:8}] {entry['name']}")
        else:
            lines.append("dylibs     : none")

        return "\n".join(lines)

    # -- mutation ---------------------------------------------------------- #

    def apply_patch(self, vmaddr: int, payload: bytes, expect: bytes | None, force: bool) -> None:
        offset = self.vmaddr_to_offset(vmaddr)
        current = bytes(self.data[offset:offset + len(payload)])

        if expect is not None:
            actual = bytes(self.data[offset:offset + len(expect)])
            if actual != expect and not force:
                raise MachOError(
                    "byte check failed at 0x%x\n  expected %s\n  found    %s\n"
                    "(wrong build, or the offset is stale - not writing anything)"
                    % (vmaddr, expect.hex(" "), actual.hex(" ")))

        self.data[offset:offset + len(payload)] = payload

    def remove_dylibs(self, patterns) -> list[str]:
        removed = []
        keep = []
        for entry in self.dylibs:
            if any(pattern.lower() in entry["name"].lower() for pattern in patterns):
                removed.append(entry["name"])
                continue
            keep.append(entry)
        if not removed:
            return []

        # Compact the load command area: keep every other command, in order, and
        # zero the tail. Nothing after the header moves, so all file offsets stay
        # valid and __LINKEDIT is untouched.
        first = 32
        end = first + self.sizeofcmds
        area = bytearray()
        offset = first
        drop_offsets = {entry["command_offset"] for entry in self.dylibs
                        if any(p.lower() in entry["name"].lower() for p in patterns)}

        while offset < end:
            cmd, size = struct.unpack_from("<II", self.data, offset)
            if size < 8:
                break
            if offset not in drop_offsets:
                area += self.data[offset:offset + size]
            offset += size

        if len(area) > self.sizeofcmds:
            raise MachOError("internal error: load command area grew")

        self.data[first:end] = area + b"\0" * (self.sizeofcmds - len(area))
        struct.pack_into("<II", self.data, 16, self.ncmds - len(removed), len(area))
        self.dylibs = keep
        self.ncmds = len(keep)
        self.sizeofcmds = len(area)
        return removed


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def parse_number(value) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().replace("_", "")
        if text.lower().startswith("0x"):
            return int(text, 16)
        # a-f present means the caller meant hex; all digits means decimal
        if any(ch in "abcdefABCDEF" for ch in text):
            return int(text, 16)
        return int(text, 10)
    raise MachOError(f"not a number: {value!r}")


def parse_bytes(value, field: str) -> bytes:
    if isinstance(value, list):
        return bytes(parse_number(item) & 0xFF for item in value)
    if isinstance(value, str):
        cleaned = "".join(ch for ch in value if ch in "0123456789abcdefABCDEF")
        if len(cleaned) % 2:
            raise MachOError(f"{field}: odd number of hex digits")
        return bytes.fromhex(cleaned)
    raise MachOError(f"{field}: expected a hex string")


def find_app_bundle(root: str) -> str:
    payload = os.path.join(root, "Payload")
    if not os.path.isdir(payload):
        raise MachOError("IPA has no Payload/ directory")
    for entry in sorted(os.listdir(payload)):
        if entry.endswith(".app"):
            return os.path.join(payload, entry)
    raise MachOError("Payload/ has no .app bundle")


def executable_name(app_dir: str) -> str:
    import plistlib
    info_path = os.path.join(app_dir, "Info.plist")
    with open(info_path, "rb") as handle:
        info = plistlib.load(handle)
    name = info.get("CFBundleExecutable")
    if not name:
        raise MachOError("Info.plist has no CFBundleExecutable")
    return name


def extract_ipa(ipa_path: str, workdir: str) -> str:
    with zipfile.ZipFile(ipa_path) as archive:
        archive.extractall(workdir)
    return find_app_bundle(workdir)


def repack_ipa(root: str, output_path: str) -> None:
    if os.path.exists(output_path):
        os.remove(output_path)
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for base, _dirs, files in os.walk(root):
            for name in sorted(files):
                full = os.path.join(base, name)
                archive.write(full, os.path.relpath(full, root))


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_info(args) -> int:
    if args.target.endswith(".ipa"):
        with tempfile.TemporaryDirectory() as workdir:
            app = extract_ipa(args.target, workdir)
            name = executable_name(app)
            with open(os.path.join(app, name), "rb") as handle:
                image = MachO(handle.read(), name)
            print(image.describe())
            print()
            print("bundle     :", os.path.basename(app))
            frameworks = os.path.join(app, "Frameworks")
            if os.path.isdir(frameworks):
                print("frameworks :")
                for entry in sorted(os.listdir(frameworks)):
                    print("   ", entry)
    else:
        with open(args.target, "rb") as handle:
            image = MachO(handle.read(), os.path.basename(args.target))
        print(image.describe())
    return 0


def cmd_strip(args) -> int:
    patterns = args.name or list(DEFAULT_FOREIGN)

    with tempfile.TemporaryDirectory() as workdir:
        app = extract_ipa(args.ipa, workdir)
        app_name = executable_name(app)
        binary_path = os.path.join(app, app_name)

        with open(binary_path, "rb") as handle:
            image = MachO(handle.read(), app_name)

        removed = image.remove_dylibs(patterns)
        if removed:
            with open(binary_path, "wb") as handle:
                handle.write(image.data)
            print(f"removed {len(removed)} load command(s) from {app_name}:")
            for name in removed:
                print("   -", name)
        else:
            print("no matching load commands - binary left untouched")

        # Delete the dylibs themselves; a load command is gone, the file would
        # only be dead weight inside the bundle.
        deleted = 0
        for base, _dirs, files in os.walk(app):
            for name in files:
                if not name.endswith((".dylib", ".framework")):
                    continue
                if any(pattern.lower() in name.lower() for pattern in patterns):
                    path = os.path.join(base, name)
                    os.remove(path)
                    deleted += 1
                    print("   deleted", os.path.relpath(path, app))

        repack_ipa(workdir, args.output)
        print(f"\nwrote {args.output} ({os.path.getsize(args.output):,} bytes)")
        print("removed load commands, deleted files:", deleted)
        print("the old signature is now invalid - re-sign the IPA (LC Sign) before installing")
    return 0


def cmd_patch(args) -> int:
    with open(args.patches, "r", encoding="utf-8") as handle:
        spec = json.load(handle)

    entries = spec.get("patches", [])
    if not isinstance(entries, list) or not entries:
        print("error: patches file has no 'patches' array", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as workdir:
        app = extract_ipa(args.ipa, workdir)
        app_name = executable_name(app)

        by_image: dict[str, list] = {}
        for entry in entries:
            image = entry.get("image") or app_name
            by_image.setdefault(image, []).append(entry)

        applied = 0
        for image_name, image_entries in by_image.items():
            if image_name == app_name:
                binary_path = os.path.join(app, app_name)
            else:
                binary_path = os.path.join(app, "Frameworks", image_name)
            if not os.path.exists(binary_path):
                print(f"error: image {image_name} not found in the bundle", file=sys.stderr)
                return 1

            with open(binary_path, "rb") as handle:
                image = MachO(handle.read(), image_name)

            if image.encryption and image.encryption["cryptid"] != 0:
                print(f"error: {image_name} is still encrypted (cryptid="
                      f"{image.encryption['cryptid']}); decrypt it first", file=sys.stderr)
                return 1

            for entry in image_entries:
                name = entry.get("name", "(unnamed)")
                if "vmaddr" in entry:
                    vmaddr = parse_number(entry["vmaddr"])
                elif "offset" in entry:
                    vmaddr = image.base + parse_number(entry["offset"])
                else:
                    print(f"error: {name}: needs 'vmaddr' or 'offset'", file=sys.stderr)
                    return 1

                payload = parse_bytes(entry["bytes"], "bytes")
                expect = parse_bytes(entry["expect"], "expect") if "expect" in entry else None

                # A whole-function replacement is almost always "mov w0,#1; ret".
                image.apply_patch(vmaddr, payload, expect, args.force)
                print(f"patched  {name}")
                print(f"         {image_name} 0x{vmaddr:x} ({len(payload)} bytes)")
                applied += 1

            with open(binary_path, "wb") as handle:
                handle.write(image.data)

        repack_ipa(workdir, args.output)

    print(f"\nwrote {args.output} ({os.path.getsize(args.output):,} bytes)")
    print(f"{applied} patch(es) applied")
    print("re-sign the IPA (LC Sign) before installing - the old signature no longer matches")
    return 0


# --------------------------------------------------------------------------- #
# Self test: builds a tiny Mach-O and runs the real code paths against it
# --------------------------------------------------------------------------- #

def _build_test_macho() -> bytes:
    text_vmaddr = 0x100000000
    text_fileoff = 0x8000
    text_size = 0x200

    def segment(name: str, vmaddr: int, vmsize: int, fileoff: int, filesize: int, sects) -> bytes:
        cmd = bytearray()
        cmd += struct.pack("<II", LC_SEGMENT_64, 72 + 80 * len(sects))
        cmd += name.encode().ljust(16, b"\0")
        cmd += struct.pack("<QQQQ", vmaddr, vmsize, fileoff, filesize)
        cmd += struct.pack("<IIII", 5, 5, len(sects), 0)
        for sect_name, sect_addr, sect_off, sect_size in sects:
            cmd += sect_name.encode().ljust(16, b"\0")
            cmd += "FAKE".encode().ljust(16, b"\0")
            cmd += struct.pack("<QQIIIIIIII", sect_addr, sect_size, sect_off, 4, 0, 0, 0, 0, 0, 0)
        return bytes(cmd)

    def dylib(path: str) -> bytes:
        raw = path.encode() + b"\0"
        size = 24 + len(raw)
        size = (size + 7) & ~7
        cmd = struct.pack("<IIIIII", LC_LOAD_DYLIB, size, 24, 2, 0x10000, 0x10000)
        return cmd + raw.ljust(size - 24, b"\0")

    commands = b""
    commands += segment("__TEXT", text_vmaddr, text_size + text_fileoff, 0, text_size + text_fileoff,
                        [("__text", text_vmaddr + text_fileoff, text_fileoff, text_size)])
    commands += dylib("@executable_path/Frameworks/libsubstrate.dylib")
    commands += dylib("@executable_path/Frameworks/LoadControl.dylib")
    commands += dylib("@executable_path/Frameworks/GNUnlock.dylib")

    # 1 segment command + 3 dylib commands
    header = struct.pack("<IIIIIIII", MH_MAGIC_64, 0x0100000C, 0, MH_EXECUTE,
                         4, len(commands), 0, 0)
    blob = bytearray(header + commands)
    blob += b"\0" * (text_fileoff - len(blob))
    # A recognisable "function" at the start of __text: 4 nops.
    blob += b"\x1f\x20\x03\xd5" * 8
    blob += b"\0" * (text_size + text_fileoff - len(blob))
    return bytes(blob)


def cmd_selftest(_args) -> int:
    blob = _build_test_macho()
    image = MachO(blob, "test")
    failures = []

    if image.base != 0x100000000:
        failures.append("base")
    if len(image.dylibs) != 3:
        failures.append("dylib count")

    # patch: rewrite the first instruction with a known pattern
    vmaddr = image.base + 0x8000
    pattern = bytes.fromhex("20008052c0035fd6")
    image.apply_patch(vmaddr, pattern, bytes.fromhex("1f2003d5"), force=False)
    if bytes(image.data[0x8000:0x8008]) != pattern:
        failures.append("patch write")

    # patch with a wrong expectation must refuse
    try:
        image.apply_patch(vmaddr, pattern, bytes.fromhex("ffffffff"), force=False)
        failures.append("byte check did not refuse")
    except MachOError:
        pass

    # strip: the two foreign dylibs go, ours stays
    removed = image.remove_dylibs(["substrate", "LoadControl"])
    if len(removed) != 2:
        failures.append(f"strip removed {len(removed)}")
    if [d["name"] for d in image.dylibs] != ["@executable_path/Frameworks/GNUnlock.dylib"]:
        failures.append("strip kept the wrong dylibs")

    reparsed = MachO(bytes(image.data), "test")
    if reparsed.ncmds != 2:
        failures.append("header ncmds not updated")
    if len(reparsed.data) != len(blob):
        failures.append("file size changed")

    if failures:
        print("SELFTEST FAIL:", ", ".join(failures), file=sys.stderr)
        return 1

    print("selftest ok: patch verification, strip, header rewrite")
    return 0


# --------------------------------------------------------------------------- #

def main(argv) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="describe the app binary in an IPA")
    info.add_argument("target")
    info.set_defaults(func=cmd_info)

    strip = sub.add_parser("strip", help="remove foreign dylib load commands + files")
    strip.add_argument("ipa")
    strip.add_argument("-o", "--output", required=True)
    strip.add_argument("--name", action="append", help="substring to match (repeatable)")
    strip.set_defaults(func=cmd_strip)

    patch = sub.add_parser("patch", help="apply byte patches to the app binary")
    patch.add_argument("ipa")
    patch.add_argument("-o", "--output", required=True)
    patch.add_argument("--patches", required=True)
    patch.add_argument("--force", action="store_true", help="write even if 'expect' does not match")
    patch.set_defaults(func=cmd_patch)

    selftest = sub.add_parser("selftest", help="run the built-in checks")
    selftest.set_defaults(func=cmd_selftest)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except MachOError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
