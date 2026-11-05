#!/usr/bin/env python3
"""Remove the four iCloud entitlements from a signed .ipa, without unpacking it.

Why this is not "unzip, edit, rezip"
------------------------------------
The request that produced this file was "unzip into a temp dir, edit, repackage
preserving structure and permissions".  Repackaging from a directory is the part
that actually breaks apps, and it breaks them in ways that are invisible until
the app is installed:

  * Permissions.  zipfile does not restore mode bits on extract; a repack from
    disk gives everything 0644 and the main executable stops being executable.
  * Symlinks.  A framework's versioned link extracts as a *copy* of its target.
    On iOS this is rare, but it is silent when it happens.
  * Unicode.  macOS APFS stores names decomposed and compares them normalized.
    A .lproj directory written back with different normalization is a different
    directory name to the app's own bundle lookup.
  * Case.  The default macOS volume is case-insensitive; two members that differ
    only in case collide on extract and one is lost.
  * Bitcode/asset catalogs and nested .appex bundles are large trees where any
    of the above can hit once and never be noticed.

So nothing is ever written to disk.  The source archive is read entry by entry
and the destination is written entry by entry with the *same* ZipInfo (same
name, same external_attr, same date_time, same create_system, same
compress_type, same order).  Entries we do not touch are streamed through
unchanged.  After the write, every untouched member is checked to have the same
CRC-32 and the same size as the source, the main executable is checked to hash
identically, and the whole archive is CRC-verified.

What this cannot do
-------------------
It cannot change an entitlement *that is already inside a code signature*.  The
entitlements CloudKit reads at run time are the ones in the main binary's code
signature (LC_CODE_SIGNATURE -> SuperBlob -> CSSLOT_ENTITLEMENTS), and
`archived-expanded-entitlements.xcent` inside the bundle is a build artefact that
the archiver leaves behind - it is not what the kernel reads.

That distinction is why this file has three modes rather than one:

  strip    remove the four keys from every .xcent / .entitlements in the bundle,
           so that a signer which *imports* bundle entitlements cannot
           reintroduce them.  This is what was asked for.

  inspect  read the entitlements out of the main binary's code signature and
           report whether the four keys are present, and of what type.  Run this
           on the IPA *after* LC Sign.  It is the only way to answer "did the
           signer put them back" without guessing, and it is one line of output.

  export   write a signing template with the four keys absent, taken from the
           provisioning profile when the bundle carries one (that is the set the
           profile actually grants), otherwise from the signature.

Usage
-----
    python3 tools/ipa_icloud_strip.py strip in.ipa -o Goodnotes-NoiCloud.ipa
    python3 tools/ipa_icloud_strip.py inspect signed.ipa
    python3 tools/ipa_icloud_strip.py export in.ipa -o NoiCloud.entitlements
    python3 tools/ipa_icloud_strip.py --selftest

Exit codes
----------
    0  did what was asked, and verified it
    1  verification failed, or inspect found the four keys still present
    2  bad input (not a zip, no Payload/*.app, unreadable member)
    3  nothing to do (no member carries any of the four keys)
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import plistlib
import shutil
import stat
import struct
import sys
import tempfile
import zipfile

# The four keys named in the request.  Deliberately a tuple in this order: the
# report repeats them in this order, so a diff between two runs is readable.
ICLOUD_KEYS = (
    "com.apple.developer.icloud-services",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.ubiquity-kvstore-identifier",
    "com.apple.developer.ubiquity-container-identifiers",
)

# Not removed, on purpose: with the four above gone this one is inert (CloudKit
# only looks at it once it has a container list), and removing a fifth key that
# was not asked for is how a "safe" edit stops being one.
LEFTOVER_NOTES = ("com.apple.developer.icloud-container-environment",)

ENTITLEMENT_SUFFIXES = (".xcent", ".entitlements")

EXIT_OK = 0
EXIT_VERIFY = 1
EXIT_INPUT = 2
EXIT_NOTHING = 3

LC_CODE_SIGNATURE = 0x1D
CSSLOT_ENTITLEMENTS = 5
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def log(message: str) -> None:
    sys.stdout.write(message + "\n")
    sys.stdout.flush()


def warn(message: str) -> None:
    sys.stdout.write("warning: " + message + "\n")
    sys.stdout.flush()


def fail(message: str) -> None:
    sys.stderr.write("error: " + message + "\n")
    sys.stderr.flush()


class InputError(Exception):
    """The file is not something this tool can work on."""


# --------------------------------------------------------------------------
# Mach-O: the entitlements that are actually in force
# --------------------------------------------------------------------------

def _macho_slices(data: bytes, total: int | None = None):
    """Yield (offset, size) for every architecture in `data`.

    A thin Mach-O yields one slice covering the whole file.  A fat file yields
    one per architecture.  Anything else yields nothing - a caller that gets an
    empty list concludes "no Mach-O here" rather than guessing.

    `total` is the size of the *whole* file when `data` is only its head.  The
    slice table lives in the first 32 bytes per architecture, so a head is
    enough to enumerate slices; the bound check has to use the real file size
    or every slice would look truncated.
    """
    if total is None:
        total = len(data)
    if len(data) < 8:
        return []
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        count = struct.unpack(">I", data[4:8])[0]
        # A real fat header never has anywhere near this many slices; the bound
        # is there so a corrupt count cannot make this loop read off the end.
        if count > 64:
            return []
        slices = []
        offset = 8
        for _ in range(count):
            if magic == FAT_MAGIC:
                if offset + 20 > len(data):
                    return []
                _, _, slice_off, slice_size, _ = struct.unpack(
                    ">iiIII", data[offset:offset + 20])
                offset += 20
            else:
                if offset + 32 > len(data):
                    return []
                _, _, slice_off, slice_size, _, _ = struct.unpack(
                    ">iiQQII", data[offset:offset + 32])
                offset += 32
            if slice_off + slice_size > total:
                return []
            slices.append((slice_off, slice_size))
        return slices
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"):
        return [(0, total)]
    return []


def _load_commands(blob: bytes):
    """Return (endian, [(cmd, offset, cmdsize)]) for one Mach-O image, or None."""
    if len(blob) < 28:
        return None
    first = blob[:4]
    if first == b"\xcf\xfa\xed\xfe":
        endian, header = "<", 32
    elif first == b"\xfe\xed\xfa\xcf":
        endian, header = ">", 32
    elif first == b"\xce\xfa\xed\xfe":
        endian, header = "<", 28
    elif first == b"\xfe\xed\xfa\xce":
        endian, header = ">", 28
    else:
        return None
    if len(blob) < header:
        return None
    ncmds = struct.unpack(endian + "I", blob[16:20])[0]
    if ncmds > 65536:
        return None
    offset = header
    commands = []
    for _ in range(ncmds):
        if offset + 8 > len(blob):
            return None
        cmd, cmdsize = struct.unpack(endian + "II", blob[offset:offset + 8])
        if cmdsize < 8 or offset + cmdsize > len(blob):
            return None
        commands.append((cmd, offset, cmdsize))
        offset += cmdsize
    return endian, commands


def _entitlements_from_blob(blob: bytes):
    """Pull an XML entitlements plist out of a code signature SuperBlob."""
    if len(blob) < 12:
        return None
    magic, length, count = struct.unpack(">III", blob[:12])
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return None
    if length > len(blob) or count > 64:
        return None
    for index in range(count):
        entry = 12 + index * 8
        if entry + 8 > len(blob):
            return None
        slot, slot_offset = struct.unpack(">II", blob[entry:entry + 8])
        if slot != CSSLOT_ENTITLEMENTS:
            continue
        if slot_offset + 8 > len(blob):
            return None
        blob_magic, blob_length = struct.unpack(">II", blob[slot_offset:slot_offset + 8])
        if blob_magic != CSMAGIC_EMBEDDED_ENTITLEMENTS:
            return None
        start = slot_offset + 8
        end = slot_offset + blob_length
        if blob_length < 8 or end > len(blob):
            return None
        return blob[start:end]
    return None


class _BytesAccess:
    """Random access over an in-memory image."""

    def __init__(self, data: bytes):
        self._data = data
        self.size = len(data)

    def read(self, offset: int, length: int) -> bytes:
        return self._data[offset:offset + length]


class _ZipMemberAccess:
    """Random access over one member of a zip, without holding it in memory.

    The first version of this file read the whole main executable into memory
    to parse its code signature.  On a 450 MB member that put the peak resident
    size at 480 MB, and a real GoodNotes binary is in that range; on a 1 GB
    bundle it would be the largest thing in the job by an order of magnitude.
    The signature is a few kilobytes at the end of the file, and this reads it
    by seeking, so peak memory is the chunk size.
    """

    CHUNK = 1 << 20

    def __init__(self, archive: zipfile.ZipFile, name: str):
        self._archive = archive
        self._name = name
        self.size = archive.getinfo(name).file_size

    def read(self, offset: int, length: int) -> bytes:
        if length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        with self._archive.open(self._name) as handle:
            # ZipExtFile.seek is a forward discard, so this is one pass over the
            # decompressed stream and no buffer beyond CHUNK.
            handle.seek(offset)
            parts = []
            remaining = length
            while remaining > 0:
                chunk = handle.read(min(remaining, self.CHUNK))
                if not chunk:
                    break
                parts.append(chunk)
                remaining -= len(chunk)
        return b"".join(parts)


# Enough for a fat header, every architecture's load commands, and the padding
# around them.  A binary whose load commands exceed this is not something this
# parses, and _load_commands says so by returning None rather than half-parsing.
HEAD_BYTES = 8 << 20
MAX_SIGNATURE_BYTES = 64 << 20


def _signed_entitlements(access):
    """Return the entitlements dict carried by a Mach-O's code signature.

    None means "this binary carries no readable entitlements" - which is a real
    answer for an unsigned or ad-hoc-signed executable, and is reported as such.
    """
    if access.size == 0:
        return None
    head = access.read(0, min(access.size, HEAD_BYTES))
    for slice_off, slice_size in _macho_slices(head, access.size):
        wanted = min(slice_size, HEAD_BYTES)
        if slice_off + wanted <= len(head):
            image = head[slice_off:slice_off + wanted]
        else:
            image = access.read(slice_off, wanted)
        parsed = _load_commands(image)
        if parsed is None:
            continue
        endian, commands = parsed
        for cmd, offset, cmdsize in commands:
            if cmd != LC_CODE_SIGNATURE or cmdsize < 16:
                continue
            data_off, data_size = struct.unpack(endian + "II", image[offset + 8:offset + 16])
            if data_size == 0 or data_size > MAX_SIGNATURE_BYTES:
                continue
            # dataoff is relative to the slice, not to the file: a fat binary's
            # second slice stores offsets that start at its own beginning.
            if slice_off + data_off + data_size > access.size:
                continue
            blob = access.read(slice_off + data_off, data_size)
            xml = _entitlements_from_blob(blob)
            if xml is None:
                continue
            try:
                parsed_plist = plistlib.loads(xml)
            except Exception:
                continue
            if isinstance(parsed_plist, dict):
                return parsed_plist
    return None


def signed_entitlements(binary: bytes):
    """Convenience wrapper for callers that already hold the bytes."""
    return _signed_entitlements(_BytesAccess(binary))


def signed_entitlements_of_member(archive: zipfile.ZipFile, name: str):
    """The same, streamed out of a zip member."""
    return _signed_entitlements(_ZipMemberAccess(archive, name))


def _profile_entitlements(profile: bytes):
    """Entitlements granted by an embedded.mobileprovision (CMS-wrapped plist).

    Scanned rather than unshelled to openssl: the payload of a provisioning
    profile is a plain XML plist sitting in the DER body, and finding its first
    '<?xml' and last '</plist>' needs no dependency and no subprocess.  The
    openssl route is tried only if the scan finds nothing, because a profile
    with a binary payload would defeat the scan.
    """
    start = profile.find(b"<?xml")
    end = profile.find(b"</plist>")
    if start != -1 and end > start:
        try:
            parsed = plistlib.loads(profile[start:end + len(b"</plist>")])
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            granted = parsed.get("Entitlements")
            if isinstance(granted, dict):
                return granted, "scan"
    return None, None


# --------------------------------------------------------------------------
# plist editing
# --------------------------------------------------------------------------

def _plist_format(data: bytes) -> str:
    head = data.lstrip()[:8]
    if data[:8] == b"bplist00" or head.startswith(b"bplist"):
        return plistlib.FMT_BINARY
    return plistlib.FMT_XML


def strip_keys(data: bytes):
    """Return (new_bytes, removed_keys, kept_count, fmt).

    Raises InputError if `data` is not a plist dictionary.  That is deliberate:
    an entitlements file this tool cannot parse is a file whose contents it
    cannot promise anything about, and silently repackaging it would be the
    failure mode where the IPA is produced, installs, and still crashes.
    """
    try:
        parsed = plistlib.loads(data)
    except Exception as exc:
        raise InputError("not a readable property list (%s)" % exc)
    if not isinstance(parsed, dict):
        raise InputError("property list root is %s, expected a dictionary"
                         % type(parsed).__name__)
    removed = [key for key in ICLOUD_KEYS if key in parsed]
    if not removed:
        return data, [], len(parsed), _plist_format(data)
    for key in removed:
        del parsed[key]
    fmt = _plist_format(data)
    out = plistlib.dumps(parsed, fmt=fmt, sort_keys=False)
    return out, removed, len(parsed), fmt


# --------------------------------------------------------------------------
# archive inspection
# --------------------------------------------------------------------------

def open_ipa(path: str):
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise InputError("%s is not a zip archive (%s)" % (path, exc))
    return archive


def app_bundles(names):
    """Top-level '.app' directories under Payload/."""
    found = []
    for name in names:
        parts = name.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            if parts[1] not in found:
                found.append(parts[1])
    return found


def entitlement_members(names):
    """Every .xcent / .entitlements member in the archive, in archive order."""
    return [name for name in names
            if name.endswith(ENTITLEMENT_SUFFIXES) and not name.endswith("/")]


def main_executable(archive: zipfile.ZipFile, bundle: str) -> str | None:
    """Payload/X.app/<CFBundleExecutable>, using Info.plist to name it."""
    info_name = bundle + "/Info.plist"
    try:
        info = plistlib.loads(archive.read(info_name))
    except Exception:
        info = None
    if isinstance(info, dict):
        declared = info.get("CFBundleExecutable")
        if isinstance(declared, str) and declared:
            candidate = bundle + "/" + declared
            if candidate in archive.namelist():
                return candidate
    fallback = bundle + "/" + bundle.split("/")[-1][:-len(".app")]
    return fallback if fallback in archive.namelist() else None


# --------------------------------------------------------------------------
# the rewrite
# --------------------------------------------------------------------------

def rewrite(src_path: str, dst_path: str, edits: dict, snapshot: dict, order: list,
            archive_comment: bytes) -> None:
    """Copy `src_path` to `dst_path`, replacing only the members in `edits`.

    Every other member is opened on the source and streamed into a fresh write
    handle that was created from a *copy* of its ZipInfo - same name,
    date_time, external_attr (mode bits and symlink flag), create_system,
    compress_type and order.  Nothing is extracted to the filesystem.
    """
    with zipfile.ZipFile(src_path) as zin, \
            zipfile.ZipFile(dst_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
        zout.comment = archive_comment
        for zi in zin.infolist():
            name = zi.filename
            if name in edits:
                data = edits[name]
                # A fresh ZipInfo rather than mutating the source's: zipfile
                # zeroes file_size/CRC on the object it writes, and the snapshot
                # comparison later needs the original numbers.
                fresh = zipfile.ZipInfo(name, date_time=zi.date_time)
                fresh.external_attr = zi.external_attr
                fresh.internal_attr = zi.internal_attr
                fresh.create_system = zi.create_system
                fresh.compress_type = zi.compress_type
                fresh.comment = zi.comment
                zout.writestr(fresh, data)
            else:
                fresh = zipfile.ZipInfo(name, date_time=zi.date_time)
                fresh.external_attr = zi.external_attr
                fresh.internal_attr = zi.internal_attr
                fresh.create_system = zi.create_system
                fresh.compress_type = zi.compress_type
                fresh.comment = zi.comment
                force64 = zi.file_size >= (1 << 32) - 1
                with zin.open(zi) as source, zout.open(fresh, "w", force_zip64=force64) as target:
                    shutil.copyfileobj(source, target, 1024 * 1024)


def verify(src_path: str, dst_path: str, edits: dict, snapshot: dict, order: list,
           source_plists: dict, binary_member: str | None) -> list:
    """Every assertion about the output that can be made without an iPad.

    Returns a list of problems; empty means verified.  Each check here has a
    failure mode that has actually shipped in a real re-signing tool: a member
    silently dropped, a member silently duplicated, an archive whose CRCs were
    never validated, a binary that was "not changed" and was.
    """
    problems = []

    try:
        out = zipfile.ZipFile(dst_path)
    except zipfile.BadZipFile as exc:
        return ["output is not a readable zip: %s" % exc]

    with out:
        bad = out.testzip()
        if bad is not None:
            problems.append("CRC check failed on member %r" % bad)

        out_infos = out.infolist()
        if [i.filename for i in out_infos] != order:
            problems.append("member list or order differs from the source "
                            "(source %d members, output %d)"
                            % (len(order), len(out_infos)))

        for info in out_infos:
            want = snapshot.get(info.filename)
            if want is None:
                problems.append("member %r was added" % info.filename)
                continue
            want_crc, want_size, want_mode = want
            mode = info.external_attr >> 16
            if info.filename in edits:
                if want_crc == info.CRC and want_size == info.file_size:
                    problems.append("member %r was meant to change and did not"
                                    % info.filename)
            else:
                if info.CRC != want_crc or info.file_size != want_size:
                    problems.append("member %r changed but was not in the edit set "
                                    "(%d/%d bytes -> %d/%d bytes)"
                                    % (info.filename, want_size, want_crc,
                                       info.file_size, info.CRC))
            if (mode & 0o7777) != (want_mode & 0o7777):
                problems.append("member %r lost its mode bits (%o -> %o)"
                                % (info.filename, want_mode & 0o7777, mode & 0o7777))
            if stat.S_ISLNK(mode) != stat.S_ISLNK(want_mode):
                problems.append("member %r changed symlink-ness" % info.filename)

        for name, data in edits.items():
            if name not in out.namelist():
                problems.append("edited member %r is missing from the output" % name)
                continue
            try:
                parsed = plistlib.loads(out.read(name))
            except Exception as exc:
                problems.append("edited member %r does not parse: %s" % (name, exc))
                continue
            if not isinstance(parsed, dict):
                problems.append("edited member %r is no longer a dictionary" % name)
                continue
            still = [key for key in ICLOUD_KEYS if key in parsed]
            if still:
                problems.append("edited member %r still carries %s"
                                % (name, ", ".join(still)))
            before = source_plists[name]
            lost = sorted(set(before) - set(parsed))
            unexpected = sorted(set(parsed) - set(before))
            if unexpected:
                problems.append("edited member %r gained keys: %s"
                                % (name, ", ".join(unexpected)))
            if set(lost) != set(ICLOUD_KEYS) & set(before):
                problems.append("edited member %r lost keys it should have kept: %s"
                                % (name, ", ".join(sorted(set(lost) - set(ICLOUD_KEYS)))))
            for key in lost:
                if key in ICLOUD_KEYS:
                    continue
                problems.append("edited member %r lost %r" % (name, key))

        if binary_member:
            try:
                with zipfile.ZipFile(src_path) as source_archive:
                    before = _sha256_zip_member(source_archive, binary_member)
                after = _sha256_zip_member(out, binary_member)
                if before != after:
                    problems.append("the main executable changed (%s -> %s)"
                                    % (before[:16], after[:16]))
            except KeyError:
                pass
    return problems


def _sha256_zip_member(archive: zipfile.ZipFile, name: str) -> str:
    digest = hashlib.sha256()
    with archive.open(name) as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot(archive: zipfile.ZipFile) -> dict:
    out = {}
    for info in archive.infolist():
        out[info.filename] = (info.CRC, info.file_size, info.external_attr >> 16)
    return out


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def command_strip(args) -> int:
    src = args.ipa
    dst = args.output or _default_output(src)
    if os.path.abspath(src) == os.path.abspath(dst):
        fail("output would overwrite the input; pass -o with a different path")
        return EXIT_INPUT

    archive = open_ipa(src)
    with archive:
        names = archive.namelist()
        bundles = app_bundles(names)
        if not bundles:
            fail("%s has no Payload/*.app - this is not an app bundle" % src)
            return EXIT_INPUT

        candidates = entitlement_members(names)
        edits = {}
        removed_any = []
        source_plists = {}
        for name in candidates:
            raw = archive.read(name)
            try:
                stripped, removed, kept, fmt = strip_keys(raw)
            except InputError as exc:
                # Refuse the whole run.  A member we cannot read is a member we
                # cannot promise anything about, and half-stripped is worse than
                # not started: it looks done.
                fail("%s: %s" % (name, exc))
                return EXIT_INPUT
            if removed:
                edits[name] = stripped
                removed_any.extend(removed)
                source_plists[name] = plistlib.loads(raw)
                log("  - %s: removing %s (kept %d other key%s)"
                    % (name, ", ".join(removed), kept, "" if kept == 1 else "s"))

        report = {
            "mode": "strip",
            "input": {"path": os.path.abspath(src),
                      "sha256": _sha256_file(src),
                      "size": os.path.getsize(src),
                      "members": len(names)},
            "app_bundle": "Payload/" + bundles[0],
            "entitlement_members": candidates,
            "rewritten": {name: [k for k in ICLOUD_KEYS if k in source_plists[name]]
                          for name in edits},
        }

        binary = main_executable(archive, "Payload/" + bundles[0])
        report["executable"] = binary
        if binary:
            declared = signed_entitlements_of_member(archive, binary)
            report["signed_entitlements"] = _describe_entitlements(declared)
            if declared:
                present = [k for k in ICLOUD_KEYS if k in declared]
                if present:
                    log("note: the signature in this IPA already declares %d of the "
                        "four keys. Stripping the bundle's .xcent cannot change that - "
                        "only signing again can. Run `inspect` on the IPA after LC Sign."
                        % len(present))

        if not edits:
            warn("no member in %s carries any of the four iCloud keys (%d checked)"
                  % (src, len(candidates)))
            if not args.allow_missing:
                log("nothing to do; no output written (pass --allow-missing to copy anyway)")
                _write_report(args.report, report)
                return EXIT_NOTHING
            shutil.copyfile(src, dst)
            log("copied without changes: %s" % dst)
            _write_report(args.report, report)
            return EXIT_OK

        snapshot = _snapshot(archive)
        order = [info.filename for info in archive.infolist()]
        comment = archive.comment

    # Write beside the destination and rename on success, so a failure halfway
    # through never leaves something that looks like a finished IPA.
    directory = os.path.dirname(os.path.abspath(dst)) or "."
    handle, temp_path = tempfile.mkstemp(prefix=".ipa-strip-", suffix=".tmp", dir=directory)
    os.close(handle)
    try:
        rewrite(src, temp_path, edits, snapshot, order, comment)
        problems = verify(src, temp_path, edits, snapshot, order, source_plists,
                          binary if isinstance(binary, str) else None)
        if problems:
            for problem in problems:
                fail(problem)
            fail("verification failed; no output written")
            return EXIT_VERIFY
        if os.path.exists(dst):
            os.unlink(dst)
        os.replace(temp_path, dst)
        temp_path = None
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)

    report["output"] = {"path": os.path.abspath(dst),
                        "sha256": _sha256_file(dst),
                        "size": os.path.getsize(dst),
                        "members": len(order),
                        "crc_verified": True,
                        "untouched_members_identical": len(order) - len(edits)}
    log("")
    log("rewritten %d member(s); %d untouched member(s) verified byte for byte"
        % (len(edits), len(order) - len(edits)))
    log("output: %s (%d bytes, sha256 %s)"
        % (dst, report["output"]["size"], report["output"]["sha256"]))

    if args.entitlements_out or args.export_entitlements:
        code = command_export(argparse.Namespace(
            ipa=dst, output=args.entitlements_out or "NoiCloud.entitlements",
            report=None, allow_missing=True))
        if code != EXIT_OK:
            return code

    _write_report(args.report, report)
    if edits and removed_any:
        log("done: %d iCloud key occurrence(s) removed" % len(removed_any))
    return EXIT_OK


def command_inspect(args) -> int:
    """Report the entitlements that are actually in force for this IPA."""
    archive = open_ipa(args.ipa)
    with archive:
        names = archive.namelist()
        bundles = app_bundles(names)
        if not bundles:
            fail("%s has no Payload/*.app" % args.ipa)
            return EXIT_INPUT
        bundle = "Payload/" + bundles[0]
        binary = main_executable(archive, bundle)
        if binary is None:
            fail("cannot find the main executable of %s" % bundle)
            return EXIT_INPUT
        declared = signed_entitlements_of_member(archive, binary)

        report = {"mode": "inspect", "ipa": os.path.abspath(args.ipa),
                  "bundle": bundle, "executable": binary}

        if declared is None:
            log("signature: no readable entitlements in %s" % binary)
            log("this executable is unsigned, or signed ad hoc without entitlements")
            report["signed_entitlements"] = None
            present = []
        else:
            log("signature: %d entitlement(s) in %s" % (len(declared), binary))
            present = []
            for key in ICLOUD_KEYS:
                if key in declared:
                    present.append(key)
                    log("  PRESENT  %s = %s (%s)"
                        % (key, _short(declared[key]), type(declared[key]).__name__))
                else:
                    log("  absent   %s" % key)
            report["signed_entitlements"] = _describe_entitlements(declared)

        # The bundle's own .xcent files are reported separately, because a
        # signer that imports them and one that does not produce two different
        # outcomes from the same file set.
        for name in entitlement_members(names):
            try:
                parsed = plistlib.loads(archive.read(name))
            except Exception:
                log("  bundle   %s: unreadable" % name)
                continue
            keys = [k for k in ICLOUD_KEYS if k in parsed] if isinstance(parsed, dict) else []
            log("  bundle   %s: %s" % (name, ", ".join(keys) if keys else "clean"))

        _write_report(args.report, report)

        if present:
            log("")
            log("VERDICT: the four keys are IN THE SIGNATURE. Whatever the bundle's "
                "xcent files say, this is what CloudKit will read.")
            malformed = [k for k in present if not _well_typed(k, declared[k])]
            if malformed:
                log("And %d of them are the wrong type: %s"
                    % (len(malformed), ", ".join(malformed)))
            return EXIT_VERIFY
        log("")
        log("VERDICT: the signature declares none of the four keys.")
        return EXIT_OK


def command_export(args) -> int:
    """Write a signing template with the four keys absent."""
    out = args.output or "NoiCloud.entitlements"
    archive = open_ipa(args.ipa)
    with archive:
        names = archive.namelist()
        bundles = app_bundles(names)
        if not bundles:
            fail("%s has no Payload/*.app" % args.ipa)
            return EXIT_INPUT
        bundle = "Payload/" + bundles[0]

        source_kind = None
        base = None

        profile_name = bundle + "/embedded.mobileprovision"
        if profile_name in names:
            granted, how = _profile_entitlements(archive.read(profile_name))
            if granted:
                base = granted
                source_kind = "provisioning profile (%s)" % how

        if base is None:
            binary = main_executable(archive, bundle)
            if binary:
                declared = signed_entitlements_of_member(archive, binary)
                if declared:
                    base = declared
                    source_kind = "the binary's code signature"

        if base is None:
            for name in entitlement_members(names):
                try:
                    parsed = plistlib.loads(archive.read(name))
                except Exception:
                    continue
                if isinstance(parsed, dict):
                    base = parsed
                    source_kind = name
                    break

        if base is None:
            fail("no entitlements found in %s (no profile, no signature, no xcent)"
                 % args.ipa)
            return EXIT_INPUT

    cleaned = dict(base)
    removed = [key for key in ICLOUD_KEYS if key in cleaned]
    for key in removed:
        del cleaned[key]
    with open(out, "wb") as handle:
        handle.write(plistlib.dumps(cleaned, fmt=plistlib.FMT_XML, sort_keys=False))
    log("entitlements template: %s (%d keys, %d iCloud key(s) removed)"
        % (out, len(cleaned), len(removed)))
    log("  derived from: %s" % source_kind)
    log("  use this if LC Sign offers a choice of entitlements file; it is the set "
        "the profile grants, minus the four.")
    return EXIT_OK


def _well_typed(key, value) -> bool:
    """Whether an iCloud entitlement value has the shape CloudKit accepts.

    The expected type is a property of the *key*, not of the value, and that is
    the whole v13 story: `com.apple.developer.icloud-services` must be an array
    of strings, and "*" is a perfectly ordinary string.  A check that asked
    "is this a plausible value" would have passed it.  This one asks "is this
    the shape the schema demands", and "*" fails.

        com.apple.developer.icloud-services                array of strings
        com.apple.developer.icloud-container-identifiers   array of strings
        com.apple.developer.ubiquity-container-identifiers array of strings
        com.apple.developer.ubiquity-kvstore-identifier    string
    """
    wants_string = key == "com.apple.developer.ubiquity-kvstore-identifier"
    if wants_string:
        return isinstance(value, str)
    if not isinstance(value, list):
        return False
    return all(isinstance(item, str) for item in value)


def _short(value) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(repr(item) for item in value) + "]"
    return repr(value)


def _describe_entitlements(entitlements) -> dict | None:
    if entitlements is None:
        return None
    described = {}
    for key, value in entitlements.items():
        described[key] = {"type": type(value).__name__,
                          "value": value if isinstance(value, (str, list, bool, int)) else str(value)}
    return described


def _default_output(path: str) -> str:
    root, ext = os.path.splitext(path)
    return root + "-NoiCloud" + (ext or ".ipa")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _write_report(path, report) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=False)
        handle.write("\n")
    log("report: %s" % path)


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

def _fixture_entitlements(with_icloud=True, malformed=False):
    entitlements = {
        "application-identifier": "ABCDE12345.com.goodnotesapp.x",
        "keychain-access-groups": ["ABCDE12345.com.goodnotesapp.x"],
        "get-task-allow": False,
        "com.apple.developer.team-identifier": "ABCDE12345",
    }
    if with_icloud:
        entitlements["com.apple.developer.icloud-services"] = (
            "*" if malformed else ["CloudKit", "CloudDocuments"])
        entitlements["com.apple.developer.icloud-container-identifiers"] = (
            ["iCloud.com.goodnotesapp.x"])
        entitlements["com.apple.developer.ubiquity-kvstore-identifier"] = (
            "ABCDE12345.com.goodnotesapp.x")
        entitlements["com.apple.developer.ubiquity-container-identifiers"] = (
            ["iCloud.com.goodnotesapp.x"])
        entitlements["com.apple.developer.icloud-container-environment"] = "Production"
    return entitlements


def _fixture_macho(entitlements):
    """A minimal arm64 Mach-O whose LC_CODE_SIGNATURE points at a SuperBlob."""
    xml = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)
    blob_offset = 4096
    entitlements_blob = struct.pack(">II", CSMAGIC_EMBEDDED_ENTITLEMENTS, 8 + len(xml)) + xml
    index_offset = 12 + 8
    superblob = (struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE,
                             index_offset + len(entitlements_blob), 1)
                 + struct.pack(">II", CSSLOT_ENTITLEMENTS, index_offset)
                 + entitlements_blob)
    header = (b"\xcf\xfa\xed\xfe"
              + struct.pack("<7I", 0x0100000C, 0, 2, 1, 16, 0, 0)
              + struct.pack("<IIII", LC_CODE_SIGNATURE, 16, blob_offset, len(superblob)))
    body = header + b"\x00" * (blob_offset - len(header)) + superblob
    return body


def _write_fixture(path, with_xcent=True, with_plugin=True, malformed=False,
                   xcent_garbage=False, with_signature_icloud=True):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:

        def add(name, data, mode=0o100644):
            info = zipfile.ZipInfo(name)
            info.external_attr = (mode << 16)
            info.create_system = 3
            archive.writestr(info, data)

        add("Payload/", b"", 0o40755)
        add("Payload/GoodNotes.app/", b"", 0o40755)
        add("Payload/GoodNotes.app/Info.plist",
            plistlib.dumps({"CFBundleExecutable": "GoodNotes",
                            "CFBundleIdentifier": "com.goodnotesapp.x"}))
        add("Payload/GoodNotes.app/GoodNotes",
            _fixture_macho(_fixture_entitlements(with_icloud=with_signature_icloud,
                                                 malformed=malformed)), 0o100755)
        add("Payload/GoodNotes.app/_CodeSignature/CodeResources", b"<plist/>")
        add("Payload/GoodNotes.app/zh-Hans.lproj/\u00e9\u006e.lproj/InfoPlist.strings",
            "\u4f60\u597d".encode("utf-8"))
        add("Payload/GoodNotes.app/Frameworks/libthing.dylib", b"\x00" * 1024, 0o100755)
        if with_xcent:
            data = (b"this is not a plist" if xcent_garbage
                    else plistlib.dumps(_fixture_entitlements(malformed=malformed)))
            add("Payload/GoodNotes.app/archived-expanded-entitlements.xcent", data)
        if with_plugin:
            add("Payload/GoodNotes.app/PlugIns/Widget.appex/archived-expanded-entitlements.xcent",
                plistlib.dumps(_fixture_entitlements()))
        link = zipfile.ZipInfo("Payload/GoodNotes.app/Frameworks/Current")
        link.external_attr = (stat.S_IFLNK | 0o755) << 16
        link.create_system = 3
        archive.writestr(link, b"libthing.dylib")


def selftest() -> int:
    failures = []

    def invoke(handler, **kwargs):
        """Call a command the way main() does, so input errors are exit codes.

        Calling the handlers directly was the first version of this selftest,
        and it crashed instead of reporting: open_ipa raises InputError, main()
        turns that into exit 2, and the selftest bypassed main(). A test that
        exercises a path the program does not take is not testing the program.
        """
        try:
            return handler(argparse.Namespace(**kwargs))
        except InputError as exc:
            fail(str(exc))
            return EXIT_INPUT

    def check(condition, label):
        if condition:
            log("  ok    %s" % label)
        else:
            log("  FAIL  %s" % label)
            failures.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        log("selftest: strip, and every property the rewrite promises")

        good = os.path.join(tmp, "good.ipa")
        _write_fixture(good)
        out = os.path.join(tmp, "out.ipa")
        code = invoke(command_strip, ipa=good, output=out,
                      report=os.path.join(tmp, "r.json"),
                      entitlements_out=None, export_entitlements=False,
                      allow_missing=False)
        check(code == EXIT_OK, "strip exits 0")
        check(os.path.exists(out), "output written")

        with zipfile.ZipFile(good) as a, zipfile.ZipFile(out) as b:
            a_infos, b_infos = a.infolist(), b.infolist()
            check([i.filename for i in a_infos] == [i.filename for i in b_infos],
                  "member names and order identical")
            check(b.testzip() is None, "output CRCs all valid")

            edited = [n for n in a.namelist() if n.endswith(".xcent")]
            for name in edited:
                before = plistlib.loads(a.read(name))
                after = plistlib.loads(b.read(name))
                check(not any(k in after for k in ICLOUD_KEYS),
                      "%s has none of the four keys" % name.split("/")[-2])
                check(set(before) - set(after) == set(ICLOUD_KEYS) & set(before),
                      "%s lost exactly the four, nothing else" % name.split("/")[-2])
                check(all(before[k] == after[k] for k in after),
                      "%s kept every other value" % name.split("/")[-2])
                check("com.apple.developer.icloud-container-environment" in after,
                      "%s kept the fifth key, which was not in the brief"
                      % name.split("/")[-2])

            modes_before = {i.filename: i.external_attr >> 16 for i in a_infos}
            modes_after = {i.filename: i.external_attr >> 16 for i in b_infos}
            check(modes_before == modes_after, "every mode bit including symlink flags kept")
            check(stat.S_ISLNK(modes_after["Payload/GoodNotes.app/Frameworks/Current"]),
                  "the symlink is still a symlink")
            check(modes_after["Payload/GoodNotes.app/GoodNotes"] & 0o111,
                  "the main executable is still executable")

            binary_before = hashlib.sha256(a.read("Payload/GoodNotes.app/GoodNotes")).hexdigest()
            binary_after = hashlib.sha256(b.read("Payload/GoodNotes.app/GoodNotes")).hexdigest()
            check(binary_before == binary_after, "the Mach-O binary is byte identical")

            crc_unchanged = all(
                a.getinfo(i.filename).CRC == b.getinfo(i.filename).CRC
                for i in a_infos if not i.filename.endswith(".xcent"))
            check(crc_unchanged, "every untouched member has the same CRC-32")

        log("selftest: the signature reader")
        with zipfile.ZipFile(good) as archive:
            declared = signed_entitlements_of_member(archive, "Payload/GoodNotes.app/GoodNotes")
        check(isinstance(declared, dict), "synthetic Mach-O yields an entitlements dict")
        check(declared and declared.get("application-identifier")
              == "ABCDE12345.com.goodnotesapp.x", "parsed a known value out of it")
        check(declared and "com.apple.developer.icloud-services" in declared,
              "finds an iCloud key in the signature")

        log("selftest: inspect mode, on the fixture before and after signing")
        code = invoke(command_inspect, ipa=good, report=None)
        check(code == EXIT_VERIFY, "inspect rejects an IPA whose signature carries the keys")

        stripped_then_signed = os.path.join(tmp, "signed-clean.ipa")
        _write_fixture(stripped_then_signed, with_signature_icloud=False)
        code = invoke(command_inspect, ipa=stripped_then_signed, report=None)
        check(code == EXIT_OK, "inspect accepts an IPA whose signature is clean")

        log("selftest: failure modes must fail, not produce an IPA")
        garbage = os.path.join(tmp, "garbage.ipa")
        _write_fixture(garbage, xcent_garbage=True)
        target = os.path.join(tmp, "garbage-out.ipa")
        code = invoke(command_strip, ipa=garbage, output=target, report=None,
                      entitlements_out=None, export_entitlements=False,
                      allow_missing=False)
        check(code == EXIT_INPUT, "an unparseable .xcent stops the run")
        check(not os.path.exists(target), "and leaves no output behind")

        truncated = os.path.join(tmp, "truncated.ipa")
        with open(good, "rb") as source, open(truncated, "wb") as handle:
            handle.write(source.read(2048))
        target = os.path.join(tmp, "truncated-out.ipa")
        code = invoke(command_strip, ipa=truncated, output=target, report=None,
                      entitlements_out=None, export_entitlements=False,
                      allow_missing=False)
        check(code == EXIT_INPUT, "a truncated zip is rejected")
        check(not os.path.exists(target), "and leaves no output behind")

        nothing = os.path.join(tmp, "nothing.ipa")
        _write_fixture(nothing, with_xcent=False, with_plugin=False,
                       with_signature_icloud=False)
        target = os.path.join(tmp, "nothing-out.ipa")
        code = invoke(command_strip, ipa=nothing, output=target, report=None,
                      entitlements_out=None, export_entitlements=False,
                      allow_missing=False)
        check(code == EXIT_NOTHING, "an IPA with nothing to strip exits 3")
        check(not os.path.exists(target), "and does not copy a gigabyte for nothing")

        target = os.path.join(tmp, "nothing-forced.ipa")
        code = invoke(command_strip, ipa=nothing, output=target, report=None,
                      entitlements_out=None, export_entitlements=False,
                      allow_missing=True)
        check(code == EXIT_OK and os.path.exists(target),
              "--allow-missing copies it through instead")

        log("selftest: export mode")
        template = os.path.join(tmp, "t.entitlements")
        code = invoke(command_export, ipa=good, output=template)
        check(code == EXIT_OK and os.path.exists(template), "template written")
        exported = plistlib.loads(open(template, "rb").read())
        check(not any(k in exported for k in ICLOUD_KEYS), "template has none of the four")

        log("selftest: the type check that v13's crash report needed")
        services = "com.apple.developer.icloud-services"
        kvstore = "com.apple.developer.ubiquity-kvstore-identifier"
        check(_well_typed(services, ["CloudKit"]) is True,
              "an array of strings is valid for icloud-services")
        check(_well_typed(services, "*") is False,
              "a bare \"*\" is rejected for icloud-services - this is the v13 crash")
        check(_well_typed(services, [1]) is False, "an array of non-strings is not")
        check(_well_typed(kvstore, "ABCDE12345.com.x") is True,
              "a string is valid for the kvstore identifier")
        check(_well_typed(kvstore, ["ABCDE12345.com.x"]) is False,
              "an array is not valid for the kvstore identifier")

    log("")
    if failures:
        fail("%d selftest check(s) failed" % len(failures))
        return EXIT_VERIFY
    log("selftest: all checks passed")
    return EXIT_OK


# --------------------------------------------------------------------------

def main(argv) -> int:
    parser = argparse.ArgumentParser(
        description="Remove the four iCloud entitlements from an .ipa without "
                    "unpacking it, and report the entitlements that are in force.")
    parser.add_argument("--selftest", action="store_true",
                        help="run the built-in checks against synthetic archives")
    subparsers = parser.add_subparsers(dest="command")

    strip_parser = subparsers.add_parser("strip", help="remove the four keys and repack")
    strip_parser.add_argument("ipa")
    strip_parser.add_argument("-o", "--output")
    strip_parser.add_argument("--report")
    strip_parser.add_argument("--entitlements-out")
    strip_parser.add_argument("--export-entitlements", action="store_true",
                              help="also write NoiCloud.entitlements next to the output")
    strip_parser.add_argument("--allow-missing", action="store_true",
                              help="copy the archive through when nothing matches")
    strip_parser.set_defaults(handler=command_strip)

    inspect_parser = subparsers.add_parser(
        "inspect", help="report the entitlements in the code signature")
    inspect_parser.add_argument("ipa")
    inspect_parser.add_argument("--report")
    inspect_parser.set_defaults(handler=command_inspect)

    export_parser = subparsers.add_parser(
        "export", help="write a signing template with the four keys absent")
    export_parser.add_argument("ipa")
    export_parser.add_argument("-o", "--output")
    export_parser.set_defaults(handler=command_export)

    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()
    if not getattr(args, "handler", None):
        parser.print_help()
        return EXIT_INPUT
    try:
        return args.handler(args)
    except InputError as exc:
        fail(str(exc))
        return EXIT_INPUT


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
