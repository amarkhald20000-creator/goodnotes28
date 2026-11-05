#!/usr/bin/env python3
"""rebind_lint.py - the invariants that keep the v9 crash from coming back.

    python3 scripts/rebind_lint.py

Four rules, each tied to a defect that was actually shipped:

  1. src/GNRebind.m does not compare a decoded name with strcmp/strncmp.
     v9 handed strcmp a pointer decoded out of a chained fixups import table;
     the pointer was outside the string pool and strcmp faulted. Comparison now
     goes through GNReadableCStringEquals(), which proves the bytes are readable
     and finds the terminator before comparing anything.

  2. GNRebindSymbolInAppImages() gates on EnableGOTRebinding itself, before it
     walks any image. v9 gated only its callers, and the one caller that ran in
     the dylib constructor (the launch guard) bypassed the switch entirely.

  3. GNInstallLaunchGuard() does not call the rebinder. The abort tracer is
     scheduled for after launch, so a defect there cannot stop the app from
     starting.

  4. The import table stride has exactly one definition, and it matches Apple's
     dyld_chained_import* layouts: 4, 4 and 8 bytes for formats 1, 2 and 3.

Called by scripts/build.sh and scripts/stubcheck.sh.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REBIND = ROOT / "src" / "GNRebind.m"
GUARD = ROOT / "src" / "GNGuard.m"


def code_lines(text):
    """Yields (line number, code) with comments and string literals removed."""
    for number, line in enumerate(text.splitlines(), 1):
        code = line.split("//", 1)[0]
        if code.lstrip().startswith("*"):
            code = ""
        yield number, re.sub(r'@?"(?:[^"\\]|\\.)*"', '""', code)


def main():
    for path in (REBIND, GUARD):
        if not path.exists():
            raise SystemExit("missing %s" % path)

    rebind = REBIND.read_text(encoding="utf-8")
    guard = GUARD.read_text(encoding="utf-8")
    problems = []

    # 1. no unbounded comparison of decoded data
    for number, code in code_lines(rebind):
        for match in re.finditer(r'(?<![_A-Za-z0-9])(strcmp|strncmp|strcasecmp)\s*\(', code):
            problems.append("%s:%d uses %s() on decoded data - compare through "
                            "GNReadableCStringEquals()" % (REBIND.name, number, match.group(1)))

    # 2. the config gate lives inside the function, before the walk
    start = rebind.find("NSInteger GNRebindSymbolInAppImages(")
    end = rebind.find("BOOL GNInterposeSymbol(")
    if start < 0 or end <= start:
        problems.append("%s: could not locate GNRebindSymbolInAppImages()" % REBIND.name)
    else:
        body = rebind[start:end]
        gate_at = body.find("EnableGOTRebinding")
        walk_at = body.find("_dyld_image_count")
        if gate_at < 0:
            problems.append("%s: GNRebindSymbolInAppImages() has no EnableGOTRebinding gate"
                            % REBIND.name)
        elif walk_at >= 0 and gate_at > walk_at:
            problems.append("%s: the EnableGOTRebinding gate comes after the image walk"
                            % REBIND.name)

    # 3. the constructor path never rebinds
    install = guard.find("void GNInstallLaunchGuard(void)")
    if install < 0:
        problems.append("%s: could not locate GNInstallLaunchGuard()" % GUARD.name)
    elif "GNRebindSymbolInAppImages" in guard[install:]:
        problems.append("%s: GNInstallLaunchGuard() calls the rebinder directly - schedule "
                        "it for after launch (see GNScheduleAbortTracer)" % GUARD.name)

    # 4. one stride table, matching Apple's layouts
    stride_match = re.search(r"static uint32_t GNImportEntrySize\(uint32_t format\) \{(.*?)\n\}",
                             rebind, re.S)
    if not stride_match:
        problems.append("%s: GNImportEntrySize() is missing" % REBIND.name)
    else:
        body = stride_match.group(1)
        expected = {
            "GN_IMPORT": "4",
            "GN_IMPORT_ADDEND": "4",
            "GN_IMPORT_ADDEND64": "8",
        }
        for name, size in expected.items():
            case = re.search(r"case %s:\s*(?:case [A-Z_0-9]+:\s*)*return (\d+);" % name, body)
            if not case:
                problems.append("%s: GNImportEntrySize() has no case for %s" % (REBIND.name, name))
            elif case.group(1) != size:
                problems.append("%s: GNImportEntrySize(%s) returns %s, Apple's layout is %s bytes"
                                % (REBIND.name, name, case.group(1), size))

    if problems:
        sys.stderr.write("error: rebind safety gate violated:\n")
        for problem in problems:
            sys.stderr.write("  %s\n" % problem)
        return 1

    print("ok: no unbounded comparison, gate before the walk, tracer deferred, stride correct")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
