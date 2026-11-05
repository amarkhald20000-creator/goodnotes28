#!/usr/bin/env bash
#
# Builds GNUnlock.dylib (arm64 + arm64e) for iOS.
#
# Requires Xcode command line tools. Works locally on a Mac and on the
# macos-14 GitHub runner.
#
#   ./scripts/build.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="$ROOT/out"
BUILD="$ROOT/build"
OBJ="$BUILD/obj"

MIN_IOS="14.0"
INSTALL_NAME="@executable_path/Frameworks/GNUnlock.dylib"
DYLIB_NAME="GNUnlock.dylib"

rm -rf "$OUT" "$BUILD"
mkdir -p "$OUT" "$OBJ"

# ---------------------------------------------------------------- toolchain
SDK="${SDKROOT:-}"
if [[ -z "$SDK" ]]; then
  SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
fi
if [[ ! -d "$SDK" ]]; then
  echo "error: no iOS SDK found (SDKROOT='$SDK')" >&2
  echo "       on a Mac: xcode-select --install && xcodebuild -license accept" >&2
  exit 1
fi
echo "SDK:     $SDK"
echo "clang:   $(clang --version | head -n 1)"

# --------------------------------------------------------- preflight checks
echo "==> preflight"
# The shipped defaults live in scripts/plist_expect.py and nowhere else: this
# script and the workflow both call it instead of restating the keys. v23 failed
# in CI because a second copy of "ThrowSwallowAtSite must be false" was still
# sitting in the workflow after the default changed.
python3 "$ROOT/scripts/plist_expect.py" "$ROOT/config/GNUnlock.plist"

python3 "$ROOT/scripts/gnstatic.py" selftest
echo

# A PAC discriminator taken from a chained fixup is a run time value, and the
# ptrauth builtins that accept a discriminator only accept a *constant* one.
# On arm64e that is a hard front-end error, so keep those calls out of the
# tree: signing goes through GNSignPointer() in src/GNRebind.m, which emits the
# PAC instruction directly. Comment lines are skipped on purpose - the comment
# block in GNRebind.m names the builtin while explaining why it cannot be used.
PTRAUTH_HITS="$(grep -rnE 'ptrauth_(sign_unauthenticated|sign_constant|auth_and_resign)[[:space:]]*\(' "$ROOT/src" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*|/\*)' || true)"
if [[ -n "$PTRAUTH_HITS" ]]; then
  echo "error: a ptrauth builtin with a run time discriminator reached the tree:" >&2
  echo "$PTRAUTH_HITS" >&2
  echo "       sign through GNSignPointer() in src/GNRebind.m instead" >&2
  exit 1
fi
echo "ok: no constant-discriminator-only ptrauth builtin in src/"
echo

# Apple declares every dyld type as a bare struct tag - `struct dyld_...` and
# no typedef - so a call site that names one without `struct` is a hard front
# end error. It only appears once the iOS SDK is on the include path, which is
# why a check that runs without an SDK never sees it. That is how v5 died on
# line 216 of GNRebind.m. Apple's tags may appear in a declaration and nowhere
# else; the decoder names the GNAuthBindPtr typedef.
DYLD_TAG_HITS="$(grep -rnE 'dyld_(chained|fixups)_[a-z0-9_]+[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[;=]' "$ROOT/src" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*|/\*)' \
  | grep -vE 'struct[[:space:]]+dyld_' || true)"
if [[ -n "$DYLD_TAG_HITS" ]]; then
  echo "error: an Apple dyld struct type is named without 'struct':" >&2
  echo "$DYLD_TAG_HITS" >&2
  echo "       name GNAuthBindPtr (src/GNRebind.m) instead" >&2
  exit 1
fi
echo "ok: Apple dyld types are only named through the typedef"
echo

# ------------------------------------------------------------- baked config
python3 "$ROOT/scripts/bake_plist.py" "$ROOT/config/GNUnlock.plist" "$BUILD/GNBakedConfig.h"

# ------------------------------------------------------------------ sources
SOURCES=("$ROOT"/src/*.m)
if [[ ${#SOURCES[@]} -eq 0 ]]; then
  echo "error: no sources in src/" >&2
  exit 1
fi
echo "sources: ${#SOURCES[@]} files"

COMMON_FLAGS=(
  -x objective-c
  -isysroot "$SDK"
  -miphoneos-version-min="$MIN_IOS"
  -fobjc-arc
  -O2
  -Wall
  -Wno-unused-parameter
  -Wno-unused-variable
  -Wno-unused-function
  -Wno-deprecated-declarations
  -Wno-format-security
  -Wno-nullability-completeness
  -I"$BUILD"
  -I"$ROOT/src"
)

LINK_FLAGS=(
  -framework Foundation
  -framework Security
  -framework CoreFoundation
  -framework UIKit
)

# ------------------------------------------------------- header availability
# <mach/mach_vm.h> is a trap on iOS: the entire file is
#
#     #error mach_vm.h unsupported.
#
# so a single #import of it aborts the translation unit, and every mach_vm_*
# call under it is then undeclared too - one include, two diagnostics. That is
# what stopped v5 and v6 from building, and it was only ever discovered by
# compiling, i.e. one error at a time. Checking each include on its own turns
# the whole class into one line, before a single source file is compiled.
#
# Includes behind __has_include are skipped: they are optional by construction
# and the sources already handle their absence.
echo "==> header check"
GUARDED_HEADERS="$(grep -rhoE '__has_include[[:space:]]*\([[:space:]]*<[^>]+>' "$ROOT/src" 2>/dev/null \
  | sed -E 's/.*<([^>]+)>.*/\1/' | sort -u || true)"
HEADER_FAILED=0
for header in $(grep -rhoE '^[[:space:]]*#[[:space:]]*(import|include)[[:space:]]*<[^>]+>' "$ROOT/src" 2>/dev/null \
                | sed -E 's/.*<([^>]+)>.*/\1/' | sort -u); do
  if printf '%s\n' "$GUARDED_HEADERS" | grep -qxF "$header"; then
    continue
  fi
  if ! printf '#include <%s>\n' "$header" \
       | clang -x objective-c -fsyntax-only -isysroot "$SDK" \
               -miphoneos-version-min="$MIN_IOS" - >/dev/null 2>&1; then
    echo "error: <$header> cannot be included from the iOS SDK" >&2
    HEADER_FAILED=1
  fi
done
if [[ $HEADER_FAILED -ne 0 ]]; then
  echo "       the SDK either does not ship that header or rejects it outright;" >&2
  echo "       every source that includes it will fail to compile" >&2
  exit 1
fi
echo "ok: every <...> include resolves against the SDK"
echo

# The generic check above stops a poisoned include. This one stops the call
# underneath it, which is the error the compiler actually prints, and it names
# the supported replacement instead of making the next person rediscover it.
MACHVM_HITS="$(grep -rnE 'mach_vm_[a-z_0-9]|mach/mach_vm\.h' "$ROOT/src" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*|/\*)' || true)"
if [[ -n "$MACHVM_HITS" ]]; then
  echo "error: the mach_vm_* family is not usable on iOS (mach_vm.h is '#error')" >&2
  echo "$MACHVM_HITS" >&2
  echo "       use vm_region_64 / vm_protect from <mach/vm_map.h>" >&2
  exit 1
fi
echo "ok: no mach_vm_* usage"
echo

# Swizzling an init-family selector (alloc / init / new / copy / mutableCopy and
# anything starting with "init") with a plain C function breaks ARC's ownership
# contract: the caller consumes a +1 object, the function hands back +0. That is
# an over-release waiting for the right launch order, and it is what v7 did to
# -[NSUserDefaults initWithSuiteName:]. The hook is gone; this keeps it gone.
INIT_HOOK_HITS="$(grep -rnE 'GNHook(Instance|Class|IfExists)\([^;]*"[^"]*init' "$ROOT/src" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*|/\*)' || true)"
if [[ -n "$INIT_HOOK_HITS" ]]; then
  echo "error: an init-family selector is swizzled with a C function:" >&2
  echo "$INIT_HOOK_HITS" >&2
  echo "       callers consume +1 from init; a C function returns +0" >&2
  echo "       (see the GNResign.m note about initWithSuiteName:)" >&2
  exit 1
fi
echo "ok: no init-family selector is swizzled"
echo

# GNGuard rebinds abort() and exit() in every app owned image - and this dylib
# is app owned, so its own import slots are rebound too. A direct call to either
# one inside GNGuard.m would therefore be traced, re-enter the tracer, and be
# traced again. The tracer must call the pointers saved before the rebinding,
# and fall back to _exit(), which is never rebound. grep cannot tell a comment
# from a string from code here, so this check strips both first.
echo "==> guard self-call check"
python3 - "$ROOT/src/GNGuard.m" <<'PYGUARD'
import re, sys

path = sys.argv[1]
bad = []
with open(path, "r", encoding="utf-8") as handle:
    for number, line in enumerate(handle, 1):
        code = line.split("//", 1)[0]
        if code.lstrip().startswith("*"):
            code = ""
        code = re.sub(r'@?"(?:[^"\\]|\\.)*"', '""', code)
        for match in re.finditer(r'(?<![_A-Za-z0-9.>])(abort|exit)\s*\(', code):
            bad.append((number, line.rstrip()))

if bad:
    sys.stderr.write("error: GNGuard.m calls abort()/exit() directly - those slots\n"
                     "       are rebound by GNGuard itself, so this recurses.\n"
                     "       Call gRealAbort()/gRealExit(), or _exit().\n")
    for number, line in bad:
        sys.stderr.write("  %s:%d: %s\n" % (path, number, line))
    sys.exit(1)
PYGUARD
echo "ok: GNGuard.m only reaches abort/exit through the saved pointers"
echo

# ------------------------------------------------------ rebind safety gates
# The v9 crash was a strcmp on a pointer decoded out of a chained fixups import
# table. Four invariants keep that class of bug out, and each one is checked
# here rather than remembered:
#
#   1. GNRebind.m never compares a decoded name with strcmp/strncmp. Comparison
#      goes through GNReadableCStringEquals(), which finds the terminator inside
#      a proven-readable run first, so an unterminated string cannot run off a
#      mapping.
#   2. GNRebindSymbolInAppImages() checks EnableGOTRebinding itself, before it
#      walks any image - not only at its call sites. The launch guard used to
#      call it directly, which is how a feature documented as off by default
#      ended up running in the dylib constructor.
#   3. GNInstallLaunchGuard() does not call the rebinder. The abort tracer is
#      scheduled for after launch, so a defect in it cannot stop the app from
#      starting - which is the whole difference between a bad hook and a boot
#      loop.
#   4. The decoder itself is exercised by scripts/rebind_decoder_test.py against
#      synthetic blobs in all three import formats (called from this script).
echo "==> rebind safety gates"
if ! python3 "$ROOT/scripts/rebind_lint.py"; then
  exit 1
fi
echo "ok: no unbounded comparison, gate before the walk, tracer deferred"
echo

python3 "$ROOT/scripts/rebind_decoder_test.py"
echo

# v11 invariants. Each one is a defect that actually shipped, and --selftest
# mutates the sources to prove the check is not theatre.
echo "==> v11 invariant check"
if ! python3 "$ROOT/scripts/v11_lint.py"; then
  exit 1
fi
if ! python3 "$ROOT/scripts/v11_lint.py" --selftest; then
  exit 1
fi

# v12 invariants. The whole point of v12 is that the shipped default installs
# nothing, and "nothing" is a property that erodes one convenience edit at a
# time. --selftest mutates the tree once per rule and requires each rule to fire.
echo "==> v12 invariant check"
if ! python3 "$ROOT/scripts/v12_lint.py"; then
  exit 1
fi
if ! python3 "$ROOT/scripts/v12_lint.py" --selftest; then
  exit 1
fi
echo

# The ladder's state machine is pure C: execute it rather than trust it.
LADDER_BIN="$BUILD/experiment_ladder_test"
ZIG_CC="${ZIG:-}"
if [[ -n "$ZIG_CC" && -x "$ZIG_CC" ]]; then
  "$ZIG_CC" cc "$ROOT/scripts/experiment_ladder_test.c" -o "$LADDER_BIN"
else
  cc -std=c11 "$ROOT/scripts/experiment_ladder_test.c" -o "$LADDER_BIN"
fi
"$LADDER_BIN"
echo

# The v25 resolver's only arithmetic. An interior offset from a crash log is
# turned into the entry address of the function that contains it by walking the
# image's LC_FUNCTION_STARTS delta list; if that is off by one entry the dylib
# rewrites a slot to point at a different function. src/GNFunctionStarts.h is
# pure C for exactly this reason - execute it, do not read it.
echo "==> function starts (v25 resolver)"
FS_BIN="$BUILD/functionstarts_test"
if [[ -n "$ZIG_CC" && -x "$ZIG_CC" ]]; then
  "$ZIG_CC" cc -std=c11 -Wall -Wextra -Werror "$ROOT/scripts/functionstarts_test.c" -o "$FS_BIN"
else
  cc -std=c11 -Wall -Wextra -Werror "$ROOT/scripts/functionstarts_test.c" -o "$FS_BIN"
fi
"$FS_BIN"
"$FS_BIN" --selfcheck
echo


# ------------------------------------------------------- front-end check
# One translation unit at a time, both slices, no linking. A combined compile
# buries a single file's error under the link step's output (and under lipo
# complaining about the dylib that was never written); this names the file that
# the slice actually rejects.
#
# It also no longer stops at the first failure. Stopping there means every
# round trip through CI reveals exactly one error, which is how this project
# spent four builds discovering one line at a time. Every file is compiled, all
# failures are reported, and then the build stops.
echo "==> front-end check (arm64, arm64e)"
FRONTEND_FAILED=0
for arch in arm64 arm64e; do
  for src in "${SOURCES[@]}"; do
    if ! clang -arch "$arch" -fsyntax-only "${COMMON_FLAGS[@]}" "$src"; then
      echo "  FAILED  $arch  ${src##*/}" >&2
      FRONTEND_FAILED=$((FRONTEND_FAILED + 1))
    fi
  done
done
if [[ $FRONTEND_FAILED -ne 0 ]]; then
  echo "error: $FRONTEND_FAILED file/slice combination(s) did not compile:" >&2
  echo "       every one of them is listed above; fix them in one pass" >&2
  exit 1
fi
echo "ok: all sources parse for arm64 and arm64e"

# --------------------------------------------------------------- per arch
# Callers test the return value of build_arch, which turns off `set -e` for the
# whole function body. So a failing clang used to fall straight through, and the
# first thing to notice was `lipo` on a file that had never been written - which
# is how "2 errors generated" surfaced as
# "lipo: can't open input file: GNUnlock-arm64e.dylib". Check the status.
build_arch () {
  local arch="$1"
  local output="$OBJ/GNUnlock-$arch.dylib"
  echo "==> clang -arch $arch"

  if ! clang -arch "$arch" -dynamiclib "${COMMON_FLAGS[@]}" "${SOURCES[@]}" \
        "${LINK_FLAGS[@]}" -install_name "$INSTALL_NAME" -o "$output"; then
    echo "error: compile failed for $arch" >&2
    return 1
  fi
  if [[ ! -s "$output" ]]; then
    echo "error: clang exited 0 for $arch but wrote no dylib" >&2
    return 1
  fi
  echo "    $(lipo -archs "$output" 2>/dev/null || echo "$arch")  $(stat -f%z "$output" 2>/dev/null || stat -c%s "$output") bytes"
}

build_arch arm64

# An arm64e failure is fatal by default: it is the slice that catches the
# arch-specific mistakes, so swallowing it is how a broken build ships. The app
# is a single-arch arm64 binary, so shipping arm64 only is a legitimate choice -
# make it an explicit one with ALLOW_ARM64_ONLY=1.
ARM64E_OK=0
if build_arch arm64e; then
  ARM64E_OK=1
else
  if [[ "${ALLOW_ARM64_ONLY:-0}" == "1" ]]; then
    echo "warning: arm64e slice did not build; ALLOW_ARM64_ONLY=1, shipping arm64 only" >&2
  else
    echo "error: arm64e slice did not build." >&2
    echo "       Fix the error above, or re-run with ALLOW_ARM64_ONLY=1 to ship arm64 only." >&2
    exit 1
  fi
fi

# ------------------------------------------------------------------- fat
if [[ $ARM64E_OK -eq 1 ]]; then
  lipo -create "$OBJ/GNUnlock-arm64.dylib" "$OBJ/GNUnlock-arm64e.dylib" \
       -output "$OUT/$DYLIB_NAME"
else
  cp "$OBJ/GNUnlock-arm64.dylib" "$OUT/$DYLIB_NAME"
fi

# ------------------------------------------------------------- sanity pass
echo
echo "==> verification"
lipo -info "$OUT/$DYLIB_NAME"

# Every text search below reads a file, not a pipe. With `set -o pipefail`, a
# `strings ... | grep -q` pipeline reports failure even when grep *matches*:
# grep -q exits on the first hit, strings takes SIGPIPE, and the pipeline's
# status becomes 141. These gates only started being reached once the sources
# compiled, so the trap had never fired before.
strings "$OUT/$DYLIB_NAME" > "$BUILD/strings.txt" || true
nm -u "$OUT/$DYLIB_NAME" > "$BUILD/undef.txt" 2>/dev/null || true
otool -D "$OUT/$DYLIB_NAME" | tail -n 1 > "$BUILD/installname.txt" || true

echo "install name: $(cat "$BUILD/installname.txt")"

if grep -qF "$INSTALL_NAME" "$BUILD/installname.txt"; then
  echo "ok: install name matches the LC Sign destination"
else
  echo "warning: install name is not $INSTALL_NAME" >&2
fi

if grep -qi 'CydiaSubstrate\|substrate' "$BUILD/undef.txt"; then
  echo "error: dylib still references CydiaSubstrate" >&2
  exit 1
fi
echo "ok: no Substrate dependency"

if ! grep -q 'ResignFix' "$BUILD/strings.txt"; then
  echo "error: baked config missing from the binary" >&2
  exit 1
fi
if ! grep -q 'EnableGOTRebinding' "$BUILD/strings.txt"; then
  echo "error: v3 capability keys missing from the baked config" >&2
  exit 1
fi
echo "ok: config baked in (v3 keys present)"

if grep -q 'VM_PROT_WRITE | VM_PROT_EXECUTE' "$BUILD/strings.txt"; then
  echo "error: a W^X violating protect call survived into the build" >&2
  exit 1
fi
echo "ok: no W^X violating vm_protect request"

SIZE=$(stat -f%z "$OUT/$DYLIB_NAME" 2>/dev/null || stat -c%s "$OUT/$DYLIB_NAME")
if [[ "$SIZE" -lt 20000 ]]; then
  echo "error: dylib is only $SIZE bytes - something did not compile in" >&2
  exit 1
fi
echo "ok: size $SIZE bytes"

echo
echo "==> done"
echo "    $OUT/$DYLIB_NAME"
echo
echo "next: add it in LC Sign as Frameworks/GNUnlock.dylib,"
echo "      enable 'sign injected libraries', sign and install."
echo
echo "      first launch should log:"
echo "        capability: signature=distribution CS_DEBUGGED=no AllowCodePatching=no -> codePatching BLOCKED"
echo "      that line is the proof that nothing will be written to a code page."
echo
echo "      and then the two lines that matter for the launch crash (v18):"
echo '        repair: #1 com.apple.developer.icloud-services (schema wants array of strings): string "*" -> array(1)'
echo "        slot: self-test  VERDICT: interception is LIVE in this process"
echo "      the first one has to end in array(1). v17 ended it in string \"CloudKit\""
echo "      for a key CloudKit requires to be an array, which is why the launch"
echo "      died with the log saying the hook was live."
