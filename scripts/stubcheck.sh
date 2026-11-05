#!/usr/bin/env bash
#
# stubcheck.sh - compile every source without an iOS SDK, in seconds.
#
#   ./scripts/stubcheck.sh
#
# Why this exists
# ---------------
# CI is the only authoritative compile, and it runs on a macOS runner: a single
# front-end error there costs a full round trip. This script uses the same clang
# front end (via zig's bundled compiler, which is a plain pip install) against
# scripts/stubsdk/, a small reconstruction of the parts of Foundation / UIKit /
# Security / CoreFoundation this project calls, with the SDK signatures.
#
# It is a pre-flight, not a replacement:
#
#   * it proves the sources parse, type check and generate real arm64 objects
#   * it does NOT prove the real SDK has every symbol the stub declares
#   * the stub is written to fail where the SDK fails (see mach/mach_vm.h)
#
# So: run this before pushing, and still watch the macOS job.
#
# Requires: zig (pip install ziglang), python3, and Python's site-packages path.
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIG="${ZIG:-$(command -v zig || true)}"

if [[ -z "$ZIG" || ! -x "$ZIG" ]]; then
  echo "error: zig not found. Install it with:  pip install ziglang" >&2
  echo "       then re-run, or pass ZIG=/path/to/zig" >&2
  exit 1
fi

# zig ships the Darwin C library headers (libc, mach, dispatch, objc, libkern).
# Find them next to the binary.
ZIGLIB="$(cd "$(dirname "$(readlink -f "$ZIG")")" && pwd)/lib"
SYSINC="$ZIGLIB/libc/include/any-darwin-any"
if [[ ! -d "$SYSINC" ]]; then
  echo "error: could not find zig's Darwin headers under $SYSINC" >&2
  exit 1
fi

STUB="$ROOT/scripts/stubsdk/include"
BUILD="$ROOT/build"
OBJ="$(mktemp -d)"
trap 'rm -rf "$OBJ"' EXIT

# Keep zig's caches out of the repo and out of $HOME.
export ZIG_GLOBAL_CACHE_DIR="${TMPDIR:-/tmp}/gnunlock-zig-cache"
export ZIG_LOCAL_CACHE_DIR="$ZIG_GLOBAL_CACHE_DIR"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR"

COMMON=(
  -target aarch64-ios
  -isystem "$SYSINC"
  -I"$STUB"
  -I"$BUILD"
  -I"$ROOT/src"
  -fobjc-arc
  -fblocks
  -O2
  -Wall
  -Wno-unused-parameter
  -Wno-unused-variable
  -Wno-unused-function
  -Wno-deprecated-declarations
  -Wno-format-security
  -Wno-nullability-completeness
)

echo "zig:   $("$ZIG" version)"
echo "stub:  $STUB"

if [[ ! -f "$BUILD/GNBakedConfig.h" ]]; then
  # build/ is gitignored, so a fresh clone has no baked header. Generate it.
  echo "baking build/GNBakedConfig.h (missing)"
  mkdir -p "$BUILD"
  python3 "$ROOT/scripts/bake_plist.py" "$ROOT/config/GNUnlock.plist" "$BUILD/GNBakedConfig.h" || exit 1
fi

# ---------------------------------------------------------------- probes
# Every probe below is compiled the way the sources are compiled (-c -o to a
# file), not from stdin with -fsyntax-only. That is not a style choice: zig 0.17's
# -fsyntax-only path fails inside its own libubsan sub-compilation ("failed to
# rename ... FileNotFound"), so a probe that was supposed to be rejected was being
# "rejected" for a reason that had nothing to do with the language. A probe that
# must fail is also required to carry the expected diagnostic text, so it cannot
# pass by failing for the wrong reason.
PROBE_DIR="$OBJ/probes"
mkdir -p "$PROBE_DIR"

probe_run() {
  PROBE_OUT="$("$ZIG" cc "${COMMON[@]}" -c -o "$PROBE_DIR/$1.o" "$PROBE_DIR/$1.m" 2>&1)"
  PROBE_RC=$?
}

probe_must_fail() {
  local name="$1" marker="$2" why="$3"
  probe_run "$name"
  if [[ $PROBE_RC -eq 0 ]]; then
    echo "error: the stub accepted $name. $why" >&2
    return 1
  fi
  if ! printf '%s' "$PROBE_OUT" | grep -qF "$marker"; then
    echo "error: $name was rejected, but not with the diagnostic the SDK gives" >&2
    echo "       ('$marker' not in the output). A probe that fails for another" >&2
    echo "       reason proves nothing:" >&2
    printf '%s\n' "$PROBE_OUT" | head -6 >&2
    return 1
  fi
  return 0
}

# 1. The poisoned include has to poison, or the check is theatre.
cat > "$PROBE_DIR/machvm.m" <<'SRC'
#import <mach/mach_vm.h>
int gn_probe_mach_vm(void) { return 0; }
SRC
if ! probe_must_fail machvm "mach_vm.h unsupported" \
     "<mach/mach_vm.h> is a file whose entire body is #error on iOS."; then
  echo "       Resolve it by including the header behind __has_include." >&2
  exit 1
fi
echo "ok: <mach/mach_vm.h> is rejected the way iOS rejects it"
echo

# 2. The stub has to fail where the real SDK fails. This one is not
#    hypothetical: v12.1 was green here and produced ten front-end errors on the
#    macOS runner, because this stub declared the private SecTask family that
#    <Security/Security.h> does not. So compile the exact line that failed and
#    require it to fail. If it ever starts passing, the stub has drifted back
#    into being more permissive than the SDK, and this pre-flight is theatre.
cat > "$PROBE_DIR/sectask.m" <<'SRC'
#include <Security/Security.h>
void gn_probe_sectask(void) { SecTaskRef t = SecTaskCreateFromSelf(0); (void)t; }
SRC
if ! probe_must_fail sectask "use of undeclared identifier 'SecTaskRef'" \
     "<Security/Security.h> does not declare the private SecTask API."; then
  echo "       Resolve it with dlsym, as src/GNPrivateSecTask.m does." >&2
  exit 1
fi
echo "ok: the private SecTask API is undeclared, exactly as in the public SDK"
echo

# 3. The libxpc availability trap - the reason v22 exists.
#
#    v21 was green here and produced two front-end errors on the runner:
#
#        error: conflicting types for 'xpc_connection_create_mach_service'
#        error: 'xpc_connection_create_mach_service' is unavailable: not available on iOS
#
#    because this stub had no xpc header at all, so a source that declared its own
#    prototypes had nothing to disagree with. scripts/stubsdk/include/xpc/xpc.h
#    now reproduces Apple's declarations, attributes included, and <Foundation/
#    Foundation.h> in the stub includes it for the same reason the real one does
#    (v21's conflict arrived from a transitive header).
#
#    Three probes, one per answer that has to match:
#      (a) naming the mach-service variant is rejected as unavailable
#      (b) re-declaring the available one by hand is rejected as a conflict
#      (c) the asm-labelled form this tree uses still compiles
cat > "$PROBE_DIR/xpc_mach.m" <<'SRC'
#include <xpc/xpc.h>
void gn_probe_xpc_mach(void) { (void)xpc_connection_create_mach_service("x", 0, 0); }
SRC
if ! probe_must_fail xpc_mach "'xpc_connection_create_mach_service' is unavailable" \
     "iOS marks the mach-service variant __attribute__((unavailable)), and naming it is a front end error."; then
  exit 1
fi
echo "ok: xpc_connection_create_mach_service is rejected the way iOS rejects it"

cat > "$PROBE_DIR/xpc_redecl.m" <<'SRC'
#include <xpc/xpc.h>
extern void *xpc_connection_create(const char *, dispatch_queue_t);
void gn_probe_xpc_redecl(void) { (void)&xpc_connection_create; }
SRC
if ! probe_must_fail xpc_redecl "conflicting types for 'xpc_connection_create'" \
     "Apple's returns xpc_connection_t, so a second declaration returning void* is a conflict."; then
  exit 1
fi
echo "ok: a hand-written xpc_connection_create is a conflicting declaration, as on iOS"

cat > "$PROBE_DIR/xpc_asm.m" <<'SRC'
#include <xpc/xpc.h>
extern void *gn_probe_entry(const char *, dispatch_queue_t)
    __asm__("_xpc_connection_create") __attribute__((weak_import));
void *gn_probe_use(void) { return (void *)&gn_probe_entry; }
SRC
probe_run xpc_asm
if [[ $PROBE_RC -ne 0 || ! -s "$PROBE_DIR/xpc_asm.o" ]]; then
  echo "error: the asm-labelled replacee form does not compile against the SDK's" >&2
  echo "       declaration, and src/GNXPCGate.m depends on it:" >&2
  printf '%s\n' "$PROBE_OUT" | head -10 >&2
  exit 1
fi
echo "ok: the asm-labelled replacee form compiles next to Apple's declaration"
echo

# 3. Every source, one at a time, so the report names the file.
fail=0
for src in "$ROOT"/src/*.m; do
  name="$(basename "$src" .m)"
  out="$("$ZIG" cc "${COMMON[@]}" -c -o "$OBJ/$name.o" "$src" 2>&1 \
         | grep -v 'argument unused during compilation' || true)"
  if [[ -n "$out" ]]; then
    echo "FAILED  ${src##*/}"
    echo "$out" | head -30
    fail=$((fail + 1))
  elif [[ ! -s "$OBJ/$name.o" ]]; then
    echo "FAILED  ${src##*/} - compiler produced no object file"
    fail=$((fail + 1))
  else
    echo "ok      ${src##*/}  ($(wc -c <"$OBJ/$name.o") bytes)"
  fi
done

echo
if [[ $fail -ne 0 ]]; then
  echo "error: $fail source file(s) did not compile." >&2
  echo "       This is a pre-flight: the macOS job will say the same thing." >&2
  exit 1
fi

# The two checks that do not need a compiler at all: the source invariants, and
# the decoder itself on synthetic blobs. Both are cheap; both have caught a real
# defect already (see scripts/rebind_lint.py).
echo
if ! python3 "$ROOT/scripts/rebind_lint.py"; then
  exit 1
fi
if ! python3 "$ROOT/scripts/rebind_decoder_test.py"; then
  exit 1
fi
if ! python3 "$ROOT/scripts/v11_lint.py"; then
  exit 1
fi
if ! python3 "$ROOT/scripts/v11_lint.py" --selftest; then
  exit 1
fi
if ! python3 "$ROOT/scripts/v12_lint.py"; then
  exit 1
fi
if ! python3 "$ROOT/scripts/v12_lint.py" --selftest; then
  exit 1
fi

# The experiment ladder's state machine is pure C in a header, so it can be
# *executed* here rather than reasoned about. Host target on purpose: this is
# the one test in the repo that runs its subject instead of compiling it.
echo
echo "experiment ladder state machine"
if ! "$ZIG" cc "$ROOT/scripts/experiment_ladder_test.c" -o "$OBJ/experiment_ladder_test"; then
  echo "error: the ladder test did not compile" >&2
  exit 1
fi
if ! "$OBJ/experiment_ladder_test"; then
  exit 1
fi

# The repair's *shape* is the one defect no device log caught: v17 shipped a
# repair that answered a rule wanting an array of strings with a bare string, and
# the launch log called it a success because the mechanism was live. The decision
# is pure C, so it runs here - every combination of inputs, then the same
# assertions against v17's own decision, which they must reject.
echo
echo "entitlement repair policy (src/GNRepairPolicy.h)"
if ! "$ZIG" cc -std=c11 -Wall -Wextra -Werror -O1 "$ROOT/scripts/repair_policy_test.c" \
        -o "$OBJ/repair_policy_test"; then
    echo "FAILED to build scripts/repair_policy_test.c"
    exit 1
fi
if ! "$OBJ/repair_policy_test"; then
    exit 1
fi
if ! "$OBJ/repair_policy_test" --selfcheck; then
    exit 1
fi

# The slot walker is pure C behind a header, so it runs here on the host rather
# than being reasoned about. This is the second test in the repo that executes
# its subject; see the header for why it can.
echo
echo "import slot walker (src/GNSlotWalk.h)"
if ! "$ZIG" cc -Wno-unknown-pragmas -O1 "$ROOT/scripts/slotwalk_test.c" \
     -o "$OBJ/slotwalk_test"; then
  echo "error: the slot walker test did not compile" >&2
  exit 1
fi
if ! "$OBJ/slotwalk_test"; then
  exit 1
fi

# Then once against a Mach-O object the same compiler and linker produced, so the
# structure offsets in src/GNSlotWalk.h are checked against real output and not
# only against the test's own idea of the layout.
cat > "$OBJ/gn_slot_fixture.c" <<'FIXTURE'
extern int gn_fixture_a(int);
extern int gn_fixture_b(int);
int gn_slot_fixture(int x) { return gn_fixture_a(x) + gn_fixture_b(x); }
FIXTURE
if ! "$ZIG" cc "${COMMON[@]}" -c -o "$OBJ/gn_slot_fixture.o" "$OBJ/gn_slot_fixture.c"; then
  echo "error: the Mach-O fixture did not compile" >&2
  exit 1
fi
if ! "$OBJ/slotwalk_test" "$OBJ/gn_slot_fixture.o"; then
  exit 1
fi

echo "ok: every source compiled to an arm64 object."
echo "    Not proven: that the real SDK declares everything the stub still does."
echo "    Check 2 covers the half that actually broke: the stub may not be more"
echo "    permissive about private APIs, and v12_lint's private-api-dlsym rule"
echo "    keeps every private symbol inside a dlsym string."
echo "    The macOS workflow is still the authoritative build."
