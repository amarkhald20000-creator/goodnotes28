#!/usr/bin/env python3
"""v11_lint.py - the five invariants behind v11, each tied to a real defect.

    python3 scripts/v11_lint.py            # check the tree
    python3 scripts/v11_lint.py --selftest # prove each check can fail

1. The run level ladder must not re-read Documents/gnunlock.state.

   v8-v10 read the state file from GNRunLevel(), which by then already held the
   "boot" that this same launch had just written. GNPhaseIsEarly("boot") is yes,
   so every launch looked like "the previous one died" and the ladder stepped
   down one level per launch - a healthy build reached level 0, with every hook
   off, in four launches. The value has to be captured in GNLogBoot before it is
   overwritten (gPreviousPhase) and read through GNPreviousLaunchWasEarly().

2. The launch guard must install the UIKit boundary net.

   v10 only wrapped the app delegate's two launch selectors. The crash arrived
   with no frame of ours in the stack at all, i.e. the wrapper was not on that
   path, and the report was never written.

3. The throw tracer must log and then throw for real.

   It is a tap, not a handler: if it ever stops calling the saved original, it
   silently changes what the app does. It must also set its per-thread
   re-entrancy flag, because this dylib is app owned and its own throw is
   rebound too.

4. The throw tracer must stay opt-in.

   It is the only v11 code that writes a data page during dyld init, and this
   project has already lost a launch to the decoder. With "auto" it may only
   install when no @try net went in.

5. The experiment ladder's decisions must come from the header the test runs.

   The state machine lives in src/GNExperimentLadder.h so that
   scripts/experiment_ladder_test.c executes the shipped code. If the resolve
   path grows its own copy, the test keeps passing while covering nothing.
"""

import pathlib
import re
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUPPORT = "src/GNSupport.m"
GUARD = "src/GNGuard.m"
THROW = "src/GNThrowTrace.m"
LADDER = "src/GNExperimentLadder.h"
TEST_LADDER = "scripts/experiment_ladder_test.c"

GUARD_NET = "gGuardNets"
BOUNDARY_SELECTOR = "_handleDelegateCallbacksWithOptions:isSuspended:restoreState:"


def read(root, relative):
    path = pathlib.Path(root) / relative
    if not path.exists():
        raise SystemExit("missing %s" % path)
    return path.read_text(encoding="utf-8")


def function_body(text, signature):
    """The braces-balanced body of `signature`, or "" when not found."""
    start = text.find(signature)
    if start < 0:
        return ""
    brace = text.find("{", start)
    if brace < 0:
        return ""
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:index + 1]
    return ""


def check(root):
    support = read(root, SUPPORT)
    guard = read(root, GUARD)
    throw = read(root, THROW)
    problems = []

    # 1. the ladder must use the captured phase, never the state file
    body = function_body(support, "int GNRunLevel(void)")
    if not body:
        problems.append("%s: GNRunLevel() not found" % SUPPORT)
    else:
        if "GNStatePath(" in body:
            problems.append("%s: GNRunLevel() reads the state file again - that value is this "
                            "launch's own 'boot', so the ladder steps down every launch; use "
                            "GNPreviousLaunchWasEarly()" % SUPPORT)
        if "GNPreviousLaunchWasEarly(" not in body:
            problems.append("%s: GNRunLevel() does not consult GNPreviousLaunchWasEarly()"
                            % SUPPORT)
        if "GNExperimentControlsRunLevel(" not in body:
            problems.append("%s: GNRunLevel() drops a level while the experiment ladder is "
                            "running - two ladders stepping on the same signal change two "
                            "things per launch and name neither" % SUPPORT)

    # GNDropRunLevel() writes the same bisect file from the exception path, so it
    # needs the same guard - otherwise a caught exception moves the ladder even
    # when the ladder is supposed to be holding still.
    drop = function_body(support, "void GNDropRunLevel(const char *reason)")
    if not drop:
        problems.append("%s: GNDropRunLevel() not found" % SUPPORT)
    elif "GNExperimentControlsRunLevel(" not in drop:
        problems.append("%s: GNDropRunLevel() can move the level while the experiment ladder "
                        "owns it" % SUPPORT)
    if "gPreviousPhase = " not in support:
        problems.append("%s: gPreviousPhase is never captured in GNLogBoot()" % SUPPORT)

    # 2. the boundary net has to exist and be counted
    install = function_body(guard, "void GNInstallLaunchGuard(void)")
    if not install:
        problems.append("%s: GNInstallLaunchGuard() not found" % GUARD)
    elif "GNGuardInstallBoundaryNet(" not in install:
        problems.append("%s: GNInstallLaunchGuard() does not install the UIKit boundary net - "
                        "the app delegate alone was already proven insufficient" % GUARD)

    boundary = function_body(guard, "static BOOL GNGuardInstallBoundaryNet(void)")
    if not boundary:
        problems.append("%s: GNGuardInstallBoundaryNet() not found" % GUARD)
    else:
        if BOUNDARY_SELECTOR not in boundary:
            problems.append("%s: the boundary net does not hook %s"
                            % (GUARD, BOUNDARY_SELECTOR))
        if GUARD_NET + "++" not in boundary:
            problems.append("%s: the boundary net does not count itself in %s - "
                            "GNGuardNetCount() would report 0 while a net is live"
                            % (GUARD, GUARD_NET))

    if "NSInteger GNGuardNetCount(void)" not in guard:
        problems.append("%s: GNGuardNetCount() is missing" % GUARD)

    # 3. the tracer is a tap: log, then throw for real
    tracer = function_body(throw, "static void GNThrowTracer(id exception)")
    if not tracer:
        problems.append("%s: GNThrowTracer() not found" % THROW)
    else:
        if "gRealObjcExceptionThrow(" not in tracer:
            problems.append("%s: GNThrowTracer() never calls the saved objc_exception_throw - "
                            "this is an interposition, not a replacement" % THROW)

    # v20 moved the recording out of GNThrowTracer so the trampoline can decide
    # what to do *after* the evidence exists. The invariant did not move with it
    # by accident: what it protects is "the report is guarded before it runs", and
    # that now lives in the recorder. Checking GNThrowTracer for the flag would
    # pass a build whose recorder had lost it - i.e. exactly the recursion this
    # rule exists to prevent.
    recorder = function_body(throw, "void GNThrowTraceRecord(id exception)")
    if not recorder:
        problems.append("%s: GNThrowTraceRecord() not found - the trampoline records through "
                        "it and a missing recorder means a silent swallow" % THROW)
    else:
        if "gInThrowTracer = YES" not in recorder:
            problems.append("%s: GNThrowTraceRecord() does not set its re-entrancy flag - this "
                            "dylib is app owned, so its own throw is rebound too and would "
                            "recurse" % THROW)
        if "gInThrowTracer" not in recorder.split("gInThrowTracer = YES")[0]:
            problems.append("%s: GNThrowTraceRecord() sets the re-entrancy flag without reading "
                            "it first - the flag must be tested before the report runs" % THROW)
        if "GNThrowRecord(" not in recorder:
            problems.append("%s: GNThrowTraceRecord() does not write a record" % THROW)

    if tracer and "GNThrowTraceRecord(" not in tracer:
        problems.append("%s: GNThrowTracer() no longer records - the tap would be invisible"
                        % THROW)

    # 4. and it stays opt-in
    installer = function_body(throw, "void GNInstallThrowTracer(NSInteger netsInstalled)")
    if not installer:
        problems.append("%s: GNInstallThrowTracer() not found" % THROW)
    else:
        if "netsInstalled > 0" not in installer:
            problems.append("%s: GNInstallThrowTracer() rebinds even when the @try nets are "
                            "live - in auto mode it must not" % THROW)
        if "GNRebindSymbolInAppImages(" not in installer:
            problems.append("%s: GNInstallThrowTracer() does not install anything" % THROW)
        guard_at = installer.find("netsInstalled > 0")
        rebind_at = installer.find("GNRebindSymbolInAppImages(")
        if guard_at >= 0 and rebind_at >= 0 and guard_at > rebind_at:
            problems.append("%s: the auto-mode check comes after the rebinding" % THROW)

    # 5. the experiment ladder's decisions must come from the file the test runs.
    #
    #    The state machine moved into src/GNExperimentLadder.h precisely so that
    #    scripts/experiment_ladder_test.c executes the same code the dylib ships.
    #    If GNExperimentResolve() ever grows its own copy of the logic, the test
    #    stops covering what runs - which is the failure mode this check exists
    #    for, not a style preference.
    ladder = read(root, LADDER)
    resolve = function_body(support, "static int GNExperimentResolve(")
    if not resolve:
        problems.append("%s: GNExperimentResolve() not found" % SUPPORT)
    else:
        if "GNExperimentNext(" not in resolve:
            problems.append("%s: GNExperimentResolve() no longer calls GNExperimentNext() - the "
                            "state machine that the test executes is no longer the one that "
                            "runs" % SUPPORT)
    if '#include "GNExperimentLadder.h"' not in support:
        problems.append("%s: GNExperimentLadder.h is not included" % SUPPORT)
    if "static inline GNExperimentState GNExperimentNext(" not in ladder:
        problems.append("%s: GNExperimentNext() is missing" % LADDER)
    for state in ("GNExperimentWon", "GNExperimentExhausted"):
        if state not in ladder:
            problems.append("%s: the ladder has no %s state - it would keep changing "
                            "configuration forever" % (LADDER, state))
    if "void GNExperimentNoteSurvived(void)" not in support:
        problems.append("%s: GNExperimentNoteSurvived() is missing" % SUPPORT)

    test = pathlib.Path(root) / TEST_LADDER
    if not test.exists():
        problems.append("%s: missing - the state machine is not executed anywhere" % TEST_LADDER)
    else:
        body = test.read_text(encoding="utf-8")
        if 'src/GNExperimentLadder.h' not in body:
            problems.append("%s: does not include src/GNExperimentLadder.h, so it tests a copy "
                            "instead of the shipped logic" % TEST_LADDER)

    return problems


MUTATIONS = [
    # (file, find, replace, what the check should say)
    (SUPPORT,
     "        if (GNPreviousLaunchWasEarly() && level > 0) {",
     "        if (GNPhaseIsEarly(GNReadTrimmed(GNStatePath())) && level > 0) {",
     "reads the state file again"),
    (GUARD,
     "        GNGuardInstallBoundaryNet();\n",
     "\n",
     "does not install the UIKit boundary net"),
    (THROW,
     "    if (gRealObjcExceptionThrow) gRealObjcExceptionThrow(exception);",
     "    // swallowed",
     "never calls the saved objc_exception_throw"),
    (SUPPORT,
     'if (GNCFG(@"AutoBisect", YES) && !GNExperimentControlsRunLevel()) {',
     'if (GNCFG(@"AutoBisect", YES)) {',
     "drops a level while the experiment ladder is running"),
    (SUPPORT,
     '    if (GNExperimentControlsRunLevel()) {\n        GNLogC("auto-bisect: not moving',
     '    if (NO) {\n        GNLogC("auto-bisect: not moving',
     "GNDropRunLevel() can move the level"),
    (THROW,
     'if (![mode isEqualToString:@"always"] && netsInstalled > 0) {',
     "if (NO) {",
     "rebinds even when the @try nets are live"),
    (SUPPORT,
     "    GNExperimentState next = GNExperimentNext(stored, storedValid,",
     "    GNExperimentState next = stored; (void)GNExperimentNext; (void)(",
     "no longer calls GNExperimentNext"),
]


def selftest():
    failures = 0
    for index, (relative, find, replace, expected) in enumerate(MUTATIONS, 1):
        with tempfile.TemporaryDirectory() as tmp:
            for name in (SUPPORT, GUARD, THROW, LADDER, TEST_LADDER):
                target = pathlib.Path(tmp) / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(pathlib.Path(ROOT) / name, target)

            path = pathlib.Path(tmp) / relative
            text = path.read_text(encoding="utf-8")
            if find not in text:
                print("mutation %d: could not apply - text not found in %s" % (index, relative))
                failures += 1
                continue
            path.write_text(text.replace(find, replace, 1), encoding="utf-8")

            problems = check(tmp)
            if not problems:
                print("mutation %d: NOT CAUGHT - %s" % (index, expected))
                failures += 1
            elif not any(expected in problem for problem in problems):
                print("mutation %d: caught, but not for the stated reason (%s):"
                      % (index, expected))
                for problem in problems:
                    print("    %s" % problem)
                failures += 1
            else:
                print("mutation %d: caught - %s" % (index, expected))

    if failures:
        sys.stderr.write("error: %d mutation(s) went undetected - the check is theatre\n"
                         % failures)
        return 1
    print("ok: all %d mutations were caught, each for its stated reason" % len(MUTATIONS))
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()

    problems = check(ROOT)
    if problems:
        sys.stderr.write("error: v11 invariant violated:\n")
        for problem in problems:
            sys.stderr.write("  %s\n" % problem)
        return 1
    print("ok: ladder uses the captured phase, boundary net present, tracer is a tap, "
          "tracer opt-in, experiment ladder can settle")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
