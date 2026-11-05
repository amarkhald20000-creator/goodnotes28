#!/usr/bin/env python3
"""v12_lint.py - the invariants that keep v12 inert.

Every check below exists because a previous build broke exactly this, and every
one of them is cheap to violate by accident while "just adding a small fix".
`--selftest` copies the tree, mutates it once per rule, and requires every rule
to fire for its own reason - a check that cannot fail is not a check.

  boot-first            the constructor's first statement is GNBoot(), so the
                        log exists before anything can throw or hang.

  beacon-foundation-free
                        GNBeacon.m sends no Objective-C message. It runs during
                        dyld init; Foundation is a liability there, and v11 lost
                        every log line to it.

  beacon-redundant      the beacon writes to more than one path and fsyncs.
                        "no log file" was the symptom that cost three builds.

  observe-default       ObserveOnly is true in config/GNUnlock.plist. v12 is
                        inert unless someone turns the hooks back on.

  no-behaviour-hooks    with ObserveOnly true the constructor must not touch
                        UIApplication, the launch guard, the run ladder or the
                        container fallbacks.

  appgroup-off          ResignFix.AppGroupFallback is false. It was inventing an
                        empty app group container, which is the single most
                        likely way our own code could have caused the crash.

  guard-off             GuardEnabled is false: no delegate wrapper, no private
                        UIKit selector, no abort rebinding by default.

  runlevel-zero         RunLevel is 0, so even in full mode nothing installs
                        until the launch crash is understood.

  init-swizzle-retained the one init-family swizzle in the tree carries
                        ns_returns_retained. ARC consumes +1 from an init
                        selector; v7 broke -[NSUserDefaults initWithSuiteName:]
                        by ignoring this.

  legacy-unreachable    the constructor only reaches GNRunLegacyMode() after the
                        observe early return, and that return is still there.
                        This is v12's whole claim: the hook stack is compiled in
                        but cannot run with the shipped config.

  legacy-guard-first    inside GNRunLegacyMode() the launch guard is installed
                        before the run level gate is read, level 0 included.
                        Forensics are not part of the bisect ladder: moving the
                        guard below the gate silently makes a level 0 crash as
                        opaque as the crash the guard exists to explain.

  private-api-dlsym     a symbol that exists in the framework at run time but not
                        in the public SDK may be named only inside a quoted dlsym
                        name. v12.1 called SecTaskCreateFromSelf() directly and
                        the macOS front end rejected src/GNProbe.m with ten
                        errors before anything compiled. An extern prototype is
                        not an escape either: those symbols are absent from
                        Security.tbd, so that spelling fails at link time with
                        "Undefined symbols". The one permitted home is
                        src/GNPrivateSecTask.m, via dlsym.

  stub-no-private-api   the stub SDK must not declare anything the public SDK
                        does not. v12.1's pre-flight was green because
                        scripts/stubsdk/include/Security/Security.h declared the
                        private SecTask family, so stubcheck.sh type checked a
                        header the project had authored rather than the one CI
                        compiles against. A stub more permissive than the SDK is
                        not a test, it is a false green.

  cloudkit-guard-narrow the CloudKit suppressor decides by exception *name*
                        against an allow list. Delete that comparison and it
                        becomes a blanket suppressor that hides every exception
                        in the app instead of the one malformed entitlement.

  cloudkit-guard-before-observe
                        the constructor installs the CloudKit guard before the
                        observe early return, so it runs in the shipped default.
                        Behind the gate it would be dead code in exactly the
                        configuration the crash happens in.

  cloudkit-no-init-hook -[NSException initWithName:reason:userInfo:] may not be
                        used to suppress anything. It only constructs; returning
                        nil there hands a nil object to the raise path and
                        destroys every exception object in the process, our own
                        forensics included. The interception point is -raise.

  cloudkit-guard-default-on
                        CloudKitGuard is true in config/GNUnlock.plist. v13 named
                        the crash; a default that stops naming it again is a
                        regression, not a preference.

  interpose-weak-import src/GNEntitlementRepairInterpose.m is the only file that
                        may name the private SecTask symbols, because dyld's
                        interposition table needs their addresses and an address
                        cannot come from a string. Every name there must be
                        declared weak_import: those symbols are not in
                        Security.tbd, so a plain extern reference compiles and
                        then fails at link time - the v12.1 defect again. A weak
                        import that does not resolve reads back as 0 and the log
                        says so instead of pretending the repair is live.

  interpose-section     the table must actually live in __DATA,__interpose. A
                        table in any other section is a static array nobody
                        reads, i.e. a repair that silently does nothing.

  entitlement-repair-before-observe
                        the constructor installs the repair before the observe
                        early return. Behind that gate it is dead code in exactly
                        the configuration the crash happens in.

  entitlement-repair-type-only
                        the repair consults CFGetTypeID against the type Apple
                        requires before it substitutes anything. Delete that
                        comparison and the module becomes an entitlement
                        minter - a different change with different consequences,
                        and not the one the log asked for.

  entitlement-repair-default-on
                        EntitlementRepair is true in config/GNUnlock.plist, for
                        the same reason as the CloudKit guard: the shipped
                        default is the configuration the crash happens in.

  ci-no-line-numbers    no CI step may locate a statement in a source file by
                        line number. v12's build failed before it compiled
                        because the workflow still grepped the old entry point
                        for GNInstallLaunchGuard() and int level = GNRunLevel();
                        - both moved to GNLegacy.m. A check that restates an
                        internal layout in YAML breaks on every refactor and
                        proves nothing; structural rules belong here, where
                        --selftest can prove they still fire.

  plist-expect-single-source
                        the shipped defaults have exactly one home,
                        scripts/plist_expect.py, and scripts/build.sh and the
                        workflows call it instead of restating the keys. v23
                        died here: this lint said ThrowSwallowAtSite ships
                        true, the copy in the workflow still said false, and
                        the job failed before a line compiled.

  plist-expect-mirrors-lint
                        scripts/plist_expect.py pins the same defaults this
                        lint enforces, and the two are compared. A key one of
                        them knows and the other does not is the v23 failure
                        one release early.

  plist-expect-version  ConfigVersion in scripts/plist_expect.py equals
                        GN_UNLOCK_VERSION in src/GNBeacon.h, so a build cannot
                        ship v24 defaults under a v23 log line.
"""

import pathlib
import plistlib
import re
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

ENTRY = "src/GNUnlock.m"
BEACON = "src/GNBeacon.m"
FORENSICS = "src/GNExcForensics.m"
CLOUDKIT = "src/GNCloudKitGuard.m"
REPAIR = "src/GNEntitlementRepair.m"
INTERPOSE = "src/GNEntitlementRepairInterpose.m"
SLOTWALK = "src/GNSlotWalk.h"
SLOTSCAN = "src/GNSlotScan.m"
SLOTHOOK = "src/GNEntitlementSlot.m"
AUDIT = "src/GNReadAudit.m"
SLOTWALK_TEST = "scripts/slotwalk_test.c"
LEGACY = "src/GNLegacy.m"
PLIST = "config/GNUnlock.plist"

# The defaults this lint enforces on its own. scripts/plist_expect.py pins the
# same keys for the two consumers that are not this file, and the
# plist-expect-mirrors-lint rule refuses a build where the two disagree - the
# exact contradiction that failed v23.
LINT_PINS = {
    "ObserveOnly": True,
    "GuardEnabled": False,
    "RunLevel": 0,
    "AutoBisect": False,
    "AllowCodePatching": False,
    "CloudKitGuard": True,
    "EntitlementRepair": True,
    "DlsymTap": True,
    "ThrowTap": True,
    "CloudKitStub": True,
    "ThrowSwallowAtSite": True,
    "ThrowSwallowForce": True,
    "ThrowSwallowReturnNil": True,
    # v25: the resolver and the slot walk are the two halves of the mechanism
    # that replaced the link-time table, and both have a rule above.
    "CloudKitSymbolQuarantine": True,
    "CloudKitSymbolRebind": True,
}
WORKFLOWS = ".github/workflows"

# Symbols that are exported by Security.framework at run time but declared by no
# public header. Naming one of them outside a quoted dlsym name is the v12.1
# defect; see the private-api-dlsym rule at the top.
PRIVATE_SYMBOLS = (
    "SecTaskRef",
    "SecTaskCreateFromSelf",
    "SecTaskCreateWithAuditToken",
    "SecTaskCopyValueForEntitlement",
    "SecTaskCopyValuesForEntitlements",
    "SecTaskCopySigningIdentifier",
)


def read(root, relative):
    path = pathlib.Path(root) / relative
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def strip_comments(text):
    """Drops // and /* */ comments so a rule cannot be satisfied by prose."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    return text


def private_symbol_hits(text, allow_quoted):
    """Lines naming a private symbol, optionally tolerating a quoted dlsym name.

    `allow_quoted` is what separates the two rules that share this scanner: in
    src/ the name is legal only as the string handed to dlsym, while in the stub
    SDK it is not legal at all.
    """
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        # Every double-quoted literal on the line. A name inside one of these is
        # text, not a declaration: it compiles everywhere and it links nowhere
        # by itself. Everything outside them is an identifier.
        literals = re.findall(r'@?"(?:[^"\\]|\\.)*"', line)
        for symbol in PRIVATE_SYMBOLS:
            pattern = r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(symbol)
            if not re.search(pattern, line):
                continue
            if allow_quoted and any(re.search(pattern, literal) for literal in literals):
                continue
            hits.append((number, symbol, line.strip()))
    return hits


def function_body(text, marker):
    """The braces-balanced body of the function named by marker, comments stripped."""
    text = strip_comments(text)
    start = text.find(marker)
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
                return text[brace + 1:index]
    return ""


def constructor_body(text):
    """The body of GNUnlockEntry(), comments stripped."""
    return function_body(text, "static void GNUnlockEntry(void)")


def config(root):
    path = pathlib.Path(root) / PLIST
    if not path.exists():
        return None
    with open(path, "rb") as handle:
        return plistlib.load(handle)


def check(root):
    problems = []

    entry = read(root, ENTRY)
    beacon = read(root, BEACON)
    forensics = read(root, FORENSICS)
    cfg = config(root)

    # -- the constructor opens the log before it does anything else ----------
    body = constructor_body(entry)
    if not body:
        problems.append("boot-first: GNUnlockEntry() not found in %s" % ENTRY)
    else:
        code = [line.strip() for line in body.splitlines() if line.strip()]
        if not code or code[0] != "GNBoot();":
            problems.append(
                "boot-first: the first statement of GNUnlockEntry() must be GNBoot(); "
                "found %r" % (code[0] if code else "(empty)"))

    # -- the beacon must not depend on Foundation ---------------------------
    stub = strip_comments(beacon)
    for needle in ("Foundation/Foundation.h", "UIKit/UIKit.h", "NSString", "NSFileManager"):
        if needle in stub:
            problems.append(
                "beacon-foundation-free: %s references %s; the beacon runs during dyld "
                "init and must send no Objective-C message" % (BEACON, needle))
    if re.search(r"@\"", stub) or re.search(r"@\[\s*\]", stub):
        problems.append("beacon-foundation-free: %s contains Objective-C literals" % BEACON)

    # -- the beacon must be redundant and durable ---------------------------
    sink_calls = len(re.findall(r"GNOpenSink\(", strip_comments(beacon)))
    if sink_calls < 3:      # definition + at least two call sites
        problems.append(
            "beacon-redundant: %s has %d GNOpenSink reference(s); the beacon must try "
            "several paths, not one" % (BEACON, sink_calls))
    if "fsync(" not in strip_comments(beacon):
        problems.append("beacon-redundant: %s does not fsync; a buffered log is empty "
                        "exactly when the crash happens" % BEACON)

    # -- defaults -----------------------------------------------------------
    if cfg is None:
        problems.append("observe-default: %s is missing or does not parse" % PLIST)
        cfg = {}

    if cfg.get("ObserveOnly") is not True:
        problems.append("observe-default: ObserveOnly must be true; v12 is inert by default")

    resign = cfg.get("ResignFix") or {}
    if resign.get("AppGroupFallback") is not False:
        problems.append("appgroup-off: ResignFix.AppGroupFallback must be false; inventing an "
                        "empty app group container is a behaviour change")

    if cfg.get("GuardEnabled") is not False:
        problems.append("guard-off: GuardEnabled must be false by default")

    if cfg.get("RunLevel") != 0:
        problems.append("runlevel-zero: RunLevel must be 0, found %r" % (cfg.get("RunLevel"),))

    if cfg.get("AutoBisect") is not False:
        problems.append("runlevel-zero: AutoBisect must be false; the ladder needs a "
                        "successful launch to learn anything, and we do not have one")

    # -- with ObserveOnly on, the constructor installs nothing --------------
    plain = strip_comments(entry)
    for needle in ("UIApplication",
                   "sharedApplication",
                   "GNInstallLaunchGuard(",
                   "_handleDelegateCallbacks",
                   "GNRunLevel(",
                   "GNInstallResignContainerFixes(",
                   "GNInstallDataHooks("):
        if needle in plain:
            problems.append(
                "no-behaviour-hooks: %s mentions %s; the observe path must not reach the "
                "launch guard, the ladder or the container fallbacks" % (ENTRY, needle))

    # -- v12's claim: the legacy stack is compiled in but cannot run ---------
    legacy = read(root, LEGACY)
    if body:
        observe_at = body.find("if (observe)")
        legacy_at = body.find("GNRunLegacyMode()")
        if legacy_at < 0:
            problems.append(
                "legacy-unreachable: GNUnlockEntry() never calls GNRunLegacyMode(), so full mode "
                "is unreachable even with ObserveOnly off")
        elif observe_at < 0:
            problems.append(
                "legacy-unreachable: the observe gate is gone from GNUnlockEntry(); the hook "
                "stack would install on every launch")
        elif observe_at > legacy_at:
            problems.append(
                "legacy-unreachable: GNRunLegacyMode() is called before the observe gate; the "
                "hook stack has to stay behind it")
        elif "return;" not in body[observe_at:legacy_at]:
            problems.append(
                "legacy-unreachable: the observe branch no longer returns, so the hook stack "
                "runs with ObserveOnly true")

    # -- the guard is installed before the gate, in the file that still does it
    legacy_body = function_body(legacy, "void GNRunLegacyMode(void)")
    if not legacy_body:
        problems.append("legacy-guard-first: GNRunLegacyMode() not found in %s" % LEGACY)
    else:
        guard_at = legacy_body.find("GNInstallLaunchGuard();")
        gate_at = legacy_body.find("GNRunLevel();")
        if guard_at < 0:
            problems.append(
                "legacy-guard-first: GNRunLegacyMode() no longer installs the launch guard")
        elif gate_at < 0:
            problems.append("legacy-guard-first: GNRunLegacyMode() no longer reads the run level")
        elif guard_at > gate_at:
            problems.append(
                "legacy-guard-first: the launch guard is installed after the run level gate - "
                "a level 0 crash would stay as opaque as the crash it should explain")

    # -- the CloudKit guard stays narrow, early and installed ---------------
    cloudkit = read(root, CLOUDKIT)
    cloudkit_plain = strip_comments(cloudkit)
    if not cloudkit_plain:
        problems.append("cloudkit-guard-narrow: %s is missing or empty" % CLOUDKIT)
    elif "containsObject:name" not in cloudkit_plain:
        problems.append(
            "cloudkit-guard-narrow: %s no longer filters on an exception-name allow list. "
            "Without that comparison this becomes a blanket suppressor and every defect in "
            "the app gets swallowed along with the CKException" % CLOUDKIT)

    if "initWithName:" in cloudkit_plain:
        problems.append(
            "cloudkit-no-init-hook: %s names initWithName:. Constructing an exception is not "
            "raising one: returning nil from the initialiser hands a nil object to the raise "
            "path and wipes out every exception object in the process. Suppress at "
            "-[NSException raise]" % CLOUDKIT)

    if body:
        observe_first = body.find("if (observe)")
        guard_at = body.find("GNInstallCloudKitGuard(")
        if guard_at < 0:
            problems.append(
                "cloudkit-guard-before-observe: GNUnlockEntry() no longer installs the CloudKit "
                "guard; the malformed-entitlement CKException kills the launch again")
        elif observe_first >= 0 and guard_at > observe_first:
            problems.append(
                "cloudkit-guard-before-observe: the CloudKit guard is installed after the "
                "observe early return, so it never runs in the shipped default configuration")

    if cfg.get("CloudKitGuard") is not True:
        problems.append(
            "cloudkit-guard-default-on: CloudKitGuard must be true; v13 named the launch crash "
            "and the default has to keep surviving it")

    # -- v15: the interpose table, and the rule that keeps it a type repair --
    interpose = strip_comments(read(root, INTERPOSE))
    if not interpose.strip():
        problems.append(
            "interpose-section: %s is missing or empty. Without the table dyld has "
            "nothing to apply and the repair never runs" % INTERPOSE)
    else:
        if "__DATA,__interpose" not in interpose:
            problems.append(
                "interpose-section: %s no longer puts its table in __DATA,__interpose. "
                "In any other section it is a static array nobody reads" % INTERPOSE)
        for symbol in PRIVATE_SYMBOLS:
            hit = re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(symbol))
            lines = [line for line in interpose.splitlines() if hit.search(line)]
            if not lines:
                continue
            if not any("weak_import" in line for line in lines):
                problems.append(
                    "interpose-weak-import: %s names %s without weak_import. It is not "
                    "in Security.tbd, so a plain extern reference links to nothing and "
                    "the macOS job fails with Undefined symbols - which is v12.1 all "
                    "over again" % (INTERPOSE, symbol))

    # -- the type gate lives where the CF type is read (v18 moved it out of the
    #    predicate and into GNPlanValueKind, so the comparison happens once, at the
    #    boundary, instead of being restated per branch) ---------------------
    repair = strip_comments(read(root, REPAIR))
    kind_mapper = function_body(repair, "static void GNPlanValueKind(")
    repair_predicate = function_body(repair, "static BOOL GNValueIsCorrect(")
    if not repair.strip():
        problems.append("entitlement-repair-type-only: %s is missing or empty" % REPAIR)
    elif not kind_mapper:
        problems.append(
            "entitlement-repair-type-only: GNPlanValueKind() not found in %s. It is the "
            "one place a CF type becomes a decision input, and the gate that keeps this "
            "a type repair" % REPAIR)
    else:
        for expression in ("CFGetTypeID(value) == CFArrayGetTypeID()",
                           "CFGetTypeID(value) == CFStringGetTypeID()"):
            if expression not in kind_mapper:
                problems.append(
                    "entitlement-repair-type-only: GNPlanValueKind() in %s no longer "
                    "checks %s before a value is substituted. Without that comparison "
                    "this stops being a type repair and starts minting entitlements the "
                    "signature does not carry" % (REPAIR, expression))
        if not repair_predicate:
            problems.append(
                "entitlement-repair-type-only: GNValueIsCorrect() not found in %s. It is "
                "the gate the substitution is made behind" % REPAIR)
        elif "GNRPlanRepair(" not in repair_predicate:
            problems.append(
                "entitlement-repair-type-only: GNValueIsCorrect() in %s no longer asks "
                "GNRPlanRepair(). The decision would be back in line, untested, which is "
                "exactly the shape v17 shipped" % REPAIR)

    # -- v18: the decision is the tested one, and the test runs --------------
    #
    #  v17 answered a rule that wants an array of strings with a bare string. The
    #  build was green, the device ran the replacement, and the log said the
    #  interception was live - because nothing ever compared the answer against the
    #  rule. The decision is now pure C (src/GNRepairPolicy.h), the repair file may
    #  not restate it, and the test that executes it has to run in both places the
    #  project builds.
    policy = strip_comments(read(root, "src/GNRepairPolicy.h"))
    policy_test = read(root, "scripts/repair_policy_test.c")
    if not policy.strip():
        problems.append(
            "repair-plan-from-policy: src/GNRepairPolicy.h is missing. The shape of a "
            "repaired value would be decided inside the CoreFoundation code again, where "
            "no test can execute it")
    elif "GNRPlanRepair(" not in policy:
        problems.append(
            "repair-plan-from-policy: src/GNRepairPolicy.h no longer defines "
            "GNRPlanRepair()")
    if not policy_test.strip():
        problems.append(
            "repair-policy-host-tested: scripts/repair_policy_test.c is missing. It is the "
            "only test that can fail for the v17 defect - a repair whose type does not "
            "match the rule - before a device launch")
    else:
        for needle, why in (
                ("GNRRunAll(", "it no longer enumerates every combination of inputs"),
                ("plan.produce == wanted", "it no longer asserts that a repair produces the kind the schema requires"),
                ("--selfcheck", "it can no longer prove that its own assertions reject the v17 shape"),
        ):
            if needle not in policy_test:
                problems.append(
                    "repair-policy-host-tested: scripts/repair_policy_test.c lost '%s' - %s"
                    % (needle, why))

    if repair.count("GNRPlanRepair(rule->expect") < 1:
        problems.append(
            "repair-plan-from-policy: %s no longer asks the policy with the rule's "
            "expected type. Any other argument lets the answer's shape drift from the "
            "schema, which is the v17 defect" % REPAIR)

    stubcheck = read(root, "scripts/stubcheck.sh")
    for needle, why in (
            ("repair_policy_test", "it no longer compiles the policy test"),
            ("--selfcheck", "it no longer runs the selfcheck that proves the assertions "
                            "reject the v17 shape"),
    ):
        if needle not in stubcheck:
            problems.append(
                "repair-policy-host-tested: scripts/stubcheck.sh: %s, so the one "
                "executable check on the repair's shape is back to being a launch on a "
                "device" % why)

    workflow = read(root, WORKFLOWS + "/build-dylib.yml")
    for needle, why in (
            ("repair_policy_test", "the workflow no longer runs the policy test"),
            ("repair_policy_test --selfcheck", "the workflow no longer runs its selfcheck"),
    ):
        if needle not in workflow:
            problems.append(
                "repair-policy-host-tested: %s before it builds" % why)

    # -- v18: the three new doors --------------------------------------------
    dlsym_tap = strip_comments(read(root, "src/GNDlsymTap.m"))
    if not dlsym_tap.strip():
        problems.append(
            "dlsym-tap-covers-lookup: src/GNDlsymTap.m is missing. v17 measured zero "
            "slots for the plural SecTask read; the lookup is the only other place that "
            "read can come from")
    else:
        resolve_at = dlsym_tap.find('dlsym(RTLD_DEFAULT, "dlsym")')
        rewrite_at = dlsym_tap.find('GNSlotRebindSymbol("dlsym"')
        if resolve_at < 0:
            problems.append(
                "dlsym-tap-resolves-first: src/GNDlsymTap.m no longer resolves the real "
                "dlsym")
        elif rewrite_at < 0:
            problems.append(
                "dlsym-tap-resolves-first: src/GNDlsymTap.m no longer rewrites any slot")
        elif resolve_at > rewrite_at:
            problems.append(
                "dlsym-tap-resolves-first: src/GNDlsymTap.m rewrites dlsym's slots "
                "before it has the real pointer. The tap would resolve through itself "
                "and recurse until the stack ends, during app initialisation")
        for needle in ('"SecTaskCopyValuesForEntitlements"',
                       '"SecCodeCopySigningInformation"',
                       '"SecTaskCopyValueForEntitlement"'):
            if needle not in dlsym_tap:
                problems.append(
                    "dlsym-tap-covers-lookup: src/GNDlsymTap.m no longer answers %s - a "
                    "lookup-resolved read of that key stays unrepaired" % needle)

    slot_hook = strip_comments(read(root, SLOTHOOK))
    if "GNThrowTapActivate(gGNSlotTargets[i])" not in slot_hook:
        problems.append(
            "throw-tap-armed: the slot installer no longer hands the throw tap the real "
            "objc_exception_throw it resolved. The tap would call a null pointer on the "
            "first exception, or exit the process if it could not")
    if '"objc_exception_throw"' not in slot_hook:
        problems.append(
            "throw-tap-armed: objc_exception_throw is no longer among the watched "
            "symbols, so an exception thrown from a shared cache image is anonymous again")

    if "static void GNSlotRunPluralSelfTest(" not in slot_hook or \
       "GNSlotRunPluralSelfTest(task, key);" not in slot_hook:
        problems.append(
            "slot-selftest-plural: the launch-time self-test no longer measures the "
            "plural read. v17 printed 'interception is LIVE' for the singular read while "
            "the launch still died, because the plural one was never measured")

    for key, why in (("DlsymTap", "the lookup tap"), ("ThrowTap", "the throw tap")):
        if cfg.get(key) is not True:
            problems.append(
                "%s-default-on: %s must be true in config/GNUnlock.plist. The shipped "
                "default is the configuration the crash happens in"
                % ("dlsym-tap" if key == "DlsymTap" else "throw-tap", why))

    inst = body or ""
    tap_at = inst.find("GNInstallDlsymTap(")
    watch_at = inst.find("if (observe)")
    if tap_at < 0:
        problems.append(
            "dlsym-tap-before-observe: GNUnlockEntry() no longer installs the lookup tap")
    elif watch_at >= 0 and tap_at > watch_at:
        problems.append(
            "dlsym-tap-before-observe: the lookup tap is installed after the observe "
            "early return, so it never runs in the shipped default configuration")

    if body:
        observe_first = body.find("if (observe)")
        repair_at = body.find("GNInstallEntitlementRepair(")
        if repair_at < 0:
            problems.append(
                "entitlement-repair-before-observe: GNUnlockEntry() no longer installs "
                "the entitlement repair; a malformed iCloud value kills the launch again")
        elif observe_first >= 0 and repair_at > observe_first:
            problems.append(
                "entitlement-repair-before-observe: the repair is installed after the "
                "observe early return, so it never runs in the shipped default "
                "configuration")

    if cfg.get("EntitlementRepair") is not True:
        problems.append(
            "entitlement-repair-default-on: EntitlementRepair must be true. The shipped "
            "default is the configuration the crash happens in, so a default that is "
            "off is dead code")


    # -- v16: the slot rewrite, and the proof it writes only what it can -----
    #
    #  These exist because v15's log said "armed" while nothing was intercepted.
    #  Every rule below is one of the three things that could have made that true
    #  again: writing a code page (fatal on this signature), writing a slot whose
    #  signature was guessed (a fault on the next call), or shipping without the
    #  measurement that tells the two apart.
    slotwalk = strip_comments(read(root, SLOTWALK))
    if not slotwalk.strip():
        problems.append(
            "slotwalk-pure-header: %s is missing or empty. It is the half of the "
            "rebinder scripts/slotwalk_test.c can execute on the host" % SLOTWALK)
    else:
        for line in slotwalk.splitlines():
            stripped = line.strip()
            if not stripped.startswith(("#include", "#import")):
                continue
            header = stripped.split(None, 1)[1].strip()
            if any(name in header for name in
                   ("stdbool.h", "stddef.h", "stdint.h", "string.h")):
                continue
            problems.append(
                "slotwalk-pure-header: %s includes %s. With a framework header in the "
                "walk it can no longer be compiled and run on the host, and the "
                "section-table bounds checks stop being executed before they are "
                "trusted" % (SLOTWALK, header))

    slotscan = strip_comments(read(root, SLOTSCAN))
    slothook = strip_comments(read(root, SLOTHOOK))
    for name, text in (("slot-hook-data-only", slotscan), ("slot-hook-data-only", slothook)):
        if not text.strip():
            continue
        for forbidden in ("GNPatchCodeBytes(", "GNInlineHookSymbol(",
                          "sys_icache_invalidate("):
            if forbidden in text:
                problems.append(
                    "slot-hook-data-only: a v16 module calls %s. A write to a code page "
                    "on a Distribution signature is not risky, it is the CODESIGNING / "
                    "Invalid Page kill this project already lost a launch to; the slot "
                    "route exists precisely so no code page is touched" % forbidden)

    readrange = function_body(slotwalk, "static inline GNSlotStats GNWRebindSlotRange(")
    if not readrange:
        problems.append(
            "slot-refuse-does-not-write: GNWRebindSlotRange() not found in %s" % SLOTWALK)
    else:
        refuse_at = readrange.find("if (value == 0) {")
        write_at = readrange.find("ops->write(")
        # The refuse branch has no nested braces, so its first closing brace ends
        # it: taking a fixed window instead would pick up the `continue` of the
        # *next* branch and pass a mutation that removed this one.
        refuse_end = readrange.find("}", refuse_at) if refuse_at >= 0 else -1
        refuse_block = readrange[refuse_at:refuse_end] if refuse_end > refuse_at else ""
        if refuse_at < 0:
            problems.append(
                "slot-refuse-does-not-write: GNWRebindSlotRange() in %s no longer stops "
                "on a refused slot. moveTo() returning 0 means the signature could not "
                "be reproduced; writing anything there turns a missed hook into a fault "
                "on the next call into that slot" % SLOTWALK)
        elif "stats.refused++" not in refuse_block or "continue;" not in refuse_block:
            problems.append(
                "slot-refuse-does-not-write: the refusal branch in GNWRebindSlotRange() "
                "in %s no longer counts the slot and continues past it, so a slot whose "
                "signature could not be reproduced falls through to the write" % SLOTWALK)
        elif write_at < 0 or refuse_at > write_at:
            problems.append(
                "slot-refuse-does-not-write: the refusal check sits after the write in "
                "GNWRebindSlotRange(), which is the same as not having it")

    rebind = strip_comments(read(root, "src/GNRebind.m"))
    move = function_body(rebind, "uintptr_t GNSlotMoveTo(uintptr_t raw, uintptr_t target")
    if not move:
        problems.append(
            "slot-proof-before-write: GNSlotMoveTo() not found in src/GNRebind.m. Without "
            "it a slot move is a guess")
    else:
        if "GNSignPointer(target, key, modifiers[index]) != raw" not in move:
            problems.append(
                "slot-proof-before-write: GNSlotMoveTo() in src/GNRebind.m no longer "
                "reproduces the bytes already in the slot before signing the "
                "replacement. That comparison is the whole proof: a wrong key or "
                "discriminator produces a slot the callee cannot authenticate")
        if "return 0;" not in move:
            problems.append(
                "slot-proof-before-write: GNSlotMoveTo() has no refusal path. A slot it "
                "cannot reproduce must be left untouched")

    if not slothook.strip():
        problems.append("slot-selftest-required: %s is missing or empty" % SLOTHOOK)
    else:
        install = function_body(slothook, "void GNInstallEntitlementSlotHook(NSDictionary *cfg)")
        if not install:
            problems.append(
                "slot-selftest-required: GNInstallEntitlementSlotHook() not found in %s"
                % SLOTHOOK)
        else:
            if "GNSlotRunSelfTest();" not in install:
                problems.append(
                    "slot-selftest-required: the installer no longer runs the self-test. "
                    "v15 shipped 'armed' as if it meant 'working'; the self-test is the "
                    "only thing that tells them apart")
        selftest = function_body(slothook, "static void GNSlotRunSelfTest(void)")
        if not selftest:
            problems.append("slot-selftest-two-paths: GNSlotRunSelfTest() not found")
        else:
            for call in ("GNPrivateSecTaskCopyEntitlement(", "GNEntitlementCallThroughImport("):
                if call not in selftest:
                    problems.append(
                        "slot-selftest-two-paths: the self-test in %s no longer calls %s. "
                        "Two calls that differ only in whether a binding is in the middle "
                        "is what makes the result mean anything" % (SLOTHOOK, call))
            if selftest.count("GNEntitlementRepairCount()") < 2 or "after > before" not in selftest:
                problems.append(
                    "slot-selftest-two-paths: the self-test no longer reads the repair "
                    "counter either side of the two calls and compares them, so a value "
                    "that happens to look repaired would be read as proof that our "
                    "replacement ran")

    if "static void GNOnImageAdded(" not in slotscan or \
       "_dyld_register_func_for_add_image(GNOnImageAdded)" not in slotscan:
        problems.append(
            "slot-add-image-watch: %s no longer rescans an image dyld adds later. "
            "CloudKit is dlopen'ed by the app after this dylib's constructor, so its "
            "slots do not exist at install time - the one image that matters most" % SLOTSCAN)

    if repair.count(")GNInterposeReal(") < 3:
        problems.append(
            "repair-dlsym-not-own-replacement: src/GNEntitlementRepair.m no longer resolves all "
            "three symbols through GNInterposeReal(). The call-through design assumes the "
            "resolved address is the real function and not this dylib's replacement; if that "
            "ever stops being true the replacement calls itself until the stack ends, during "
            "app initialisation")

    if body:
        observe_first = body.find("if (observe)")
        slot_at = body.find("GNInstallEntitlementSlotHook(")
        if slot_at < 0:
            problems.append(
                "slot-before-observe: GNUnlockEntry() no longer installs the slot rewrite")
        elif observe_first >= 0 and slot_at > observe_first:
            problems.append(
                "slot-before-observe: the slot rewrite is installed after the observe "
                "early return, so it never runs in the shipped default configuration")

    if cfg.get("EntitlementSlotRebind") is not True:
        problems.append(
            "slot-default-on: EntitlementSlotRebind must be true. The shipped default is "
            "the configuration the crash happens in")

    if cfg.get("EntitlementSlotSelfTest") is not True:
        problems.append(
            "slot-selftest-default-on: EntitlementSlotSelfTest must be true, or the next "
            "log cannot distinguish 'armed' from 'intercepted'")

    # -- v17: the real-image fixture belongs to the compiler ----------------
    #
    #  v16 asserted `stats.sections >= 5` against an object built by zig's clang,
    #  which emits a dozen __DWARF sections. The macOS runner builds the same
    #  fixture with Apple clang, whose object carries __text and __compact_unwind
    #  and nothing else, so the assertion failed on a walker that was correct: it
    #  was measuring the machine that wrote it. How many sections a fixture has is
    #  the compiler's business; the only count it can be checked against is its
    #  own, read back out of the file.
    walktest = strip_comments(read(root, SLOTWALK_TEST))
    if not walktest.strip():
        problems.append(
            "real-fixture-reads-the-file: %s is missing or empty. It is the only part "
            "of the slot walk that runs against real linker output" % SLOTWALK_TEST)
    else:
        if "CountSectionsRaw(" not in walktest:
            problems.append(
                "real-fixture-reads-the-file: %s no longer reads the fixture with its own "
                "parser, so what it compares against is not what the file declares"
                % SLOTWALK_TEST)
        if "CHECK(stats.sections == raw.sections," not in walktest:
            problems.append(
                "real-fixture-reads-the-file: the real-image check no longer compares the "
                "walker's section count with the count in the fixture. Any other "
                "comparison is a property of the compiler that produced it, and it will "
                "mean something different on the runner than it did locally")
        if "CHECK(stats.segments == raw.segments," not in walktest:
            problems.append(
                "real-fixture-reads-the-file: the real-image check no longer compares the "
                "walker's segment count with the fixture's")
        floor = re.search(r"stats\.(?:sections|segments)\s*>=\s*([2-9]|[1-9][0-9]+)", walktest)
        if floor:
            problems.append(
                "real-fixture-not-a-constant: %s asserts '%s'. A floor above one here is "
                "the shape of the fixture, not a property of the walker, and it is what "
                "made v16 fail on a runner whose compiler emitted fewer sections"
                % (SLOTWALK_TEST, floor.group(0).strip()))

    # -- a private symbol may only appear inside a quoted dlsym name --------
    src_root = pathlib.Path(root) / "src"
    if src_root.is_dir():
        for path in sorted(src_root.iterdir()):
            if path.suffix not in (".m", ".h"):
                continue
            # The interpose table is the documented exception: it needs the
            # addresses, and interpose-weak-import above is what keeps that
            # exception narrow. Everything else resolves through dlsym.
            if path.name == pathlib.Path(INTERPOSE).name:
                continue
            for number, symbol, line in private_symbol_hits(
                    strip_comments(read(root, "src/" + path.name)), allow_quoted=True):
                problems.append(
                    "private-api-dlsym: src/%s:%d names %s outside a quoted symbol name. "
                    "No public header declares it, so a declaration is a front-end error and "
                    "an extern prototype fails at link time (it is not in Security.tbd). "
                    "Resolve it once in src/GNPrivateSecTask.m and call the wrapper. Line: %s"
                    % (path.name, number, symbol, line[:80]))

    # -- the stub SDK has to fail where the real SDK fails ------------------
    stub_root = pathlib.Path(root) / "scripts/stubsdk"
    if stub_root.is_dir():
        for path in sorted(stub_root.rglob("*.h")):
            relative = str(path.relative_to(pathlib.Path(root)))
            for number, symbol, line in private_symbol_hits(
                    strip_comments(read(root, relative)), allow_quoted=False):
                problems.append(
                    "stub-no-private-api: %s:%d declares %s. The public SDK declares no such "
                    "symbol, so a stub that offers one turns a real front-end error into a "
                    "green pre-flight - which is exactly how v12.1 reached macOS with ten "
                    "errors in src/GNProbe.m." % (relative, number, symbol))

    # -- no CI step may pin a statement's line number -----------------------
    workflows = pathlib.Path(root) / WORKFLOWS
    if workflows.is_dir():
        for path in sorted(workflows.glob("*.y*ml")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"grep\s+-n(\s|$)", line):
                    problems.append(
                        "ci-no-line-numbers: %s:%d locates source by line number; where a "
                        "statement sits is not an invariant - assert the rule here instead"
                        % (path.relative_to(root), number))

    # -- v19: the number that decides the next step must be attributable ----
    #
    # v18's log could say "the replacement ran". It could not say whether the
    # process that died ever went through it, and those are different claims.
    # These five rules hold the difference in place: the audit is installed, it
    # records the caller rather than a bare count, it never resolves addresses on
    # the door's own path, the dylib's own probe does not pollute the count, and
    # the observe boundaries cannot swallow anything.
    audit = read(root, AUDIT)
    entry_plain = strip_comments(entry)

    if "GNReadAuditDump()" not in entry_plain:
        problems.append(
            "callsite-audit-wired: the constructor no longer dumps the call site audit. "
            "Without it the log goes back to saying 'the replacement ran' - which was "
            "already true in v18, in a process that died of the same exception.")

    doors = ["GNReadDoorSingle", "GNReadDoorBatch", "GNReadDoorSigningInfo"]
    repair_plain = strip_comments(read(root, REPAIR))
    for door in doors:
        if repair_plain.count("GNReadAuditNote(%s" % door) != 1:
            problems.append(
                "callsite-audit-wired: %s does not record exactly one GNReadAuditNote(%s, ...) "
                "call. A door without attribution is the v18 blind spot." % (REPAIR, door))

    # The two functions that run on the door's own path - i.e. inside CloudKit's
    # call, during dyld init - may record an address but must not resolve one.
    # Resolution is dladdr, and this project has already lost a launch to work
    # done on that path. The address to resolve is in GNReadSiteDescription(),
    # which only the dump calls.
    on_door_path = [
        "void GNReadAuditNote(GNReadDoor door, const void *caller, bool changed) {",
        "static void GNReadAuditRecord(GNReadDoor door, const void *caller, bool changed) {",
    ]
    for marker in on_door_path:
        body = function_body(audit, marker)
        if not body:
            problems.append(
                "callsite-audit-no-inline-resolve: %s not found in %s" % (marker.split("(")[0], AUDIT))
        elif "dladdr" in body:
            problems.append(
                "callsite-audit-no-inline-resolve: %s in %s resolves the caller inline. That is "
                "dladdr inside a call CloudKit makes during dyld init; record the raw address and "
                "resolve it in the dump." % (marker.split("(")[0].split()[-1], AUDIT))
    if "dladdr" not in strip_comments(audit):
        problems.append(
            "callsite-audit-no-inline-resolve: %s never resolves a caller, so the audit can count "
            "calls but cannot name one - and naming the caller is the whole point." % AUDIT)

    slot_plain = strip_comments(read(root, SLOTHOOK))
    if "GNReadAuditSuspend();" not in slot_plain or "GNReadAuditResume();" not in slot_plain:
        problems.append(
            "callsite-self-test-quiet: the slot self-test no longer suspends the audit. It "
            "calls a door on purpose, and counting that as a caller makes the one number "
            "that decides the next step an artefact of the measurement itself.")

    cloudkit_plain = strip_comments(read(root, CLOUDKIT))
    rethrown = cloudkit_plain.count("GNBoundaryObserveRethrow(site, exception)) @throw;")
    if rethrown < 6:
        problems.append(
            "boundary-observe-rethrows: only %d of the 6 boundary wrappers rethrow in observe "
            "mode. Observe mode is only safe because it cannot change what the app sees; a "
            "branch that forgets to rethrow turns instrumentation into a behaviour change."
            % rethrown)

    probe_body = function_body(cloudkit_plain, "static NSArray<NSDictionary *> *GNBoundaryProbeDefaults(void)")
    if not probe_body:
        problems.append("probe-never-swallows: GNBoundaryProbeDefaults() not found in %s"
                        % CLOUDKIT)
    elif probe_body.count('@"observe"') < 1 or probe_body.count('@"swallow"') > 0:
        problems.append(
            "probe-never-swallows: the probe list must be observe-only. CloudKit's container "
            "selectors return non-optional values in Swift, so a swallowed exception here "
            "becomes a Swift trap: the same crash with a worse log.")

    # -- the one init-family swizzle has to be ARC correct ------------------
    plain_forensics = strip_comments(forensics)
    if "initWithName:reason:userInfo:" in plain_forensics:
        if plain_forensics.count("ns_returns_retained") < 2:
            problems.append(
                "init-swizzle-retained: the init-family replacement in %s must be annotated "
                "ns_returns_retained on both the typedef and the function" % FORENSICS)

    # -- v20: the CloudKit substitute ------------------------------------
    # The whole design rests on one property: the original method is never
    # called. A version that kept a pointer to it and called it "on failure"
    # would be v19 again with more code - the throw would come out of a
    # dispatch_once whose gate is then owned by this thread for ever.
    stub_path = "src/GNCloudKitStub.m"
    try:
        stub_plain = strip_comments(read(root, stub_path))
    except Exception:
        stub_plain = ""
        problems.append("stub-subclass: %s is missing" % stub_path)

    if stub_plain:
        if ("objc_allocateClassPair(base, name, 0)" not in stub_plain
                or "class_createInstance(gStubContainerClass, 0)" not in stub_plain):
            problems.append(
                "stub-subclass: the substitute must be a runtime subclass of the real "
                "CKContainer with zeroed ivars (objc_allocateClassPair + class_createInstance). "
                "A proxy of another class fails isKindOfClass: and the Swift dynamic cast.")
        if "gOriginal" in stub_plain or "gSavedImplementation" in stub_plain:
            problems.append(
                "stub-never-calls-original: %s keeps a pointer to the replacement's "
                "predecessor. This design never calls it; keeping the pointer is how a later "
                "edit turns a substitution back into a container that re-enters CloudKit's "
                "dispatch_once." % stub_path)
        if "class_replaceMethod(" not in stub_plain:
            problems.append(
                "stub-subclass: no class_replaceMethod - nothing is actually substituted")
    if cfg.get("CloudKitStub") is not True:
        problems.append(
            "stub-reversible: CloudKitStub must default to true - v19 shipped a launch that "
            "dies of CKException, and the substitute is the only mechanism measured to reach "
            "the value CloudKit rejects")
    if cfg.get("CloudKitStubMode") not in ("noAccount", "nil", "observe"):
        problems.append(
            "stub-reversible: CloudKitStubMode must be one of noAccount / nil / observe")

    if stub_plain:
        if "GNCFG(@\"CloudKitStub\", YES)" not in stub_plain:
            problems.append(
                "stub-reversible: the substitute must be behind a config key so one plist "
                "edit restores the pre-v20 behaviour")

    # -- v20: the trampoline may only swallow what it can prove ----------
    tramp_path = "src/GNThrowTrampoline.m"
    try:
        tramp_plain = strip_comments(read(root, tramp_path))
    except Exception:
        tramp_plain = ""
        problems.append("trampoline-classifies: %s is missing" % tramp_path)

    if tramp_plain:
        if "__builtin_return_address(0)" not in tramp_plain:
            problems.append(
                "trampoline-classifies: the trampoline does not read its return address, so it "
                "cannot know what the code after the throwing call is")
        body = function_body(tramp_plain, "void *GNThrowTrampolineObject(void *exceptionRaw)")
        if not body:
            problems.append("trampoline-classifies: GNThrowTrampolineObject() not found")
        else:
            swallow_at = body.find("if (maySwallow)")
            decision_at = body.find("BOOL maySwallow")
            record_at = body.find("GNThrowTraceRecord(")
            decision = ""
            if decision_at >= 0:
                end = body.find(";", decision_at)
                decision = body[decision_at:end if end > 0 else len(body)]
            if swallow_at < 0 or "continuation.safe" not in decision:
                problems.append(
                    "trampoline-classifies: the swallow decision does not require "
                    "continuation.safe. Returning from objc_exception_throw is only survivable "
                    "where the next instruction is a return; everywhere else it resumes bytes "
                    "the compiler emitted as unreachable.")
            if record_at < 0 or (swallow_at >= 0 and record_at > swallow_at):
                problems.append(
                    "trampoline-records-first: the swallow happens before the record is "
                    "written. A swallow with no record is indistinguishable from a throw that "
                    "never happened, which is the one outcome this project cannot debug.")
            if "gnRealThrow" in body or "gRealThrow" not in body:
                problems.append(
                    "trampoline-rethrows: the fallthrough path must call the real "
                    "objc_exception_throw saved before any slot was rewritten")

    # -- v20: the read-surface sweep counts, it does not arm -------------
    try:
        scan_plain = strip_comments(read(root, "src/GNSlotScan.m"))
    except Exception:
        scan_plain = ""
        problems.append("read-surface-dry-run: src/GNSlotScan.m is missing")

    if scan_plain:
        # Both probes, each read as a body: v25 added the address-keyed one, and a
        # rule that only looked at the file could be satisfied by the other probe
        # still being correct.
        for marker in ("int32_t GNSlotProbeSymbol(const char *symbol, void **resolvedOut) {",
                       "int32_t GNSlotProbeAddress(uintptr_t target, int32_t *matchedOut) {"):
            probe_body = function_body(scan_plain, marker)
            if not probe_body:
                problems.append(
                    "read-surface-dry-run: %r not found in src/GNSlotScan.m" % marker)
                continue
            if "gSlotDryRun = true;" not in probe_body or \
                    "gSlotDryRun = false;" not in probe_body:
                problems.append(
                    "read-surface-dry-run: %r does not bracket its sweep with the dry run "
                    "flag, so a count-only probe would rewrite the slots it was only supposed "
                    "to measure" % marker.split("(")[0])
        move_body = function_body(scan_plain, "static uint64_t GNScanMoveTo(void *ctx, uint64_t raw, uint64_t target,")
        if not move_body or "gSlotDryRun" not in move_body:
            problems.append(
                "read-surface-dry-run: GNScanMoveTo() does not check the dry run flag - the "
                "writer is the only place that can guarantee a probe never writes")

    # -- v21: the throw gate covers the process, not three images --------
    try:
        throw_plain = strip_comments(read(root, "src/GNThrowInterpose.m"))
    except Exception:
        throw_plain = ""
        problems.append("interpose-table-read-by-dyld: src/GNThrowInterpose.m is missing")

    if throw_plain:
        if '__attribute__((section("__DATA,__interpose")))' not in throw_plain:
            problems.append(
                "interpose-table-read-by-dyld: GNThrowInterpose.m has no __DATA,__interpose "
                "section. That section is the entire mechanism: dyld applies it to every "
                "binding in the process, cache images included, and without it the replacement "
                "covers only the images a slot walk can attribute - the v20 result.")
        if "__attribute__((used))" not in throw_plain:
            problems.append(
                "interpose-table-read-by-dyld: the interpose table is not marked used. Nothing "
                "in this image refers to it, so the linker is entitled to drop it and the file "
                "becomes a no-op with a log line claiming the opposite")
        if "GNInterposeReal(" not in throw_plain:
            problems.append(
                "interpose-never-calls-by-name: the replacement does not resolve the real "
                "function through GNInterposeReal(). A call by name from this image is a "
                "binding, dyld has already redirected every binding to the replacement, and a "
                "bare dlsym is interposed too on the launches where dyld applies the table to "
                "its own lookups")
        if "dlsym(RTLD_DEFAULT" in throw_plain:
            problems.append(
                "interpose-original-one-place: GNThrowInterpose.m resolves the replaced symbol "
                "itself. dyld4 ends every lookup in interpose(state, resolved), so on a launch "
                "where that happens dlsym answers with this file's own replacement and the "
                "rethrow becomes unbounded recursion - v21 shipped exactly that path. The "
                "resolution belongs in GNInterposeReal.m, which refuses that answer and falls "
                "back to the tuple half")
        interposed_body = function_body(throw_plain, "static void GNThrowInterposed(id exception)")
        if not interposed_body:
            problems.append(
                "interpose-never-calls-by-name: GNThrowInterposed() not found, so nothing can be "
                "said about how it rethrows")
        elif "GNThrowInterposeReplacee(" in interposed_body:
            problems.append(
                "interpose-never-calls-by-name: the replacement calls the replacee identifier "
                "directly - that is recursion with extra steps, not a rethrow")
        if "&GNThrowInterposeReplacee" not in throw_plain or "_objc_exception_throw" not in throw_plain:
            problems.append(
                "interpose-table-read-by-dyld: the table does not name the replacee, or the "
                "replacee is not bound to _objc_exception_throw. dyld needs both halves of the "
                "pair to know what to replace, and a table with a null replacee installs "
                "nothing while still looking installed")

    # -- v22: the daemon conversation is cut at the one connection that can be named
    #
    # v21 required both libxpc entry points to be interposed, and the second one
    # cannot be named at all: Apple marks xpc_connection_create_mach_service
    # __attribute__((unavailable)) on iOS, and naming it - even inside an interpose
    # table, where it reads as data rather than as a call - is a front end error.
    # The rules below hold the shape that replaced it:
    #
    #   * the remaining replacee is named through an asm label, so the compiler has
    #     no declaration to conflict with and no identifier for an availability
    #     attribute to attach to;
    #   * the table names that identifier and not the SDK's, because the SDK's is
    #     what the front end checks;
    #   * the unavailable name appears nowhere in the tree.
    try:
        xpc_plain = strip_comments(read(root, "src/GNXPCGate.m"))
    except Exception:
        xpc_plain = ""
        problems.append("xpc-gate-named-only: src/GNXPCGate.m is missing")

    if xpc_plain:
        if '__attribute__((section("__DATA,__interpose")))' not in xpc_plain:
            problems.append(
                "xpc-gate-named-only: GNXPCGate.m has no interpose section, so the connection "
                "redirect never runs")
        if '__asm__("_xpc_connection_create")' not in xpc_plain:
            problems.append(
                "xpc-asm-labelled-replacee: the C entry point is not declared through an asm "
                "label. On iOS Apple's <xpc/connection.h> is in scope whether or not this file "
                "includes it, and a second declaration under the same identifier is either a "
                "conflicting type or an unavailable-symbol error - which is how v21 died")
        if "(const void *)&GNXPCCreateReplacee" not in xpc_plain:
            problems.append(
                "xpc-asm-labelled-replacee: the interpose table does not name the asm-labelled "
                "identifier, so it names something the compiler can check against the SDK")
        if "GNInterposeReal(" not in xpc_plain:
            problems.append(
                "interpose-original-one-place: the gate does not resolve the real function "
                "through GNInterposeReal(), so a dlsym answer that is this dylib's own "
                "replacement would be called as if it were libxpc")
        if "dlsym(RTLD_DEFAULT" in xpc_plain:
            problems.append(
                "interpose-original-one-place: GNXPCGate.m resolves the replaced symbol itself "
                "instead of going through GNInterposeReal.m")
        if "com.zaka.gnunlock.blackhole" not in xpc_plain:
            problems.append(
                "xpc-gate-named-only: the substitute service name is gone. The redirect must "
                "point at a name with nothing behind it, by construction, so no daemon can "
                "answer anything")
        if "if (!name || !*name) return NO;" not in xpc_plain:
            problems.append(
                "xpc-gate-named-only: the service filter does not refuse an empty name. A gate "
                "that matches 'nothing' is a gate that redirects every connection in the "
                "process")
        for needle in ("cloudd", "cloudkit"):
            if needle not in xpc_plain:
                problems.append(
                    "xpc-gate-named-only: the default filter no longer names '%s'; a wider "
                    "filter would redirect services this dylib has no business touching"
                    % needle)

    # -- v22: a symbol Apple marks unavailable on iOS is not named at all -----
    #
    # The compiler catches every naming except the one that hides behind an asm
    # label, and that is exactly the form this tree uses to dodge SDK declarations.
    # So the check is by name, over every source, with comments stripped: a comment
    # may discuss a symbol the code may not name.
    for unavailable in ("xpc_connection_create_mach_service",):
        for relative in sorted(p.name for p in (root / "src").glob("*.m")) + \
                        sorted(p.name for p in (root / "src").glob("*.h")):
            try:
                text = strip_comments(read(root, "src/" + relative))
            except Exception:
                continue
            if unavailable in text:
                problems.append(
                    "ios-unavailable-not-named: src/%s names %s, which Apple marks "
                    "__attribute__((unavailable)) on iOS. Naming it is a front end error "
                    "whether it is called, referred to, or put in an interpose table"
                    % (relative, unavailable))

    # -- v22: one place resolves the function behind a replacement -----------
    try:
        real_plain = strip_comments(read(root, "src/GNInterposeReal.m"))
    except Exception:
        real_plain = ""
        problems.append("interpose-original-one-place: src/GNInterposeReal.m is missing")

    if real_plain:
        if "(viaLookup == replacement)" not in real_plain:
            problems.append(
                "interpose-original-one-place: the resolver does not refuse a dlsym answer that "
                "is the replacement itself. dyld interposes dlsym results on the launches where "
                "it applies the table to its own lookups, and calling that answer is recursion")
        if "tableHalf != replacement" not in real_plain:
            problems.append(
                "interpose-original-one-place: the resolver no longer falls back to the "
                "replacee half of the tuple. That half is what dyld read in order to install "
                "the replacement, so it is the one source that still answers when dlsym cannot")

    # -- v21: the quarantine selects on shape, not on a list -------------
    try:
        qu_plain = strip_comments(read(root, "src/GNCloudKitQuarantine.m"))
    except Exception:
        qu_plain = ""
        problems.append("quarantine-void-only: src/GNCloudKitQuarantine.m is missing")

    if qu_plain:
        if "types[0] != 'v'" not in qu_plain:
            problems.append(
                "quarantine-void-only: the replacement does not require a void return type. A "
                "method that returns an object cannot be given an empty body: nil where Swift "
                "expects a non-optional CKDatabase is a trap, not a fallback")
        if "class_getImageName" not in qu_plain or '"CloudKit"' not in qu_plain:
            problems.append(
                "quarantine-image-scoped: the class filter is gone. Without the image check the "
                "rule reaches every class whose name happens to start with CK, in the app "
                "included")
        if "method_getTypeEncoding" not in qu_plain:
            problems.append(
                "quarantine-void-only: the type encoding is not read, so the shape check cannot "
                "be happening")
        if "class_replaceMethod" not in qu_plain:
            problems.append("quarantine-void-only: nothing is actually replaced")

    # -- v21: the ordered constructor ------------------------------------
    v21_body = constructor_body(entry)
    if v21_body:
        def at(needle):
            return v21_body.find(needle)
        if at("GNInstallThrowInterpose(") < 0:
            problems.append(
                "interpose-armed-early: the constructor never installs the throw interpose, so "
                "the trampoline is reachable only through the three v20 slots")
        if at("GNInstallCloudKitQuarantine(") < 0:
            problems.append("quarantine-before-stub: the constructor never installs the "
                            "quarantine")
        elif at("GNInstallCloudKitStub(") >= 0 and at("GNInstallCloudKitQuarantine(") > at("GNInstallCloudKitStub("):
            problems.append(
                "quarantine-before-stub: the quarantine runs after the stub, so it overwrites "
                "the fourteen answers that return substitute objects or deliver "
                "CKErrorNotAuthenticated with an empty body")
        if at("GNInstallXPCGate(") < 0:
            problems.append("xpc-gate-named-only: the constructor never installs the gate")
        retry_body = function_body(v21_body, "@try") if False else v21_body
        if "GNInstallCloudKitQuarantine(GNConfig());" not in retry_body:
            problems.append("quarantine-before-stub: the retry path does not re-run the "
                            "quarantine before the stub")

    # -- v21: the initialiser hole is closed -----------------------------
    try:
        stub_plain = strip_comments(read(root, "src/GNCloudKitStub.m"))
    except Exception:
        stub_plain = ""
        problems.append("stub-init-guarded: src/GNCloudKitStub.m is missing")

    if stub_plain:
        for selector in ("initWithContainerIdentifier:", "initWithContainerID:"):
            if selector not in stub_plain:
                problems.append(
                    "stub-init-guarded: %s is not replaced. A caller that builds a container "
                    "with the initialiser instead of the class method reaches a real "
                    "CKContainer and the check v20 removed from the other entry points"
                    % selector)
        if "ns_returns_retained" not in stub_plain:
            problems.append(
                "stub-init-guarded: the init replacement carries no ns_returns_retained. ARC "
                "does not infer the init family for a plain C function, so the caller would "
                "over-release a singleton")

    # -- v23: the swallow is scoped, forced only by choice, and measured ----
    tramp = strip_comments(read(root, "src/GNThrowTrampoline.m"))

    # The decision itself, not the file: both mutations below swap a term out of
    # the maySwallow expression, and the same identifier still appears in the
    # "why not swallowed" log lines beside it. Reading the statement is what
    # makes the rule about the decision rather than about the text.
    decision = ""
    match = re.search(r"BOOL maySwallow\s*=\s*(.*?);", tramp, re.S)
    if match:
        decision = match.group(1)

    if "GNAddressIsInImages(" not in tramp:
        problems.append(
            "swallow-image-scoped: src/GNThrowTrampoline.m has no image filter. v23 turns the "
            "swallow on by default, and an unscoped swallow would answer for exceptions thrown "
            "anywhere in the process - a second crash invited into a launch that is already "
            "one variable deep")
    elif "imageAllowed" not in decision:
        problems.append(
            "swallow-image-scoped: the image filter is computed but not part of the swallow "
            "decision, which is the same as not having one")

    if "nameAllowed" not in decision:
        problems.append(
            "swallow-named-only: the swallow decision does not check the exception name "
            "against CloudKitExceptionNames. A swallow without that list is a blanket "
            "suppressor of every exception in the app")

    # v26: this rule used to read "must be false". It is inverted rather than
    # deleted, because the reason it existed has not gone away - a forced swallow
    # still resumes a block the compiler emitted as unreachable. What changed is
    # that v25 measured the alternative: zero slots hold the throwing address,
    # dlsym cannot resolve the symbol, the call is a direct branch. With no
    # proven-return site left, shipping force off ships a launch that logs the
    # same refusal and dies in the same place - that is v25 again, and it was
    # already paid for once.
    if cfg.get("ThrowSwallowForce") is not True:
        problems.append(
            "swallow-force-on: ThrowSwallowForce must be true in the shipped plist. v26 exists "
            "because v25 proved there is no remaining proven-return site to swallow at; with "
            "this off, the trampoline rethrows the same exception at the same address and the "
            "build has no new answer to give")

    if cfg.get("ThrowSwallowReturnNil") is not True:
        problems.append(
            "swallow-forced-value: ThrowSwallowReturnNil must be true. The site resumes "
            "Optional<CKPersona>, where zero is `.none`; returning the exception object instead "
            "passes a guard-let and then gets messaged as a persona, which is a later crash at "
            "an address that names nothing")

    if "gSwallowReturnNil ? NULL : exceptionRaw" not in tramp:
        problems.append(
            "swallow-forced-value: the forced-swallow return does not go through "
            "gSwallowReturnNil. Either the key stopped being read or the swallow still hands "
            "the exception object back as the getter's result")

    if cfg.get("ThrowSwallowAtSite") is not True:
        problems.append(
            "swallow-site-on: ThrowSwallowAtSite must be true. v23 exists because the throw "
            "comes out of a dispatch_once block, where rethrowing is an abort() rather than a "
            "recoverable unwind; shipping this off is shipping v22 again")

    # -- v25: the symbol surface, resolved at run time ----------------------
    #
    # v24 was an __DATA,__interpose table naming two symbols Apple does not put in
    # CloudKit's .tbd. weak_import did not help: the linker still had to recognise
    # the name, and the build died at the link stage instead of at the launch.
    # v25 replaced the table with a run time resolver plus the v16 slot walker,
    # and these rules keep every part of that shape in place.
    symbols = strip_comments(read(root, "src/GNCloudKitSymbolQuarantine.m"))

    if not symbols:
        problems.append("symbol-no-linktime-extern: src/GNCloudKitSymbolQuarantine.m is missing")
    else:
        # Every one of these is a link time reference to a name the SDK does not
        # declare. Any of them coming back is v24 again, one stage early.
        for needle, what in (
                ("__asm__(", "an asm-labelled extern"),
                ("weak_import", "a weak import"),
                ("__DATA,__interpose", "an interpose tuple"),
                ("extern ", "an extern declaration")):
            if needle in symbols:
                problems.append(
                    "symbol-no-linktime-extern: src/GNCloudKitSymbolQuarantine.m contains %s. "
                    "Neither name is in CloudKit's .tbd, so anything the linker has to resolve "
                    "is 'Undefined symbols for architecture arm64'. Resolution is run time only"
                    % what)

        # Both names, still as data - the log and the dlsym attempt need them.
        for needle in ("$sSo9CKPersonaC8CloudKitE6launchABSgvgZ",
                       "CKMainBundleIsAppleExecutable"):
            if needle not in symbols:
                problems.append(
                    "symbol-both-names: %s is gone from the resolver. Both names came from the "
                    "device backtrace, and a table that drops one is a v24 with extra files"
                    % needle)

        # The two sources of an address, in the order they are tried.
        for needle in ("dlsym(RTLD_DEFAULT, name)", "RTLD_NOLOAD",
                       "GNFSFindFunction(", "GNImageFunctionStart(", "GNImageBase("):
            if needle not in symbols:
                problems.append(
                    "symbol-runtime-resolution: %r is missing. dlsym is the first source and, "
                    "for a symbol that is not exported, the offset walked through "
                    "LC_FUNCTION_STARTS is the second - dropping either one leaves an entry "
                    "with no address and a log line that cannot say why" % needle)

        # The offset parser refuses anything that is not a hex number. A relaxed
        # parser is a rewritten slot pointing at nothing.
        for needle in ("GNParseHexOffset(", "isxdigit(", "strtoull(", "CloudKitSymbolOffsets"):
            if needle not in symbols:
                problems.append(
                    "symbol-offset-validated: %r is missing. A configured offset that is not "
                    "strictly hex has to be refused, not coerced: the value ends up in an "
                    "import slot" % needle)

        # v27: an image-relative number has two readings - interior (what a crash
        # log prints) and entry (what a load-command dump gives) - and the log does
        # not say which one it handed over. Refusing to resolve because the *kind*
        # was wrong spends a launch on a one-word mistake; the other reading costs a
        # slot walk that matches nothing and writes nothing. So the failure path has
        # to keep going instead of returning.
        for needle in ("asEntry = YES;", "offset(entry-fallback)",
                       "reading the same number as an entry instead"):
            if needle not in symbols:
                problems.append(
                    "symbol-entry-fallback: %r is missing. With CloudKitSymbolOffsets filled, a "
                    "kind that does not match the number must cost a log line, not a launch: "
                    "the same number is re-read as an entry and the line says which reading "
                    "answered" % needle)

        # The redirection goes through the address-keyed walker, and this file
        # writes no memory of its own.
        for needle in ("GNSlotRebindAddress(", "GNSlotProbeAddress("):
            if needle not in symbols:
                problems.append(
                    "symbol-slot-rebind: %r is missing. The slot walk is the only mechanism "
                    "left now that the interpose table is gone, and the probe is what makes a "
                    "zero explainable" % needle)
        for needle in ("GNWriteBytes(", "GNSlotMoveTo(", "vm_protect("):
            if needle in symbols:
                problems.append(
                    "symbol-slot-rebind: %r appears in this file. Slot writes belong to "
                    "src/GNSlotScan.m, where the signature is proved before the value is "
                    "stored; a second writer here is a second place to get PAC wrong" % needle)

        # The honest half: exported vs not, and the direct-branch conclusion.
        for needle in ("is not exported", "direct branch", "slot(s) hold the address"):
            if needle not in symbols:
                problems.append(
                    "symbol-honest: %r never appears. v15, v17 and v19 all shipped a log that "
                    "read 'armed' where the truth was 'unreachable'; the sentences that say "
                    "which case this process is in are the fix" % needle)

        # Both replacements keep their gate, and reach the real function only
        # through the resolved pointer.
        if symbols.count("!gGate || !entry->enabled") < 2:
            problems.append(
                "symbol-gated: both replacements must check the master switch and their own "
                "entry switch. A rewritten slot cannot be un-rewritten, so off has to mean "
                "pass-through inside the replacement")

        for marker, call in (
                ("static void *GNCloudKitPersonaLaunchReplaced(void) {",
                 "((void *(*)(void))entry->real)()"),
                ("static bool GNCloudKitMainBundleIsAppleReplaced(void) {",
                 "((bool (*)(void))entry->real)()")):
            body = function_body(symbols, marker)
            if not body:
                problems.append(
                    "symbol-no-selfcall: %r not found - the entry it belongs to is not a "
                    "replacement at all" % marker)
                continue
            if call not in body:
                problems.append(
                    "symbol-no-selfcall: %r does not call through the resolved pointer. Without "
                    "an interpose tuple there is no other source for the real function, and a "
                    "call by name recurses into this dylib" % marker)
            own = marker.split("(")[0].split()[-1]
            if own in body:
                problems.append(
                    "symbol-no-selfcall: %r names itself. That is recursion with a convincing "
                    "log in front of it" % marker)

    for key in ("CloudKitSymbolQuarantine", "CloudKitSymbolRebind"):
        if cfg.get(key) is not True:
            problems.append(
                "symbol-config-keys: %s must be true in the shipped plist - the resolver and "
                "the slot walk are what v25 delivered" % key)
    if not isinstance(cfg.get("CloudKitSymbolOffsets"), dict):
        problems.append(
            "symbol-config-keys: CloudKitSymbolOffsets must be a dictionary (label -> hex "
            "offset). An empty one is correct: the numbers come from a crash log")
    if not isinstance(cfg.get("CloudKitSymbolImage"), str):
        problems.append("symbol-config-keys: CloudKitSymbolImage must name the image")
    if cfg.get("CloudKitSymbolOffsetKind") not in ("interior", "entry"):
        problems.append(
            "symbol-config-keys: CloudKitSymbolOffsetKind must be 'interior' (what a crash log "
            "prints) or 'entry' (what a load-command dump gives)")

    quarantine = strip_comments(read(root, "src/GNCloudKitQuarantine.m"))
    if "CloudKitQuarantineClasses" not in quarantine:
        problems.append(
            "persona-named-class: the quarantine has no by-name class list. CKPersona is a "
            "Swift class, so the shape sweep cannot reach it whatever its prefixes are")

    named = cfg.get("CloudKitQuarantineClasses") or []
    if "CKPersona" not in named:
        problems.append(
            "persona-named-class: CloudKitQuarantineClasses must contain CKPersona, the class "
            "the v22 backtrace named")

    if "GNInstallCloudKitSymbolQuarantine(GNConfig());" not in v21_body:
        problems.append(
            "symbol-quarantine-installed: the constructor never installs the symbol layer, so "
            "both entries are a table nobody armed")

    # -- v23: the version the log will name ------------------------------
    beacon_head = read(root, "src/GNBeacon.h")
    if 'GN_UNLOCK_VERSION "27"' not in beacon_head:
        problems.append(
            "version-bumped: GN_UNLOCK_VERSION is not \"27\". The first line of every beacon "
            "names the build; a v27 log that says 26 is a log nobody can trust, and v26 and "
            "v27 differ by the two offsets that decide whether the slot walk runs at all")

    # -- v24: one home for the shipped defaults ------------------------------
    # v23 failed in the lint job before a single line compiled: this file had
    # been taught that ThrowSwallowAtSite ships true, while a handwritten copy
    # of the same assertion in .github/workflows/build-dylib.yml still demanded
    # false. Neither file was wrong about its own version - the defect is that
    # the fact existed twice. It lives in scripts/plist_expect.py now, and these
    # rules keep it there: the consumers must call it, and its pins must agree
    # with the rules this lint enforces on its own.
    expect_src = read(root, "scripts/plist_expect.py")
    pins = {}
    config_version = None
    module_check = None

    if not expect_src:
        problems.append(
            "plist-expect-single-source: scripts/plist_expect.py is missing. The shipped "
            "defaults must have exactly one home; two copies of one default is what failed "
            "v23 before it compiled")
    else:
        namespace = {"__name__": "plist_expect"}
        try:
            exec(compile(expect_src, "scripts/plist_expect.py", "exec"), namespace)
            pins = namespace.get("PINNED") or {}
            config_version = namespace.get("CONFIG_VERSION")
            module_check = namespace.get("check")
        except Exception as error:                       # noqa: BLE001 - report, do not trace
            problems.append(
                "plist-expect-single-source: scripts/plist_expect.py does not execute: %s"
                % error)

    build_sh = read(root, "scripts/build.sh")
    if "plist_expect.py" not in build_sh:
        problems.append(
            "plist-expect-single-source: scripts/build.sh does not run "
            "scripts/plist_expect.py, so a local build can ship defaults that CI would "
            "reject - which is how v23 was packaged")
    if "plistlib" in build_sh:
        problems.append(
            "plist-expect-single-source: scripts/build.sh reads the plist and asserts "
            "defaults itself again. Call scripts/plist_expect.py; a second copy of a default "
            "is a copy that goes stale the next time the default changes")

    workflows = sorted((pathlib.Path(root) / WORKFLOWS).glob("*.yml"))
    if not workflows:
        problems.append("plist-expect-single-source: no workflows found under %s" % WORKFLOWS)
    for workflow in workflows:
        relative = "%s/%s" % (WORKFLOWS, workflow.name)
        text = workflow.read_text(encoding="utf-8")
        if "plist_expect.py" not in text:
            problems.append(
                "plist-expect-single-source: %s does not run scripts/plist_expect.py, so the "
                "job validates whatever it happens to assert locally" % relative)
        if "plistlib" in text:
            problems.append(
                "plist-expect-single-source: %s parses the plist and asserts defaults inline. "
                "That handwritten copy is what told v23 \"ThrowSwallowAtSite must ship "
                "false\" while the plist and this lint both said true" % relative)

    for key, wanted in LINT_PINS.items():
        if key not in pins:
            problems.append(
                "plist-expect-mirrors-lint: scripts/plist_expect.py does not pin %s, but this "
                "lint has a rule about it. A key one side knows and the other does not is a "
                "disagreement waiting for a release" % key)
        elif pins[key] is not wanted:
            problems.append(
                "plist-expect-mirrors-lint: scripts/plist_expect.py pins %s=%r while this lint "
                "requires %r. The two copies of the fact have diverged again - that is the "
                "v23 failure, one release early" % (key, pins[key], wanted))

    version_hit = re.search(r'GN_UNLOCK_VERSION "(\d+)"', beacon_head)
    if version_hit and config_version is not None:
        if config_version != int(version_hit.group(1)):
            problems.append(
                "plist-expect-version: scripts/plist_expect.py pins ConfigVersion %r while the "
                "dylib reports version %s. A build whose plist and beacon disagree is a log "
                "whose reader cannot tell which defaults were in effect"
                % (config_version, version_hit.group(1)))

    if module_check is not None and cfg is not None:
        for problem in module_check(cfg):
            problems.append("plist-expect-agrees: %s" % problem)

    return problems


MUTATIONS = [
    ("boot-first", ENTRY,
     "    GNBoot();", "    ;",
     "constructor no longer opens the beacon first"),

    ("beacon-foundation-free", BEACON,
     '#include "GNBeacon.h"', '#include "GNBeacon.h"\n#import <Foundation/Foundation.h>',
     "beacon imports Foundation"),

    ("beacon-redundant", BEACON,
     "        fsync(gSinkFD[i]);", "        (void)0;",
     "beacon stops flushing"),

    ("observe-default", PLIST,
     "<key>ObserveOnly</key>\n\t<true/>", "<key>ObserveOnly</key>\n\t<false/>",
     "hooks are back on by default"),

    ("appgroup-off", PLIST,
     "<key>AppGroupFallback</key>\n\t\t<false/>", "<key>AppGroupFallback</key>\n\t\t<true/>",
     "the app group fallback is back"),

    ("guard-off", PLIST,
     "<key>GuardEnabled</key>\n\t<false/>", "<key>GuardEnabled</key>\n\t<true/>",
     "the launch guard is back on by default"),

    ("runlevel-zero", PLIST,
     "<key>RunLevel</key>\n\t<integer>0</integer>", "<key>RunLevel</key>\n\t<integer>3</integer>",
     "the run level starts at 3 again"),

    ("no-behaviour-hooks", ENTRY,
     "            if (observe) {", "            GNInstallLaunchGuard();\n            if (observe) {",
     "the constructor reaches the launch guard"),

    ("init-swizzle-retained", FORENSICS,
     "    __attribute__((ns_returns_retained));\n\nstatic void GNRestoreExceptionInit",
     "    ;\n\nstatic void GNRestoreExceptionInit",
     "the init swizzle loses its ownership annotation"),

    ("legacy-unreachable", ENTRY,
     "                             GNBeaconUptimeMs());\n                return;",
     "                             GNBeaconUptimeMs());\n                ;",
     "the observe branch stops returning"),

    ("legacy-guard-first", LEGACY,
     "    GNInstallLaunchGuard();\n    GNInstallThrowTracer(GNGuardNetCount());\n\n"
     "    int level = GNRunLevel();",
     "    GNInstallThrowTracer(GNGuardNetCount());\n\n    int level = GNRunLevel();\n"
     "    GNInstallLaunchGuard();",
     "the launch guard moved below the run level gate"),

    ("private-api-dlsym", "src/GNProbe.m",
     '#import "GNPrivateSecTask.h"',
     '#import "GNPrivateSecTask.h"\n\n'
     'typedef struct __SecTask *SecTaskRef;\n'
     'static SecTaskRef GNProbeV121Regression(void) { return SecTaskCreateFromSelf(0); }',
     "a private symbol is named directly instead of through dlsym"),

    ("stub-no-private-api", "scripts/stubsdk/include/Security/Security.h",
     "extern const CFStringRef kSecClass;",
     "typedef struct __SecTask *SecTaskRef;\n"
     "SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);\n\n"
     "extern const CFStringRef kSecClass;",
     "the stub SDK declares a symbol the public SDK does not"),

    ("cloudkit-guard-narrow", CLOUDKIT,
     "BOOL nameMatched = [gSuppressedNames containsObject:name];",
     "BOOL nameMatched = YES;",
     "the suppressor stops filtering on the exception name"),

    ("cloudkit-guard-before-observe", ENTRY,
     '            if (GNCFG(@"CloudKitGuard", YES)) {',
     '            if (observe) { return; }\n            if (GNCFG(@"CloudKitGuard", YES)) {',
     "the CloudKit guard moved behind the observe early return"),

    ("cloudkit-no-init-hook", CLOUDKIT,
     "#import <objc/runtime.h>",
     '#import <objc/runtime.h>\nstatic const char *kGNWrongHookName = "initWithName:";',
     "the guard tries to suppress at the initialiser"),

    ("cloudkit-guard-default-on", PLIST,
     "<key>CloudKitGuard</key>\n\t<true/>",
     "<key>CloudKitGuard</key>\n\t<false/>",
     "the CloudKit guard ships disabled"),

    ("interpose-weak-import", INTERPOSE,
     "extern CFTypeRef SecTaskCopyValueForEntitlement(const void *task, CFStringRef entitlement, "
     "CFErrorRef *error) __attribute__((weak_import));",
     "extern CFTypeRef SecTaskCopyValueForEntitlement(const void *task, CFStringRef entitlement, "
     "CFErrorRef *error);",
     "the interpose table names a symbol without weak_import"),

    ("interpose-section", INTERPOSE,
     'section("__DATA,__interpose")', 'section("__DATA,__gnunlock")',
     "the interpose table moves out of __DATA,__interpose"),

    ("entitlement-repair-type-only", REPAIR,
     "if (CFGetTypeID(value) == CFArrayGetTypeID()) {",
     "if (1) {",
     "the repair stops checking the type before substituting"),

    ("entitlement-repair-before-observe", ENTRY,
     '            if (GNCFG(@"EntitlementRepair", YES)) {',
     '            if (observe) { return; }\n            if (GNCFG(@"EntitlementRepair", YES)) {',
     "the entitlement repair moved behind the observe early return"),

    ("entitlement-repair-default-on", PLIST,
     "<key>EntitlementRepair</key>\n\t<true/>",
     "<key>EntitlementRepair</key>\n\t<false/>",
     "the entitlement repair ships disabled"),


    ("slotwalk-pure-header", SLOTWALK,
     "#include <string.h>",
     "#include <string.h>\n#import <Foundation/Foundation.h>",
     "the walk pulls in a framework header and stops being host-testable"),

    ("slot-hook-data-only", SLOTSCAN,
     "#pragma mark - One section, one image",
     "static void GNBadPatch(void) { GNPatchCodeBytes(0, 0, 0); }\n\n"
     "#pragma mark - One section, one image",
     "a v16 module writes a code page"),

    ("slot-hook-data-only", SLOTHOOK,
     "#pragma mark - Describing a value for the log",
     "static void GNBadInline(void) { GNInlineHookSymbol(0, 0, 0); }\n\n"
     "#pragma mark - Describing a value for the log",
     "a v16 module inline hooks, which needs a text page"),

    ("slot-refuse-does-not-write", SLOTWALK,
     "            stats.refused++;\n            continue;\n        }",
     "            stats.refused++;\n        }",
     "a refused slot falls through to the write"),

    ("slot-proof-before-write", "src/GNRebind.m",
     "if (GNSignPointer(target, key, modifiers[index]) != raw) continue;",
     "if (GNSignPointer(target, key, modifiers[index]) != 0) continue;",
     "the slot move stops reproducing the existing signature"),

    ("real-fixture-not-a-constant", SLOTWALK_TEST,
     "CHECK(stats.sections == raw.sections,",
     "CHECK(stats.sections >= 5,",
     "the real-image check asserts a section count that belongs to the compiler"),

    ("slot-selftest-required", SLOTHOOK,
     "    if (GNCFG(@\"EntitlementSlotSelfTest\", YES)) {\n        GNSlotRunSelfTest();",
     "    if (GNCFG(@\"EntitlementSlotSelfTest\", YES)) {",
     "the installer stops measuring whether the hook fires"),

    ("slot-selftest-two-paths", SLOTHOOK,
     "    CFTypeRef bound = GNEntitlementCallThroughImport((CFTypeRef)task, key, NULL);",
     "    CFTypeRef bound = GNPrivateSecTaskCopyEntitlement(task, key);",
     "the self-test takes both readings through the same path"),

    ("slot-selftest-two-paths", SLOTHOOK,
     "    int32_t after = GNEntitlementRepairCount();",
     "    int32_t after = before;",
     "the self-test stops consulting the repair counter"),

    ("slot-add-image-watch", SLOTSCAN,
     "        _dyld_register_func_for_add_image(GNOnImageAdded);",
     "        /* no late image watch */",
     "a framework loaded after the constructor is never scanned"),

    ("slot-before-observe", ENTRY,
     '            if (GNCFG(@"EntitlementSlotRebind", YES)) {',
     '            if (observe) { return; }\n            if (GNCFG(@"EntitlementSlotRebind", YES)) {',
     "the slot rewrite moved behind the observe early return"),

    ("slot-default-on", PLIST,
     "<key>EntitlementSlotRebind</key>\n\t<true/>",
     "<key>EntitlementSlotRebind</key>\n\t<false/>",
     "the slot rewrite ships disabled"),

    ("repair-dlsym-not-own-replacement", REPAIR,
     "gOriginalCopyValue = (GNCopyValueFn)GNInterposeReal(",
     "gOriginalCopyValue = (GNCopyValueFn)(",
     "the repair trusts that the resolved address is never its own replacement"),

    ("slot-selftest-default-on", PLIST,
     "<key>EntitlementSlotSelfTest</key>\n\t<true/>",
     "<key>EntitlementSlotSelfTest</key>\n\t<false/>",
     "the self-test ships disabled"),

    # -- v18 ----------------------------------------------------------------
    ("repair-plan-from-policy", REPAIR,
     "GNRPlanRepair(rule->expect",
     "GNRPlanRepair(GNRExpectString",
     "the repair asks the policy with a fixed expectation instead of the rule's"),

    ("repair-plan-from-policy", "src/GNRepairPolicy.h",
     "static inline GNRPlan GNRPlanRepair(",
     "static inline GNRPlan GNRPlanRepairRenamed(",
     "the tested policy no longer defines the decision the repair calls"),

    ("repair-policy-host-tested", "scripts/stubcheck.sh",
     '"$OBJ/repair_policy_test" --selfcheck',
     '"$OBJ/repair_policy_test"',
     "the host test stops proving its own assertions can fail"),

    ("repair-policy-host-tested", ".github/workflows/build-dylib.yml",
     "          /tmp/repair_policy_test --selfcheck",
     "          true",
     "the workflow stops running the policy selfcheck"),

    ("repair-policy-host-tested", "scripts/repair_policy_test.c",
     "plan.produce == wanted",
     "plan.produce == plan.produce",
     "the host test stops asserting that a repair's kind matches the schema"),

    ("dlsym-tap-covers-lookup", "src/GNDlsymTap.m",
     'if (strcmp(symbol, "SecCodeCopySigningInformation") == 0) {',
     'if (0) {',
     "the lookup tap stops answering the signing-information read"),

    ("dlsym-tap-resolves-first", "src/GNDlsymTap.m",
     'gRealDlsym = (GNDlsymFn)dlsym(RTLD_DEFAULT, "dlsym");',
     'gRealDlsym = NULL;',
     "the tap no longer resolves the real dlsym"),

    ("throw-tap-armed", SLOTHOOK,
     "            GNThrowTapActivate(gGNSlotTargets[i]);",
     "            GNThrowTapActivate(NULL);",
     "the installer stops handing the throw tap the real function"),

    ("slot-selftest-plural", SLOTHOOK,
     "    GNSlotRunPluralSelfTest(task, key);",
     "    ;",
     "the launch self-test stops measuring the plural read"),

    ("dlsym-tap-default-on", PLIST,
     "<key>DlsymTap</key>\n\t<true/>",
     "<key>DlsymTap</key>\n\t<false/>",
     "the lookup tap ships disabled"),

    ("throw-tap-default-on", PLIST,
     "<key>ThrowTap</key>\n\t<true/>",
     "<key>ThrowTap</key>\n\t<false/>",
     "the throw tap ships disabled"),

    ("stub-never-calls-original", "src/GNCloudKitStub.m",
     "static BOOL GNReplace(Class cls, const char *name, IMP replacement, BOOL classMethod) {",
     "static IMP gOriginal;\nstatic BOOL GNReplace(Class cls, const char *name, IMP replacement, BOOL classMethod) {",
     "the substitute keeps a pointer to what it replaced"),

    ("stub-subclass", "src/GNCloudKitStub.m",
     "    Class made = objc_allocateClassPair(base, name, 0);",
     "    Class made = base;",
     "the substitute becomes the real class instead of a subclass of it"),

    ("trampoline-classifies", "src/GNThrowTrampoline.m",
     "        && (continuation.safe || gSwallowForce);",
     "        && (YES || gSwallowForce);",
     "the swallow stops requiring a decoded return at the throw site"),

    ("trampoline-records-first", "src/GNThrowTrampoline.m",
     "    GNThrowTraceRecord(exception);",
     "    ;",
     "the trampoline swallows without writing the record first"),

    ("read-surface-dry-run", "src/GNSlotScan.m",
     "    gSlotDryRun = true;",
     "    gSlotDryRun = false;",
     "the count-only probe arms the writer and rewrites what it measures"),

    ("stub-reversible", PLIST,
     "<key>CloudKitStub</key>\n\t<true/>",
     "<key>CloudKitStub</key>\n\t<false/>",
     "the CloudKit substitute ships disabled"),

    ("dlsym-tap-before-observe", ENTRY,
     '            if (GNCFG(@"DlsymTap", YES)) {',
     '            if (observe) { return; }\n            if (GNCFG(@"DlsymTap", YES)) {',
     "the lookup tap moved behind the observe early return"),

    ("ci-no-line-numbers", ".github/workflows/build-dylib.yml",
     "      - name: No bare Apple dyld struct tag",
     "      - name: The launch guard comes first\n"
     "        run: |\n"
     "          guard=$(grep -n 'GNInstallLaunchGuard();' src/GNUnlock.m | head -1 | cut -d: -f1)\n"
     "          echo \"$guard\"\n"
     "\n"
     "      - name: No bare Apple dyld struct tag",
     "a CI step pins a statement's line number again"),

    ("callsite-audit-wired", ENTRY,
     "                        GNReadAuditDump();", "                        ;",
     "the constructor stops dumping the call site audit"),

    ("callsite-audit-wired", REPAIR,
     "GNReadAuditNote(GNReadDoorSigningInfo, caller, after != before);",
     "(void)caller;",
     "the signing-information door stops recording its caller"),

    ("callsite-audit-no-inline-resolve", AUDIT,
     "    uintptr_t address = (uintptr_t)caller;",
     "    Dl_info inline_probe; dladdr(caller, &inline_probe);\n"
     "    uintptr_t address = (uintptr_t)caller;",
     "the door resolves the caller inline, during dyld init"),

    ("callsite-self-test-quiet", SLOTHOOK,
     "    GNReadAuditSuspend();", "    ;",
     "the self-test stops excluding itself from the audit"),

    ("boundary-observe-rethrows", CLOUDKIT,
     "            if (GNBoundaryObserveRethrow(site, exception)) @throw;\n"
     "            return nil;",
     "            return nil;",
     "an observe boundary swallows instead of rethrowing"),

    ("probe-never-swallows", CLOUDKIT,
     '           @"ClassMethod": @YES, @"Return": @"object", @"Arguments": @0,\n'
     '           @"Mode": @"observe" },\n\n'
     '        @{ @"Class": @"CKContainer", @"Selector": @"containerWithIdentifier:"',
     '           @"ClassMethod": @YES, @"Return": @"object", @"Arguments": @0,\n'
     '           @"Mode": @"swallow" },\n\n'
     '        @{ @"Class": @"CKContainer", @"Selector": @"containerWithIdentifier:"',
     "a probe boundary is allowed to swallow a Swift non-optional"),
    ("interpose-table-read-by-dyld", "src/GNThrowInterpose.m",
     '__attribute__((section("__DATA,__interpose")))',
     '__attribute__((section("__DATA,__notinterpose")))',
     "the throw table leaves the section dyld reads"),

    ("interpose-table-read-by-dyld", "src/GNThrowInterpose.m",
     "    { (const void *)&GNThrowInterposed, (const void *)&GNThrowInterposeReplacee },",
     "    { (const void *)&GNThrowInterposed, (const void *)0 },",
     "the table names no replacee, so dyld cannot tell what to replace"),

    ("interpose-never-calls-by-name", "src/GNThrowInterpose.m",
     '        real = GNInterposeReal("objc_exception_throw",',
     '        real = (void *)&GNThrowInterposeReplacee;',
     "the replacement calls the replacee identifier instead of resolving the real function"),

    ("interpose-original-one-place", "src/GNThrowInterpose.m",
     "static void *GNThrowInterposeRealAddress(void) {",
     'static void *GNThrowInterposeRealAddress(void) { (void)dlsym(RTLD_DEFAULT, '
     '"objc_exception_throw");',
     "the rethrow path goes back to a bare dlsym, which dyld is entitled to interpose"),

    ("interpose-armed-early", ENTRY,
     "                GNInstallThrowInterpose(GNConfig());",
     "                (void)0;",
     "the constructor never arms the process-wide throw gate"),

    ("xpc-gate-named-only", "src/GNXPCGate.m",
     "    if (!name || !*name) return NO;",
     "    if (!name) return NO;",
     "the service filter stops refusing an empty name"),

    ("xpc-gate-named-only", "src/GNXPCGate.m",
     'static const char *const kGNBlackholeService = "com.zaka.gnunlock.blackhole";',
     'static const char *const kGNBlackholeService = "com.apple.cloudd";',
     "the redirect points at a real daemon again"),

    ("quarantine-void-only", "src/GNCloudKitQuarantine.m",
     "if (!types || types[0] != 'v') continue;",
     "if (!types) continue;",
     "the quarantine stops checking the return type"),

    ("quarantine-image-scoped", "src/GNCloudKitQuarantine.m",
     'return strstr(image, "CloudKit") != NULL;',
     "return YES;",
     "the quarantine stops filtering by defining image"),

    ("quarantine-before-stub", ENTRY,
     "                GNInstallCloudKitQuarantine(GNConfig());",
     "                (void)0;",
     "the constructor stops installing the quarantine"),

    ("stub-init-guarded", "src/GNCloudKitStub.m",
     'GNReplace(container, "initWithContainerIdentifier:", (IMP)GNServeContainerInit, NO)',
     'GNReplace(container, "initWithContainerIdentifierX:", (IMP)GNServeContainerInit, NO)',
     "the container initialiser hole is open again"),

    ("version-bumped", "src/GNBeacon.h",
     '#define GN_UNLOCK_VERSION "27"', '#define GN_UNLOCK_VERSION "26"',
     "the build reports the previous version"),

    # -- v22 ----------------------------------------------------------------
    ("ios-unavailable-not-named", "src/GNXPCGate.m",
     'extern void *GNXPCCreateReplacee(const char *name, dispatch_queue_t targetq)',
     'extern void *gn_unavailable_probe(const char *name, dispatch_queue_t targetq) '
     '__asm__("_xpc_connection_create_mach_service");\n'
     'extern void *GNXPCCreateReplacee(const char *name, dispatch_queue_t targetq)',
     "a symbol the SDK marks unavailable comes back, hidden behind an asm label"),

    ("xpc-asm-labelled-replacee", "src/GNXPCGate.m",
     '__asm__("_xpc_connection_create") __attribute__((weak_import))',
     '__attribute__((weak_import))',
     "the replacee loses its asm label and goes back to an SDK identifier"),

    ("xpc-asm-labelled-replacee", "src/GNXPCGate.m",
     "{ (const void *)&GNXPCGateCreate, (const void *)&GNXPCCreateReplacee },",
     "{ (const void *)&GNXPCGateCreate, (const void *)&xpc_connection_create },",
     "the table names the SDK's identifier instead of the asm-labelled one"),

    ("interpose-original-one-place", "src/GNInterposeReal.m",
     "BOOL lookupRefused = (viaLookup != NULL) && (viaLookup == replacement);",
     "BOOL lookupRefused = NO;",
     "the resolver stops refusing its own replacement"),

    ("interpose-original-one-place", "src/GNInterposeReal.m",
     "void *viaTable = (tableHalf && tableHalf != replacement) ? (void *)tableHalf : NULL;",
     "void *viaTable = NULL;",
     "the tuple fallback disappears, so a bad dlsym answer is the only answer"),

    ("interpose-original-one-place", "src/GNXPCGate.m",
     "    void *real = GNXPCCreateOriginal();",
     '    void *real = dlsym(RTLD_DEFAULT, "xpc_connection_create");',
     "the gate resolves the replaced symbol itself again"),

    # -- v23 ----------------------------------------------------------------
    ("swallow-image-scoped", "src/GNThrowTrampoline.m",
     "        && imageAllowed", "        && YES",
     "the swallow stops filtering by the image that threw"),

    ("swallow-named-only", "src/GNThrowTrampoline.m",
     "        && nameAllowed", "        && YES",
     "the swallow stops checking the exception name"),

    ("swallow-force-on", PLIST,
     "<key>ThrowSwallowForce</key>\n\t<true/>", "<key>ThrowSwallowForce</key>\n\t<false/>",
     "the forced swallow stops shipping and v25 ships again"),

    ("swallow-forced-value", PLIST,
     "<key>ThrowSwallowReturnNil</key>\n\t<true/>",
     "<key>ThrowSwallowReturnNil</key>\n\t<false/>",
     "a forced swallow hands the exception object back as the getter's value"),

    ("swallow-site-on", PLIST,
     "<key>ThrowSwallowAtSite</key>\n\t<true/>", "<key>ThrowSwallowAtSite</key>\n\t<false/>",
     "the proven-return swallow is off again"),

    ("symbol-no-linktime-extern", "src/GNCloudKitSymbolQuarantine.m",
     "#include <string.h>",
     "#include <string.h>\nextern void GNCloudKitGhost(void) __attribute__((weak_import));",
     "a link time reference to a name CloudKit does not export comes back"),

    ("symbol-both-names", "src/GNCloudKitSymbolQuarantine.m",
     '.symbol = "$sSo9CKPersonaC8CloudKitE6launchABSgvgZ"',
     '.symbol = "$sSo9CKPersonaC8CloudKitE6launchABSgvgX"',
     "the mangled name the backtrace gave is mistyped"),

    ("symbol-runtime-resolution", "src/GNCloudKitSymbolQuarantine.m",
     "found = dlsym(RTLD_DEFAULT, name);",
     "found = NULL;",
     "the resolver stops trying dlsym at all"),

    ("symbol-offset-validated", "src/GNCloudKitSymbolQuarantine.m",
     "if (!isxdigit((unsigned char)*q)) return NO;",
     "if (0) return NO;",
     "the offset parser accepts a value that is not hex"),
    ("symbol-entry-fallback", "src/GNCloudKitSymbolQuarantine.m",
     "asEntry = YES;",
     "return;",
     "a mislabelled offset kind refuses to resolve instead of trying the other reading"),

    ("symbol-slot-rebind", "src/GNCloudKitSymbolQuarantine.m",
     "GNSlotRebindAddress(entry->label, entry->target, entry->replacement, YES, &written);",
     "GNWriteBytes(entry->target, NULL, 0);",
     "the file starts writing slots itself instead of going through the walker"),

    ("symbol-honest", "src/GNCloudKitSymbolQuarantine.m",
     '"%s: is not exported by any image in this process (RTLD_DEFAULT, RTLD_NEXT "',
     '"%s: was installed (RTLD_DEFAULT, RTLD_NEXT "',
     "the log stops saying the symbol is not exported"),

    ("symbol-gated", "src/GNCloudKitSymbolQuarantine.m",
     "    if (!gGate || !entry->enabled) {",
     "    if (NO) {",
     "a replacement ignores its own gate"),

    ("symbol-no-selfcall", "src/GNCloudKitSymbolQuarantine.m",
     "return ((void *(*)(void))entry->real)();",
     "return GNCloudKitPersonaLaunchReplaced();",
     "a replacement calls itself instead of the resolved function"),

    ("persona-named-class", PLIST,
     "<string>CKPersona</string>", "<string>CKPersonaOld</string>",
     "the class the backtrace named leaves the by-name list"),

    ("persona-named-class", "src/GNCloudKitQuarantine.m",
     'NSArray *named = GNCFGArray(@"CloudKitQuarantineClasses");',
     'NSArray *named = nil;',
     "the by-name class list is no longer read"),

    ("symbol-quarantine-installed", ENTRY,
     "                GNInstallCloudKitSymbolQuarantine(GNConfig());",
     "                (void)0;",
     "the constructor stops installing the symbol layer"),

    # -- v24 ----------------------------------------------------------------
    ("plist-expect-single-source", "scripts/build.sh",
     'python3 "$ROOT/scripts/plist_expect.py" "$ROOT/config/GNUnlock.plist"',
     'python3 -c "import plistlib, sys; plistlib.load(open(sys.argv[1], \'rb\'))" '
     '"$ROOT/config/GNUnlock.plist"',
     "the local build goes back to reading the plist itself"),

    ("plist-expect-single-source", ".github/workflows/build-dylib.yml",
     "python3 scripts/plist_expect.py config/GNUnlock.plist --selftest",
     'python3 -c "import plistlib; '
     'plistlib.load(open(\'config/GNUnlock.plist\', \'rb\'))"',
     "the workflow goes back to asserting defaults inline"),

    ("plist-expect-mirrors-lint", "scripts/plist_expect.py",
     '    "ThrowSwallowAtSite": True,',
     '    "ThrowSwallowAtSite": False,',
     "the shared expectation drifts back to the v22 value"),

    ("plist-expect-mirrors-lint", "scripts/plist_expect.py",
     '    "ThrowSwallowForce": True,\n', '',
     "the shared expectation silently stops pinning a key this lint rules on"),

    ("plist-expect-version", "scripts/plist_expect.py",
     "CONFIG_VERSION = 27", "CONFIG_VERSION = 26",
     "the plist schema version lags the build version"),

]


def selftest():
    failures = 0
    for name, relative, old, new, description in MUTATIONS:
        with tempfile.TemporaryDirectory() as scratch:
            target = pathlib.Path(scratch) / "tree"
            shutil.copytree(ROOT, target,
                            ignore=shutil.ignore_patterns("build", "out", ".git", "__pycache__"))
            victim = target / relative
            text = victim.read_text(encoding="utf-8")
            if text.count(old) < 1:
                print("  FAIL  %-24s fixture text not found in %s" % (name, relative))
                failures += 1
                continue
            victim.write_text(text.replace(old, new, 1), encoding="utf-8")

            found = [p for p in check(target) if p.startswith(name + ":")]
            if not found:
                print("  FAIL  %-24s mutation (%s) was not caught" % (name, description))
                failures += 1
            else:
                print("  ok    %-24s caught: %s" % (name, found[0].split(":", 1)[1].strip()[:72]))

    if failures:
        print("\nselftest: %d mutation(s) survived - the check is theatre" % failures)
        return 1
    print("\nselftest: all %d mutations caught" % len(MUTATIONS))
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()

    problems = check(ROOT)
    if problems:
        for problem in problems:
            print("error: %s" % problem, file=sys.stderr)
        print("\nv12_lint: %d problem(s)" % len(problems), file=sys.stderr)
        return 1
    print("v12_lint: %d invariants hold" % len(MUTATIONS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
