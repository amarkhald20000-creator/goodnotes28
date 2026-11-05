#!/usr/bin/env python3
"""plist_expect.py - what the shipped plist must default to, in one place.

v23 failed in the lint job before a single line compiled, and it failed on a
contradiction between two files that both believed they were right:

    scripts/v12_lint.py                 "ThrowSwallowAtSite must be true"   (v23)
    .github/workflows/build-dylib.yml   "ThrowSwallowAtSite must be false"  (v22)

Both statements were true about the version they were written for. The problem
is that the fact existed twice, in two files, and only one of them was edited
when the default changed. Version after version this repository has removed
duplication of exactly this kind - v12 took the launch-guard grep out of the
workflow and put it in the lint, precisely because a second copy of an internal
fact fails on every refactor and proves nothing.

So the defaults live here now, and the three consumers call this file instead of
restating it:

    scripts/build.sh                     preflight, before anything compiles
    .github/workflows/build-dylib.yml    the "Validate the plist" step
    scripts/v12_lint.py                  imports PINNED and CONFIG_VERSION and
                                         requires them to agree with the rules
                                         it enforces itself, so this file cannot
                                         drift away from the lint either

Two rules about what belongs here:

  * only statements about the *shipped* configuration. A key may have other
    legal values at run time (a diagnostic session is allowed to turn
    ThrowSwallowForce on by hand); what this file pins is what ships.
  * every pin carries its reason. A CI failure that prints "ships False, must
    ship True" tells the next person what broke; one that prints an assertion
    line number does not.

Usage:
    python3 scripts/plist_expect.py [config/GNUnlock.plist]
    python3 scripts/plist_expect.py [config/GNUnlock.plist] --selftest

--selftest mutates a copy of the config once per expectation and requires the
check to reject it. A preflight nobody has watched fail is the other half of how
v23 shipped: the inline copy had been dead weight since v23 and nobody noticed,
because no test ever flipped the value it guarded.
"""

import copy
import pathlib
import plistlib
import sys

# The config schema version this build ships. It moves with GN_UNLOCK_VERSION in
# src/GNBeacon.h - scripts/v12_lint.py ("plist-expect-version") refuses a build
# where the two disagree, because a v25 log carrying ConfigVersion 24 is a log
# whose reader cannot tell which defaults were in effect.
CONFIG_VERSION = 27

# Keys that must be present and must hold exactly this value in the shipped
# plist. scripts/v12_lint.py imports this dict and compares it against its own
# hard-coded rules: the two must agree on every key named in both.
PINNED = {
    # -- the inert baseline, from v12 onward ------------------------------
    "ObserveOnly": True,
    "GuardEnabled": False,
    "RunLevel": 0,
    "AutoBisect": False,
    "ExperimentLadder": False,
    "AllowCodePatching": False,

    # -- mechanisms that exist because a device log asked for them --------
    "CloudKitGuard": True,
    "EntitlementRepair": True,
    "DlsymTap": True,
    "ThrowTap": True,
    "EntitlementReadSurface": True,
    "CloudKitStub": True,
    "CloudKitSymbolQuarantine": True,
    "CloudKitSymbolRebind": True,

    # -- v23: how far the throw trampoline may go -------------------------
    # This pair is the reason this file exists. AtSite is on because the throw
    # comes out of a dispatch_once block, where rethrowing is abort() rather
    # than a recoverable unwind. Force stays off because resuming at a call
    # site the compiler marked unreachable is a gamble, not a fix.
    "ThrowSwallowAtSite": True,
    "ThrowSwallowForce": True,
    "ThrowSwallowReturnNil": True,
}

WHY = {
    "ObserveOnly": "v12 ships inert; the hooks are a separate, deliberate change",
    "GuardEnabled": "the launch guard is a diagnostic, not a default",
    "RunLevel": "run level 0 installs nothing",
    "AutoBisect": "the ladder needs a human reading the log, not a machine retrying",
    "ExperimentLadder": "the ladder is opt-in",
    "AllowCodePatching": "a Distribution certificate cannot patch a code page",
    "CloudKitGuard": "v13 named the launch crash; a default that stops naming it is a regression",
    "EntitlementRepair": "the malformed entitlement value is what kills the launch",
    "DlsymTap": "v17 measured zero slots for the plural read without it",
    "ThrowTap": "it is what names an exception thrown from the shared cache",
    "EntitlementReadSurface": "it is the sweep that says which entitlement doors exist",
    "CloudKitStub": "it is the only mechanism that has reached the value CloudKit rejects",
    "CloudKitSymbolQuarantine": "v23's two symbols are the ones the v22 backtrace named",
    "CloudKitSymbolRebind": (
        "v25's whole mechanism: without the slot walk the two names have an address and no "
        "way to act on it"),
    "ThrowSwallowAtSite": (
        "v23 exists because the throw comes out of a dispatch_once block, where rethrowing "
        "is abort(); shipping this off is shipping v22 again"),
    "ThrowSwallowForce": (
        "v26: the v25 log left no proven-return site to swallow at - the throw is a direct "
        "branch inside CloudKit, zero slots hold it, and dlsym cannot see the symbol. Resuming "
        "the block is the only move left in this mechanism"),
    "ThrowSwallowReturnNil": (
        "a forced swallow resumes Optional<CKPersona>, where zero is `.none`; returning the "
        "exception object instead passes a guard-let and then gets messaged as a persona"),
}

# Keys the check reads structurally rather than by equality.
TYPED = (
    "AutoBisect", "ShowLaunchNotice", "ExperimentLadder", "GuardCatchBoundary",
    "CloudKitBoundariesEnabled", "EntitlementRepairFill", "EnableGOTRebinding",
    "CloudKitSymbolQuarantinePersonaLaunch",
)

INTEGERS = ("GuardTraceThrowBudget", "ThrowSwallowBudget", "EntitlementRepairLogBudget")

STRINGS = ("GuardTraceThrow", "CloudKitStubMode", "CloudKitSymbolImage",
           "CloudKitSymbolOffsetKind")


def same(value, expected):
    """Equality that does not let True pass for 1 (or 0 for False)."""
    if isinstance(expected, bool):
        return value is expected
    if isinstance(expected, int):
        return isinstance(value, int) and not isinstance(value, bool) and value == expected
    return value == expected


def is_hex_offset(text):
    """The runtime parser's rule (GNParseHexOffset), restated here.

    Optional 0x, hex digits only, no sign, no suffix, not zero. Both ends of the
    exchange have to agree: a value this file calls fine and the dylib refuses is
    a launch spent on a log line.
    """
    if not isinstance(text, str) or not text or len(text) > 18:
        return False
    body = text[2:] if text[:2].lower() == "0x" else text
    if not body or not all(character in "0123456789abcdefABCDEF" for character in body):
        return False
    return int(body, 16) != 0


def check(config):
    """Every problem with this config, as strings. Empty list means it ships."""
    if not isinstance(config, dict):
        return ["top level: the plist is not a dictionary"]

    problems = []

    def fail(where, message):
        problems.append("%s: %s" % (where, message))

    # -- the version this build claims to be -----------------------------
    version = config.get("ConfigVersion")
    if not isinstance(version, int) or isinstance(version, bool):
        fail("ConfigVersion", "missing or not an integer")
    elif version != CONFIG_VERSION:
        fail("ConfigVersion",
             "ships %d, must ship %d - the defaults in this file are the ones a %d build "
             "reads" % (version, CONFIG_VERSION, CONFIG_VERSION))

    # -- the pinned defaults ---------------------------------------------
    for key, expected in PINNED.items():
        if key not in config:
            fail(key, "missing from the shipped plist (must be %r: %s)"
                 % (expected, WHY[key]))
        elif not same(config[key], expected):
            fail(key, "ships %r, must ship %r - %s" % (config[key], expected, WHY[key]))

    # -- types of the keys whose value is checked elsewhere --------------
    for key in TYPED:
        if key in config and not isinstance(config[key], bool):
            fail(key, "is %r, must be a bool" % (config[key],))
    for key in INTEGERS:
        if key in config and (not isinstance(config[key], int)
                              or isinstance(config[key], bool)):
            fail(key, "is %r, must be an integer" % (config[key],))
    for key in STRINGS:
        if key in config and not isinstance(config[key], str):
            fail(key, "is %r, must be a string" % (config[key],))

    if "GuardTraceThrow" in config and config["GuardTraceThrow"] not in (
            "auto", "always", "never"):
        fail("GuardTraceThrow", "is %r, must be auto / always / never"
             % (config["GuardTraceThrow"],))

    if "CloudKitSymbolOffsetKind" in config and config["CloudKitSymbolOffsetKind"] not in (
            "interior", "entry"):
        fail("CloudKitSymbolOffsetKind",
             "is %r, must be interior / entry - interior is what a crash log prints, entry is "
             "what a load-command dump gives" % (config["CloudKitSymbolOffsetKind"],))

    # v27: the table is no longer allowed to be empty.
    #
    # v25 shipped it empty on purpose and spent a whole device launch on
    # "no CloudKitSymbolOffsets entry, so there is no address to rewrite" - the
    # mechanism was armed and had nothing to aim at. The numbers themselves are
    # per OS build and are not pinned here; what is pinned is that both labels are
    # present and that each value is a hex number the runtime parser will accept,
    # because a value it refuses is the same wasted launch one stage later.
    offsets = config.get("CloudKitSymbolOffsets")
    if not isinstance(offsets, dict):
        fail("CloudKitSymbolOffsets",
             "must be a dictionary of label -> hex offset; a list or a bare string makes the "
             "resolver look up nothing and say nothing")
    else:
        for label, value in offsets.items():
            if not isinstance(label, str) or not isinstance(value, str):
                fail("CloudKitSymbolOffsets",
                     "%r -> %r: keys and values are strings" % (label, value))
            elif not is_hex_offset(value):
                fail("CloudKitSymbolOffsets",
                     "%s -> %r: not a hex offset by the runtime parser's own rule (optional "
                     "0x, hex digits, not zero). The parser refuses it and the entry it was "
                     "meant for resolves to nothing" % (label, value))

        for label in ("CKPersona.launch", "CKMainBundleIsAppleExecutable"):
            if label not in offsets:
                fail("CloudKitSymbolOffsets",
                     "no %r entry: v27 ships both numbers taken from the device crash report, "
                     "and the resolver reads them by these exact labels" % label)

    if "CloudKitStubMode" in config and config["CloudKitStubMode"] not in (
            "noAccount", "nil", "observe"):
        fail("CloudKitStubMode", "is %r, must be noAccount / nil / observe"
             % (config["CloudKitStubMode"],))

    # -- the two lists that make a mechanism narrow instead of blanket ----
    names = config.get("CloudKitExceptionNames")
    if not isinstance(names, list) or not names:
        fail("CloudKitExceptionNames",
             "must be a non-empty list; an empty allow list swallows nothing")
    elif not all(isinstance(name, str) for name in names):
        fail("CloudKitExceptionNames", "must contain strings only")
    elif "CKException" not in names:
        fail("CloudKitExceptionNames", "CKException must stay on the allow list")

    images = config.get("ThrowSwallowImages")
    if not isinstance(images, list) or not images:
        fail("ThrowSwallowImages",
             "must name at least one image; an empty filter is an unscoped swallow")
    elif not all(isinstance(image, str) for image in images):
        fail("ThrowSwallowImages", "must contain strings only")
    elif "CloudKit" not in images:
        fail("ThrowSwallowImages",
             "CloudKit must stay in the list - it is the image the v22 backtrace named, and "
             "a swallow scoped to some other image would answer for a second crash")

    budget = config.get("ThrowSwallowBudget")
    if isinstance(budget, int) and not isinstance(budget, bool) and budget < 0:
        fail("ThrowSwallowBudget", "is %d, must not be negative" % budget)

    classes = config.get("CloudKitQuarantineClasses")
    if not isinstance(classes, list):
        fail("CloudKitQuarantineClasses",
             "must be a list; the by-name sweep reads it")
    elif "CKPersona" not in classes:
        fail("CloudKitQuarantineClasses",
             "CKPersona must stay in the list - it is the class the v22 backtrace named")

    if not isinstance(config.get("EntitlementRepairValues"), dict):
        fail("EntitlementRepairValues", "must be a dictionary")

    resign = config.get("ResignFix")
    if not isinstance(resign, dict):
        fail("ResignFix", "must be a dictionary")
    else:
        if resign.get("Enabled") is not False:
            fail("ResignFix.Enabled", "must be false: the crash fixes are opt-in")
        if resign.get("AppGroupFallback") is not False:
            fail("ResignFix.AppGroupFallback",
                 "must be false: it invents an empty app group container, which is the most "
                 "likely way our own code could cause the crash")

    return problems


# -- selftest ------------------------------------------------------------
# One mutation per expectation, applied to a copy of the shipped config. The
# check must reject every one of them for its own key: a mutation that is caught
# by an unrelated rule would let the rule it targets rot.

def _mutations():
    def setter(key, value):
        def apply(config):
            config[key] = value
        return apply

    def dropper(key):
        def apply(config):
            config.pop(key, None)
        return apply

    def nested(key, inner, value):
        def apply(config):
            config[key][inner] = value
        return apply

    def drop_nested(key, inner):
        def apply(config):
            config[key].pop(inner, None)
        return apply

    table = [
        ("ConfigVersion goes back to 25", setter("ConfigVersion", 25)),
        ("ObserveOnly off", setter("ObserveOnly", False)),
        ("GuardEnabled on", setter("GuardEnabled", True)),
        ("RunLevel 3", setter("RunLevel", 3)),
        ("AutoBisect on", setter("AutoBisect", True)),
        ("ExperimentLadder on", setter("ExperimentLadder", True)),
        ("AllowCodePatching on", setter("AllowCodePatching", True)),
        ("CloudKitGuard off", setter("CloudKitGuard", False)),
        ("EntitlementRepair off", setter("EntitlementRepair", False)),
        ("DlsymTap off", setter("DlsymTap", False)),
        ("ThrowTap off", setter("ThrowTap", False)),
        ("EntitlementReadSurface off", setter("EntitlementReadSurface", False)),
        ("CloudKitStub off", setter("CloudKitStub", False)),
        ("symbol quarantine off", setter("CloudKitSymbolQuarantine", False)),
        ("symbol slot walk off", setter("CloudKitSymbolRebind", False)),
        ("symbol offsets stop being a dictionary", setter("CloudKitSymbolOffsets", [])),
        ("symbol offsets hold a non-string", setter("CloudKitSymbolOffsets", {"a": 1})),
        ("symbol offsets emptied again", setter("CloudKitSymbolOffsets", {})),
        ("a symbol offset is not hex", nested("CloudKitSymbolOffsets", "CKPersona.launch", "0x10G4")),
        ("a symbol offset has a trailing space",
         nested("CloudKitSymbolOffsets", "CKPersona.launch", "0x100DC ")),
        ("a symbol offset is zero", nested("CloudKitSymbolOffsets", "CKPersona.launch", "0")),
        ("a symbol offset loses its label",
         drop_nested("CloudKitSymbolOffsets", "CKMainBundleIsAppleExecutable")),
        ("offset kind invented", setter("CloudKitSymbolOffsetKind", "guess")),
        # The exact v23 CI failure, from both directions.
        ("swallow-at-site off again", setter("ThrowSwallowAtSite", False)),
        ("forced swallow turned back off", setter("ThrowSwallowForce", False)),
        ("forced swallow returns the exception object", setter("ThrowSwallowReturnNil", False)),
        ("swallow images emptied", setter("ThrowSwallowImages", [])),
        ("swallow images lose CloudKit", setter("ThrowSwallowImages", ["UIKitCore"])),
        ("swallow budget negative", setter("ThrowSwallowBudget", -1)),
        ("exception allow list emptied", setter("CloudKitExceptionNames", [])),
        ("CKException leaves the allow list", setter("CloudKitExceptionNames", ["NSException"])),
        ("stub mode invented", setter("CloudKitStubMode", "yes")),
        ("trace mode invented", setter("GuardTraceThrow", "sometimes")),
        ("quarantine classes lose CKPersona", setter("CloudKitQuarantineClasses", [])),
        ("repair values become a list", setter("EntitlementRepairValues", [])),
        ("resign fixes ship on", nested("ResignFix", "Enabled", True)),
        ("app group fallback ships on", nested("ResignFix", "AppGroupFallback", True)),
        ("ThrowSwallowAtSite removed", dropper("ThrowSwallowAtSite")),
        ("CloudKitQuarantineClasses removed", dropper("CloudKitQuarantineClasses")),
        ("ShowLaunchNotice becomes a string", setter("ShowLaunchNotice", "yes")),
    ]
    return table


def selftest(config):
    failures = 0

    clean = check(config)
    if clean:
        print("  FAIL  the shipped config is already rejected:")
        for problem in clean:
            print("        %s" % problem)
        failures += 1
    else:
        print("  ok    shipped config accepted")

    for description, mutate in _mutations():
        victim = copy.deepcopy(config)
        mutate(victim)
        problems = check(victim)
        if not problems:
            print("  FAIL  %-36s mutation survived" % description)
            failures += 1
        else:
            print("  ok    %-36s caught: %s" % (description, problems[0][:70]))

    if failures:
        print("\nselftest: %d expectation(s) unguarded" % failures, file=sys.stderr)
        return 1
    print("\nselftest: %d mutations caught" % (len(_mutations()) + 1))
    return 0


def load(path):
    with open(path, "rb") as handle:
        return plistlib.load(handle)


def main(argv):
    args = [arg for arg in argv[1:] if not arg.startswith("-")]
    path = args[0] if args else str(
        pathlib.Path(__file__).resolve().parent.parent / "config" / "GNUnlock.plist")

    try:
        config = load(path)
    except Exception as error:                      # noqa: BLE001 - report, do not trace
        print("error: %s does not parse: %s" % (path, error), file=sys.stderr)
        return 1

    if "--selftest" in argv:
        return selftest(config)

    problems = check(config)
    if problems:
        for problem in problems:
            print("error: %s" % problem, file=sys.stderr)
        print("\nplist_expect: %d problem(s) in %s" % (len(problems), path), file=sys.stderr)
        return 1

    print("plist ok: %d keys, ConfigVersion %d, run level %d"
          % (len(config), config["ConfigVersion"], config["RunLevel"]))
    print("ok: default config installs nothing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
