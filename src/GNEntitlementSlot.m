//
//  GNEntitlementSlot.m
//  The v16 answer to "the interposition armed but nothing was intercepted".
//
//  ======================= the question this has to answer =======================
//
//  v15 shipped a __DATA,__interpose table, logged "armed - intercepted for the
//  whole process", and the launch still died on the same CKException. An armed
//  interposition and an interposition that reaches the caller are different
//  facts, and the v15 log only reported the first one. That is the gap this file
//  exists to close: every mechanism is now installed *and measured*, in process,
//  at launch, with the result written to the same log.
//
//  ============================== the three layers ==============================
//
//  1. interpose (v15, kept)      dyld rewrites the process's *bindings* for the
//                                two SecTask functions.
//  2. slot rewrite (v16, new)    every import slot in every image - shared
//                                cache included - that currently holds either
//                                address is rewritten to point at the repair.
//                                See src/GNSlotScan.m for why this is not
//                                fishhook: the slot is found by the address it
//                                holds, because the cache keeps no symbol table.
//  3. the launch-time self-test  call the function twice - once through dlsym
//                                (the real function) and once through this
//                                dylib's own binding - and report the type of
//                                both answers. If they differ, interception is
//                                live in this process. If they do not, no
//                                data-only mechanism can see that read and the
//                                log says so instead of guessing.
//
//  Layer 3 is the part that was missing. It is not a diagnostic nicety: it is the
//  difference between "we shipped a hook" and "we know the hook fires here".
//
//  ============================== what is not done ==============================
//
//  No code page is written. Ever. The failure that killed the v5 attempt is
//  specific to that: a patched text page loses its signature and amfi kills the
//  task on the next instruction fetch (CODESIGNING / "Failed to fault in a page
//  with execute permissions"). An entry patch or an MSHookFunction style inline
//  hook cannot be made to work on a Distribution signature - not "risky", not
//  permitted - which is why neither of the two mechanisms in this file touches
//  one. Every byte written here belongs to a data page.
//
#import "GNEntitlementRepair.h"
#import "GNPrivateSecTask.h"
#import "GNThrowTrampoline.h"
#import "GNUnlock.h"

#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>

/// Every door CloudKit can use to read an entitlement, plus the one place every
/// Objective-C exception has to pass through.
///
/// v17 covered the two SecTask calls and found one of them ("the singular form")
/// reachable through an import slot and the other ("the plural") not reachable at
/// all: zero slots held its address, in 2622 images. That is a measurement, not a
/// refusal - it says the callers of the plural do not go through an import slot,
/// which leaves exactly two possibilities: a direct branch (inline in a code
/// page, unreachable for a data-only hook) or a pointer resolved once through
/// dlsym and cached (reachable, through GNDlsymTap below).
///
/// So v18 widens the net instead of guessing which one it is:
///
///   SecTaskCopyValueForEntitlement        the singular read (v16, works)
///   SecTaskCopyValuesForEntitlements      the plural read (v16, no slot found)
///   SecCodeCopySigningInformation         the entitlements dictionary inside the
///                                         signing information - the third public
///                                         door, and the one the v17 log suggested
///   objc_exception_throw                  not a repair: a tap, so the next launch
///                                         names the exception and the throw site
///                                         instead of leaving a bare EXC_CRASH
enum { GN_SLOT_SYMBOLS = 4 };

static const char *const kGNSlotSymbols[GN_SLOT_SYMBOLS] = {
    "SecTaskCopyValueForEntitlement",
    "SecTaskCopyValuesForEntitlements",
    "SecCodeCopySigningInformation",
    "objc_exception_throw",
};

static void *const kGNSlotReplacements[GN_SLOT_SYMBOLS] = {
    (void *)&GNRepairCopyValueForEntitlement,
    (void *)&GNRepairCopyValuesForEntitlements,
    (void *)&GNRepairCopySigningInformation,
    (void *)&GNThrowTrampolineObject,
};

/// Named indices, because two of the four entries are not repairs: one is a
/// second door onto the same value, the other is a tap that only records.
enum {
    GN_SLOT_SINGULAR = 0,
    GN_SLOT_PLURAL   = 1,
    GN_SLOT_SIGNING  = 2,
    GN_SLOT_THROW    = 3,
};

static void *gGNSlotTargets[GN_SLOT_SYMBOLS];
static bool  gGNSlotInstalled;
static int   gGNSlotFiredSelfTest = -1;      // -1 not run, 0 no, 1 yes
static char  gGNSlotStatus[256] = "not installed";
static char  gGNSlotSelfTest[192] = "not run";

#pragma mark - Describing a value for the log

/// "string \"*\"", "array(1)", "absent" - the type is the whole point here, so
/// the text says the type first and the content second.
static void GNSlotDescribe(CFTypeRef value, char *out, size_t size) {
    if (!out || size == 0) return;
    out[0] = '\0';

    if (!value) {
        snprintf(out, size, "absent");
        return;
    }

    if (CFGetTypeID(value) == CFStringGetTypeID()) {
        char text[64];
        if (!CFStringGetCString((CFStringRef)value, text, sizeof(text),
                                kCFStringEncodingUTF8)) {
            text[0] = '\0';
        }
        snprintf(out, size, "string \"%s\"", text);
        return;
    }

    if (CFGetTypeID(value) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount((CFArrayRef)value);
        char first[64];
        first[0] = '\0';
        if (count > 0) {
            CFTypeRef element = CFArrayGetValueAtIndex((CFArrayRef)value, 0);
            if (element && CFGetTypeID(element) == CFStringGetTypeID()) {
                if (!CFStringGetCString((CFStringRef)element, first, sizeof(first),
                                        kCFStringEncodingUTF8)) {
                    first[0] = '\0';
                }
            }
        }
        if (first[0]) snprintf(out, size, "array(%ld) [\"%s\", ...]", (long)count, first);
        else snprintf(out, size, "array(%ld)", (long)count);
        return;
    }

    if (CFGetTypeID(value) == CFDictionaryGetTypeID()) {
        snprintf(out, size, "dictionary(%ld)", (long)CFDictionaryGetCount((CFDictionaryRef)value));
        return;
    }

    snprintf(out, size, "type#%lu", (unsigned long)CFGetTypeID(value));
}

/// "dictionary(3) icloud-services=array(1) [\"CloudKit\", ...]" - for the plural
/// self-test, where the interesting part is the *entry inside* the dictionary and
/// not the dictionary itself.
static void GNSlotDescribeDictionaryEntry(CFTypeRef value, CFStringRef key,
                                          char *out, size_t size) {
    if (!out || size == 0) return;
    out[0] = '\0';

    if (!value) { snprintf(out, size, "absent"); return; }
    if (CFGetTypeID(value) != CFDictionaryGetTypeID()) {
        GNSlotDescribe(value, out, size);
        return;
    }

    CFDictionaryRef dictionary = (CFDictionaryRef)value;
    CFIndex count = CFDictionaryGetCount(dictionary);
    CFTypeRef entry = key ? CFDictionaryGetValue(dictionary, key) : NULL;

    char entryText[160];
    GNSlotDescribe(entry, entryText, sizeof(entryText));

    char keyText[96];
    keyText[0] = '\0';
    if (key) {
        (void)CFStringGetCString(key, keyText, (CFIndex)sizeof(keyText),
                                 kCFStringEncodingUTF8);
    }
    snprintf(out, size, "dictionary(%ld) %s=%s", (long)count, keyText[0] ? keyText : "?",
             entryText);
}

/// The plural read, measured the same way the singular one is.
///
/// This is the part v17 could not answer. Its log said the plural function had
/// found zero slots, and a zero there has three possible meanings - no caller, a
/// direct branch, or a cached pointer - which the old code could not tell apart.
/// Now the dylib calls the plural read twice at launch, through dlsym (the real
/// function) and through its own binding, and prints the value CloudKit would get
/// from each. If the two differ, the plural path is intercepted in this process.
/// If they are identical, the zeros in the slot line are the whole story and the
/// only remaining fix is at signing time.
static void GNSlotRunPluralSelfTest(GNSecTaskHandle task, CFStringRef key) {
    if (!GNEntitlementValuesImportBound()) {
        GNLogC("slot: self-test  plural: the symbol is absent, so there is no binding to "
               "measure - only the singular read exists here");
        return;
    }

    const void *one = (const void *)key;
    CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault, &one, 1, &kCFTypeArrayCallBacks);
    if (!keys) return;

    int32_t beforePlural = GNEntitlementRepairCount();
    CFTypeRef direct = GNPrivateSecTaskCopyValues(task, keys);
    CFTypeRef bound = GNEntitlementCallValuesThroughImport((CFTypeRef)task, keys, NULL);
    int32_t afterPlural = GNEntitlementRepairCount();

    char directText[192];
    char boundText[192];
    GNSlotDescribeDictionaryEntry(direct, key, directText, sizeof(directText));
    GNSlotDescribeDictionaryEntry(bound, key, boundText, sizeof(boundText));

    GNLogC("slot: self-test  plural, direct (dlsym, the real function) : %s", directText);
    GNLogC("slot: self-test  plural, through this dylib's binding      : %s", boundText);

    if (afterPlural > beforePlural) {
        GNLogC("slot: self-test  VERDICT (plural): interception is LIVE - CloudKit's "
               "batch read is answered by this dylib");
    } else if (direct && bound) {
        GNLogC("slot: self-test  VERDICT (plural): NOT intercepted - the binding did not "
               "reach the replacement. If the launch still dies on an entitlement value, "
               "that read went through a direct branch and only the signer can fix it.");
    }

    if (direct) CFRelease(direct);
    if (bound) CFRelease(bound);
    CFRelease(keys);
}

#pragma mark - Install

#pragma mark - The self-test

/// Calls the same entitlement through the two paths that differ in exactly one
/// respect - whether an import binding is in the middle - and reports both.
///
/// The repair counter is the arbiter rather than a comparison of the two values:
/// a value can look "repaired" for reasons that have nothing to do with us
/// (a corrected signature, a different entitlement set), while the counter can
/// only move when *our* replacement ran.
static void GNSlotRunSelfTest(void) {
    static const char *const keyName = "com.apple.developer.icloud-services";

    // v19: this function calls a door on purpose, to prove the binding is ours.
    // The audit that answers "did CloudKit ever ask" must not count our own
    // probe as a caller, or the one number that decides the next step becomes an
    // artefact of the measurement itself.
    GNReadAuditSuspend();

    CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, keyName,
                                                kCFStringEncodingUTF8);
    GNSecTaskHandle task = GNPrivateSecTaskCreateFromSelf();
    if (!key || !task) {
        snprintf(gGNSlotSelfTest, sizeof(gGNSlotSelfTest),
                 "skipped (no SecTask in this process)");
        GNLogC("slot: self-test skipped - %s", gGNSlotSelfTest);
        if (key) CFRelease(key);
        if (task) CFRelease(task);
        GNReadAuditResume();
        return;
    }

    int32_t before = GNEntitlementRepairCount();

    // Path A: the real function, reached through dlsym. dyld does not apply an
    // interpose to dlsym, so this is what the signature actually says.
    CFTypeRef direct = GNPrivateSecTaskCopyEntitlement(task, key);
    char directText[160];
    GNSlotDescribe(direct, directText, sizeof(directText));

    // Path B: the same call through this dylib's own import binding.
    CFTypeRef bound = GNEntitlementCallThroughImport((CFTypeRef)task, key, NULL);
    char boundText[160];
    GNSlotDescribe(bound, boundText, sizeof(boundText));

    int32_t after = GNEntitlementRepairCount();
    gGNSlotFiredSelfTest = (after > before) ? 1 : 0;

    snprintf(gGNSlotSelfTest, sizeof(gGNSlotSelfTest), "%s -> %s (%s)",
             directText, boundText,
             gGNSlotFiredSelfTest ? "replacement ran" : "replacement did not run");

    GNLogC("slot: self-test  direct (dlsym, the real function) : %s", directText);
    GNLogC("slot: self-test  through this dylib's binding      : %s", boundText);

    if (gGNSlotFiredSelfTest) {
        GNLogC("slot: self-test  VERDICT: interception is LIVE in this process "
               "(repair counter %d -> %d)", (int)before, (int)after);
    } else {
        GNLogC("slot: self-test  VERDICT: interception did NOT run for this call. "
               "Either the binding is not ours in this process, or the read happens "
               "somewhere no data-only hook can see.");
    }

    if (direct) CFRelease(direct);
    if (bound) CFRelease(bound);

    // v18: the same measurement for the plural read, which is the one v17's log
    // showed zero slots for. Nothing about it is assumed now.
    GNSlotRunPluralSelfTest(task, key);

    CFRelease(key);
    CFRelease(task);
    GNReadAuditResume();
}

void GNInstallEntitlementSlotHook(NSDictionary *cfg) {
    (void)cfg;
    if (gGNSlotInstalled) return;
    gGNSlotInstalled = true;

    if (!GNCFG(@"EntitlementSlotRebind", YES)) {
        snprintf(gGNSlotStatus, sizeof(gGNSlotStatus), "disabled by config");
        GNLogC("slot: disabled by config - a CKException from a malformed iCloud "
               "entitlement kills the launch again");
        return;
    }

    if (GNSafeModeActive()) {
        snprintf(gGNSlotStatus, sizeof(gGNSlotStatus), "skipped (safe mode)");
        GNLogC("slot: safe mode (the previous launch died in our code) - not installed");
        return;
    }

    int32_t sections = 0;
    int32_t found = 0;
    int32_t unreachable = 0;

    for (int i = 0; i < GN_SLOT_SYMBOLS; i++) {
        // The throw tap is a diagnostic, not a repair: it can be switched off
        // without losing the entitlement answer. Everything else stays on, because
        // each one is a door CloudKit can read the same value through.
        if (i == GN_SLOT_THROW && !GNCFG(@"ThrowTap", YES)) {
            GNLogC("slot: throw tap disabled by config - an exception thrown from a "
                   "shared cache image will be anonymous again");
            continue;
        }

        int32_t before = GNSlotRewriteCount();
        int32_t here = GNSlotRebindSymbol(kGNSlotSymbols[i], kGNSlotReplacements[i],
                                          &gGNSlotTargets[i], true);
        int32_t rewrote = GNSlotRewriteCount() - before;

        sections += here;
        if (here > 0) found++;

        // One line per symbol, stating which of the three worlds it is in. A
        // count of zero has to be explained at the place it was measured, not
        // summed into a total that hides which function it was about.
        if (rewrote > 0) {
            GNLogC("slot: '%s' reachable: %d slot(s) rewritten", kGNSlotSymbols[i],
                   (int)rewrote);
        } else if (here == 0) {
            unreachable++;
            GNLogC("slot: '%s' UNREACHABLE: no image in this process imports it through a "
                   "slot, so its callers use a direct branch or a value resolved once and "
                   "cached. The second case is covered by the dlsym tap below; the first "
                   "cannot be fixed in process.", kGNSlotSymbols[i]);
        } else {
            unreachable++;
            GNLogC("slot: '%s' unreachable: %d slot section(s) walked, none held its "
                   "address", kGNSlotSymbols[i], (int)here);
        }

        // The throw tap needs the real function the walker resolved, and it has to
        // be armed before the first interesting throw - which is during app
        // initialisation, i.e. after this constructor returns.
        if (i == GN_SLOT_THROW && gGNSlotTargets[i]) {
            GNThrowTapActivate(gGNSlotTargets[i]);
            // v20: the object the slot now points at is the trampoline, not the
            // tap. It needs the same real function, handed over before the first
            // interesting throw - which is during app initialisation, i.e. after
            // this constructor returns.
            GNThrowTrampolineArm(gGNSlotTargets[i]);
        }
    }

    if (GNCFG(@"EntitlementSlotSelfTest", YES)) {
        GNSlotRunSelfTest();
    } else {
        snprintf(gGNSlotSelfTest, sizeof(gGNSlotSelfTest), "disabled by config");
        GNLogC("slot: self-test disabled by config - the next log cannot say whether "
               "the hook fires");
    }

    snprintf(gGNSlotStatus, sizeof(gGNSlotStatus),
             "armed (symbols=%d/%d, sections=%d, rewritten=%d, refused=%d, fired=%s)",
             found, GN_SLOT_SYMBOLS, (int)sections, (int)GNSlotRewriteCount(),
             (int)GNSlotRefusedCount(),
             gGNSlotFiredSelfTest == 1 ? "yes" : (gGNSlotFiredSelfTest == 0 ? "no" : "n/a"));

    GNLogC("slot: %s", gGNSlotStatus);

    // The paragraph worth reading when the launch still dies. It states which of
    // the three worlds this process is in, using the measurements above rather
    // than a theory about dyld.
    if (sections == 0) {
        GNLogC("slot: no import slot section in any image held any of the %d symbols. "
               "Every caller reaches them through a direct branch, which is inline in a "
               "code page - unreachable for a data-only hook on a Distribution signature. "
               "The value has to be fixed at signing time.", GN_SLOT_SYMBOLS);
    } else if (gGNSlotFiredSelfTest != 1) {
        GNLogC("slot: %d of %d symbol(s) could not be reached in this process, and the "
               "self-test call through the binding did not reach the replacement. What "
               "the log above says per symbol is the measurement; the dlsym tap line says "
               "whether a lookup-resolved read was caught instead.",
               (int)unreachable, GN_SLOT_SYMBOLS);
    } else {
        GNLogC("slot: live. CloudKit's entitlement read is intercepted in process; "
               "no CKException should be raised for a malformed iCloud type.");
    }
}

#pragma mark - Reporting

const char *GNEntitlementSlotStatus(void) {
    return gGNSlotStatus;
}

const char *GNEntitlementSlotSelfTestText(void) {
    return gGNSlotSelfTest;
}

#pragma mark - The read surface (v20)

/// Every public door an entitlement can be read through, measured - not hooked.
///
/// Why a separate sweep
/// --------------------
/// v19 ended with an unexplained pair of facts: the SecTask reads were proven
/// LIVE on the device, and CloudKit still raised CKException("malformed
/// entitlements"). Either the value comes from a reader this dylib never armed,
/// or the check does not read the app's own task at all. Choosing between those
/// by argument is what the last four versions did, and it did not converge.
///
/// This lists the doors instead. Each line is one symbol, whether this process
/// has it, and how many import slots in how many images hold its address. A
/// symbol with zero slots has no caller that goes through a slot - which is a
/// different statement from "has no caller", and the two are printed separately.
///
/// Deliberately not hooked: this sweep only counts. Adding a rewrite for a symbol
/// whose role is guessed is how a launch gets lost for a measurement that was not
/// needed.
static const char *const kGNReadSurface[] = {
    "SecTaskCopyValueForEntitlement",
    "SecTaskCopyValuesForEntitlements",
    "SecTaskCreateFromSelf",
    "SecTaskCreateWithAuditToken",
    "SecTaskGetTypeID",
    "SecCodeCopySigningInformation",
    "SecCodeCopySelf",
    "SecCodeCopyGuestWithAttributes",
    "SecStaticCodeCreateWithPath",
    "SecCodeCheckValidity",
    "SecCodeCheckValidityWithErrors",
    "xpc_copy_entitlement_for_self",
    "xpc_copy_entitlement_for_token",
    // The mach-service variant used to be listed here and it never belonged: it is
    // not a door an entitlement is read through, and on iOS Apple marks it
    // __attribute__((unavailable)), so naming it in this array is a front end
    // error on the real SDK. v22 dropped it; xpc_copy_entitlement_for_self is the
    // entry that answers the same question.
};

void GNEntitlementReadSurfaceDump(void) {
    if (!GNCFG(@"EntitlementReadSurface", YES)) {
        GNLogC("reads: read-surface sweep disabled by config");
        return;
    }

    const int count = (int)(sizeof(kGNReadSurface) / sizeof(kGNReadSurface[0]));
    int present = 0;
    int withSlots = 0;

    GNLogC("reads: sweeping %d entitlement door(s) across every loaded image - counted, "
           "never rewritten", count);

    for (int i = 0; i < count; i++) {
        void *resolved = NULL;
        int32_t matchBefore = GNSlotMatchCount();
        int32_t sections = GNSlotProbeSymbol(kGNReadSurface[i], &resolved);
        int32_t matches = GNSlotMatchCount() - matchBefore;

        if (!resolved) {
            GNLogC("reads:   %-38s absent  - no image in this process exports it",
                   kGNReadSurface[i]);
            continue;
        }
        present++;
        if (matches > 0) withSlots++;

        GNLogC("reads:   %-38s %p  %d slot(s) in %d section(s) - %s",
               kGNReadSurface[i], resolved, (int)matches, (int)sections,
               matches > 0 ? "callers go through an import slot"
                           : "no caller reaches it through a slot");
    }

    GNLogC("reads: %d of %d symbol(s) present, %d reachable through a slot", present, count,
           withSlots);
    GNLogC("reads: a symbol absent here cannot be the reader. A symbol present with zero "
           "slots is either called by direct branch or resolved once and cached - and a "
           "cached resolution goes through the dlsym tap, whose hit count is logged above. "
           "If CKException still appears with every door accounted for, the check is not "
           "reading this process's own task and no in-process hook can answer it.");
}
