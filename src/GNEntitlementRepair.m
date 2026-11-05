//
//  GNEntitlementRepair.m
//  The policy half. GNEntitlementRepairInterpose.m owns the table; this file
//  decides what a repaired answer looks like.
//
//  ============================ what the log said ============================
//
//      probe: com.apple.developer.icloud-services = *
//      EXCEPTION name=CKException
//                reason=Application has malformed entitlements. Found value "*"
//                       for entitlement com.apple.developer.icloud-services,
//                       expected an array of strings
//
//  CloudKit reads its own entitlements in process, finds a string where the
//  schema says "array of strings", and throws. v14 answered that by swallowing
//  the exception at -[NSException raise]; the next launch proved CloudKit does
//  not use -raise (it uses @throw, which calls objc_exception_throw directly).
//
//  ===================== why the answer is a type repair =====================
//
//  The other candidate was to hook objc_exception_throw and return without
//  throwing. That is not a fix, it is a fall-through: the call is the last
//  instruction of its basic block because the compiler knows it does not return,
//  so "returning" from it resumes at whatever bytes happen to follow - a
//  landing pad, padding, or the next function's prologue - with the registers
//  the throw was about to use. In CloudKit that code sits inside a dispatch_once
//  during app initialisation; a corrupted continuation there is a worse crash
//  than the one being avoided, and it is not reproducible.
//
//  Repairing the value has no such tail: the exception is never constructed,
//  CloudKit takes its ordinary success path, and every other caller in the
//  process sees exactly what the signature says. The cost is that the repair has
//  to be *correct* rather than merely survivable - hence the narrow rules below.
//
//  ============================== the rules ==============================
//
//  Four keys, from the message itself and from Apple's entitlement schema:
//
//      com.apple.developer.icloud-services                  array of strings
//      com.apple.developer.icloud-container-identifiers      array of strings
//      com.apple.developer.ubiquity-container-identifiers    array of strings
//      com.apple.developer.ubiquity-kvstore-identifier       string
//
//  A value is rewritten only when its *type* is wrong, or when it is the literal
//  wildcard "*" that a signer writes when it does not know the real value. A
//  correctly typed value passes through untouched, whatever it contains - this
//  is a type repair, not a grant, and it cannot make iCloud work on a
//  Distribution certificate. Nothing here invents an entitlement the signature
//  does not have; it only stops a malformed one from killing the launch.
//
//  Nothing in this file is Foundation. It can be reached during dyld init, from
//  another image's initialiser, before this dylib's constructor has run - the
//  beacon taught that lesson the expensive way. CoreFoundation only: CFRetain,
//  CFRelease, CFGetTypeID, CFStringGetCString, CFArrayCreate, dlsym.
//

#import "GNUnlock.h"
#import "GNEntitlementRepair.h"
#import "GNRepairPolicy.h"
#import "GNInterposeReal.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#pragma mark - Types

typedef CFTypeRef (*GNCopyValueFn)(const void *task, CFStringRef key, CFErrorRef *error);
typedef CFTypeRef (*GNCopyValuesFn)(const void *task, CFArrayRef keys, CFErrorRef *error);

/// SecCodeCopySigningInformation's ABI: (SecCodeRef, SecCSFlags, CFDictionaryRef *).
/// SecCodeRef is opaque and SecCSFlags is a uint32_t, so no Apple type has to be
/// named here; this declaration exists because that function is public API and
/// one of the paths CloudKit can use to read the entitlements dictionary.
typedef uint32_t (*GNCodeCopySigningInformationFn)(const void *code, uint32_t flags,
                                                   CFDictionaryRef *information);

/// What Apple's schema requires for a key, and how to answer when the value the
/// signature carries cannot be used. `expect` is the GNRExpect enum from
/// src/GNRepairPolicy.h - the decision itself no longer lives in this file.
typedef struct {
    const char *key;
    GNRExpect   expect;
    const char *literal;    // used when usesBundle is NO
    const char *prefix;     // prepended to the bundle id when usesBundle is YES
    BOOL        usesBundle;
} GNRule;

/// The iCloud family, i.e. exactly the keys CloudKit validates before it will
/// talk to anything. Each one is here because its *type* is enforced:
///
///   icloud-services                  array of strings   ("*" is a string)
///   icloud-container-identifiers     array of strings
///   ubiquity-container-identifiers   array of strings
///   ubiquity-kvstore-identifier      string
///   icloud-container-environment     string ("Development" / "Production")
///   icloud-container-development-…   array of strings
///
/// A key outside this family is never touched, whatever it contains: the crash
/// is about these, and widening the repair would be inventing entitlements.
static const GNRule gRules[] = {
    { "com.apple.developer.icloud-services",
      GNRExpectStringArray, "CloudKit", NULL,       NO  },
    { "com.apple.developer.icloud-container-identifiers",
      GNRExpectStringArray, NULL,       "iCloud.",  YES },
    { "com.apple.developer.icloud-container-development-container-identifiers",
      GNRExpectStringArray, NULL,       "iCloud.",  YES },
    { "com.apple.developer.ubiquity-container-identifiers",
      GNRExpectStringArray, NULL,       "iCloud.",  YES },
    { "com.apple.developer.ubiquity-kvstore-identifier",
      GNRExpectString,      NULL,       "",         YES },
    { "com.apple.developer.icloud-container-environment",
      GNRExpectString,      "Production", NULL,     NO  },
};

#pragma mark - State

static GNCopyValueFn  gOriginalCopyValue;
static GNCopyValuesFn gOriginalCopyValues;
static GNCodeCopySigningInformationFn gOriginalCopySigningInformation;

static BOOL gInstalled;
static BOOL gFillMissing;

/// Per rule text, filled from EntitlementRepairValues at install time: the same
/// dylib answering with the container and team values the signature really has,
/// without a rebuild. Empty means "use the rule's built-in default".
enum { GNRuleCount = (int)(sizeof(gRules) / sizeof(gRules[0])) };
static const size_t gRuleCount = sizeof(gRules) / sizeof(gRules[0]);
static char gOverrideText[sizeof(gRules) / sizeof(gRules[0])][128];

static volatile int32_t gRepairCount;
static volatile int32_t gDepth;
static volatile int32_t gLogBudget = 6;

static char gStatus[192] = "not installed";

#pragma mark - Small helpers

/// YES when `key` is our name. Buffer-bounded on purpose: an entitlement name
/// longer than the buffer is not one of the four, and CFStringGetCString says so
/// rather than truncating into a false match.
static BOOL GNKeyEquals(CFStringRef key, const char *name) {
    char text[128];
    if (!CFStringGetCString(key, text, (CFIndex)sizeof(text), kCFStringEncodingUTF8)) return NO;
    return strcmp(text, name) == 0;
}

static const GNRule *GNRuleForKey(CFStringRef key) {
    for (size_t i = 0; i < sizeof(gRules) / sizeof(gRules[0]); i++) {
        if (GNKeyEquals(key, gRules[i].key)) return &gRules[i];
    }
    return NULL;
}

/// The main bundle's identifier, without Foundation. Empty on failure, which is
/// handled by the callers: the value then carries no suffix rather than "iCloud."
/// followed by nothing.
static void GNBundleIdentifierString(char *out, size_t size) {
    if (!out || size == 0) return;
    out[0] = '\0';

    CFBundleRef bundle = CFBundleGetMainBundle();
    if (!bundle) return;

    CFStringRef identifier = CFBundleGetIdentifier(bundle);
    if (!identifier) return;

    (void)CFStringGetCString(identifier, out, (CFIndex)size, kCFStringEncodingUTF8);
}

/// "*" is what some signers write when they do not know the real value. An empty
/// string is the same mistake spelled differently, and CloudKit rejects both by
/// type, so both are repaired.
static BOOL GNIsWildcardString(CFStringRef string) {
    char text[8];
    if (!CFStringGetCString(string, text, (CFIndex)sizeof(text), kCFStringEncodingUTF8)) return NO;
    return text[0] == '\0' || (text[0] == '*' && text[1] == '\0');
}

static BOOL GNArrayHoldsOnlyStrings(CFArrayRef array) {
    CFIndex count = CFArrayGetCount(array);
    for (CFIndex i = 0; i < count; i++) {
        CFTypeRef entry = (CFTypeRef)CFArrayGetValueAtIndex(array, i);
        if (!entry || CFGetTypeID(entry) != CFStringGetTypeID()) return NO;
    }
    return YES;
}

/// Turns a CF value into the planner's vocabulary.
///
/// This is the only place in the tree where a CoreFoundation type id becomes a
/// decision input, and it is deliberately dumb: it reports what is there and
/// decides nothing. Everything downstream is the pure C policy in
/// src/GNRepairPolicy.h, which is executable on the build host.
static void GNPlanValueKind(CFTypeRef value, GNRKind *kind, int *isWildcard,
                            int *arrayAllStrings, long *arrayCount) {
    *kind = GNRKindAbsent;
    *isWildcard = 0;
    *arrayAllStrings = 0;
    *arrayCount = 0;
    if (!value) return;

    if (CFGetTypeID(value) == CFStringGetTypeID()) {
        *kind = GNRKindString;
        *isWildcard = GNIsWildcardString((CFStringRef)value) ? 1 : 0;
        return;
    }

    if (CFGetTypeID(value) == CFArrayGetTypeID()) {
        CFArrayRef array = (CFArrayRef)value;
        *kind = GNRKindArray;
        *arrayCount = (long)CFArrayGetCount(array);
        *arrayAllStrings = GNArrayHoldsOnlyStrings(array) ? 1 : 0;
        return;
    }

    *kind = GNRKindOther;
}

/// The gate that keeps this a type repair.
///
/// A value whose type is already correct is never touched - not for being
/// empty, not for naming a container that does not exist. Rewriting *those*
/// would be inventing data, which is a different change with different
/// consequences, and it is not what the crash is about.
///
/// v18 note: the answer is now computed by src/GNRepairPolicy.h rather than
/// spelled out here. v17 spelled it out, and the spelling was wrong in a way
/// that survived a build, a device launch and a "VERDICT: interception is LIVE"
/// line: a rule that wants an array of strings was answered with a bare string.
/// The decision is pure C now, and scripts/repair_policy_test.c executes every
/// combination of inputs against the rule - including the one from the log.
static BOOL GNValueIsCorrect(CFTypeRef value, GNRExpect expect) {
    if (!value) return NO;

    GNRKind kind = GNRKindAbsent;
    int isWildcard = 0;
    int arrayAllStrings = 0;
    long arrayCount = 0;
    GNPlanValueKind(value, &kind, &isWildcard, &arrayAllStrings, &arrayCount);

    GNRPlan plan = GNRPlanRepair(expect, kind, isWildcard, arrayAllStrings, arrayCount,
                                 gFillMissing ? 1 : 0);
    return plan.change ? NO : YES;
}

/// "string \"*\"", "array(2)", "type#42" - for the log, never for a decision.
static void GNDescribeValue(CFTypeRef value, char *out, size_t size) {
    if (!out || size == 0) return;
    if (!value) { snprintf(out, size, "(absent)"); return; }

    CFTypeID type = CFGetTypeID(value);
    if (type == CFStringGetTypeID()) {
        char text[128];
        if (CFStringGetCString((CFStringRef)value, text, (CFIndex)sizeof(text),
                               kCFStringEncodingUTF8)) {
            snprintf(out, size, "string \"%s\"", text);
        } else {
            snprintf(out, size, "string (unreadable)");
        }
        return;
    }
    if (type == CFArrayGetTypeID()) {
        snprintf(out, size, "array(%ld)", (long)CFArrayGetCount((CFArrayRef)value));
        return;
    }
    snprintf(out, size, "type#%lu", (unsigned long)type);
}

#pragma mark - Building the repaired value

static CFTypeRef GNCopyStringFromCString(const char *text) {
    if (!text || !text[0]) return NULL;
    return CFStringCreateWithCString(kCFAllocatorDefault, text,
                                     kCFStringEncodingUTF8);
}

static CFTypeRef GNCopySingleElementArray(CFStringRef element) {
    if (!element) return NULL;
    const void *one = (const void *)element;
    return CFArrayCreate(kCFAllocatorDefault, &one, 1, &kCFTypeArrayCallBacks);
}

/// The value to answer with when the real one is unusable.
///
/// icloud-services: "CloudKit" is the only service a CloudKit client can ask for
/// here, and it is the exact value the exception message asks for.
///
/// container identifiers: iCloud.<bundle id>, which is the string the signer
/// should have written (Apple's own template is iCloud.$(CFBundleIdentifier)).
///
/// kvstore identifier: <bundle id>. Apple's template is
/// $(TeamIdentifierPrefix)$(CFBundleIdentifier); the team prefix is exactly what
/// this process cannot read reliably on a re-signed build, and a string without
/// it is still the right *type*, which is what this module is about.
/// The literal for a rule, with the plist's override winning.
///
/// EntitlementRepairValues lets the same dylib answer with the container and
/// team values the signature really has, without a rebuild. Defaults:
///
///   icloud-services: "CloudKit"            the only service CloudKit can be
///                                          asked for, and the value the
///                                          exception text names
///   container ids:   iCloud.<bundle id>    Apple's own template
///   kvstore id:      <bundle id>           the team prefix is exactly what a
///                                          re-signed build cannot read
///   environment:     "Production"
static const char *GNLiteralForRule(const GNRule *rule) {
    if (!rule) return NULL;
    size_t index = (size_t)(rule - gRules);
    if (index < gRuleCount && gOverrideText[index][0]) return gOverrideText[index];
    return rule->literal;
}

/// The string a plan asks for, as a +1 CFStringRef.
static CFTypeRef GNCopySourcedString(const GNRule *rule, const GNRPlan *plan,
                                     CFTypeRef value) {
    switch (plan->source) {
        case GNRSourceKeptString:
            // The value is right, only its shape is wrong.
            return value ? (CFTypeRef)CFRetain(value) : NULL;

        case GNRSourceFirstString: {
            if (!value || CFGetTypeID(value) != CFArrayGetTypeID()) return NULL;
            CFArrayRef array = (CFArrayRef)value;
            if (CFArrayGetCount(array) == 0) return NULL;
            CFTypeRef first = (CFTypeRef)CFArrayGetValueAtIndex(array, 0);
            if (!first || CFGetTypeID(first) != CFStringGetTypeID()) return NULL;
            return (CFTypeRef)CFRetain(first);
        }

        case GNRSourceBundle: {
            char text[256];
            char bundle[192];
            GNBundleIdentifierString(bundle, sizeof(bundle));
            if (!bundle[0]) return NULL;
            snprintf(text, sizeof(text), "%s%s", rule->prefix ? rule->prefix : "", bundle);
            return GNCopyStringFromCString(text);
        }

        case GNRSourceLiteral:
        default:
            return GNCopyStringFromCString(GNLiteralForRule(rule));
    }
}

/// Returns a +1 value, or NULL when nothing should change.
///
/// v18: no per-key logic and no "if it is a string, wrap it" branch. The shape
/// comes from GNRPlanRepair(), which scripts/repair_policy_test.c exercises over
/// every combination of inputs. v17 answered an array rule with a bare string
/// because the wrapping lived in one branch and the wildcard path took another;
/// there is no second path now for a plan to fall through.
static CFTypeRef GNCopyRepairedValue(const GNRule *rule, CFTypeRef value) {
    GNRKind kind = GNRKindAbsent;
    int isWildcard = 0;
    int arrayAllStrings = 0;
    long arrayCount = 0;
    GNPlanValueKind(value, &kind, &isWildcard, &arrayAllStrings, &arrayCount);

    GNRPlan plan = GNRPlanRepair(rule->expect, kind, isWildcard, arrayAllStrings,
                                 arrayCount, gFillMissing ? 1 : 0);
    if (!plan.change) return NULL;

    CFTypeRef scalar = GNCopySourcedString(rule, &plan, value);
    if (!scalar) return NULL;

    if (plan.produce == GNRKindArray) {
        CFTypeRef array = GNCopySingleElementArray((CFStringRef)scalar);
        CFRelease(scalar);
        return array;
    }

    if (CFGetTypeID(scalar) != CFStringGetTypeID()) {
        CFRelease(scalar);
        return NULL;
    }
    return scalar;
}

/// Takes ownership of `value` (+1) and returns +1: either the same value,
/// untouched, or a replacement after the original has been released.
static CFTypeRef GNRepairApply(CFStringRef key, CFTypeRef value) {
    if (!key || CFGetTypeID(key) != CFStringGetTypeID()) return value;

    const GNRule *rule = GNRuleForKey(key);
    if (!rule) return value;

    if (GNValueIsCorrect(value, rule->expect)) return value;

    // Absent is not a type error: a key the signature does not carry is the
    // signature's business, and inventing one would be a grant.
    if (!value && !gFillMissing) return value;

    CFTypeRef replacement = GNCopyRepairedValue(rule, value);
    if (!replacement) return value;

    int32_t index = __atomic_add_fetch(&gRepairCount, 1, __ATOMIC_SEQ_CST);
    if (index <= gLogBudget) {
        char before[192];
        char after[192];
        GNDescribeValue(value, before, sizeof(before));
        GNDescribeValue(replacement, after, sizeof(after));
        GNLogC("repair: #%d %s (schema wants %s): %s -> %s", (int)index, rule->key,
               rule->expect == GNRExpectStringArray ? "array of strings" : "string",
               before, after);
    }

    if (value) CFRelease(value);
    return replacement;
}

#pragma mark - The replacements

/// The address each replacement must call through is the *real* function, and the
/// obvious way to ask for it is not safe on its own: dyld applies an interpose
/// table to a dlsym result - in dyld4 the result of every lookup ends in
/// interpose(state, resolved) - so on a launch where that happens dlsym hands back
/// this dylib's own replacement, and the call-through recurses until the stack
/// ends, during app initialisation.
///
/// v18 checked that by hand for these two symbols and then had nothing to fall back
/// on. v22 goes through GNInterposeReal(), which keeps the check and adds a second
/// source: the replacee half of the tuple in src/GNEntitlementRepairInterpose.m,
/// i.e. the pointer dyld read in order to install the replacement. If the
/// replacement is running at all, that half holds the real function.
static void GNResolveOriginals(void) {
    if (!gOriginalCopyValue) {
        gOriginalCopyValue = (GNCopyValueFn)GNInterposeReal(
            "SecTaskCopyValueForEntitlement", GNEntitlementInterposeBoundTarget(0),
            (const void *)&GNRepairCopyValueForEntitlement, "repair");
    }
    if (!gOriginalCopyValues) {
        gOriginalCopyValues = (GNCopyValuesFn)GNInterposeReal(
            "SecTaskCopyValuesForEntitlements", GNEntitlementInterposeBoundTarget(1),
            (const void *)&GNRepairCopyValuesForEntitlements, "repair");
    }
    if (!gOriginalCopySigningInformation) {
        // Public API, and not interposed by this dylib: there is no tuple half to
        // fall back to. Same check, second source absent, which is the honest
        // description of a symbol this dylib never replaced.
        gOriginalCopySigningInformation = (GNCodeCopySigningInformationFn)GNInterposeReal(
            "SecCodeCopySigningInformation", NULL,
            (const void *)&GNRepairCopySigningInformation, "repair");
    }
}

static CFTypeRef GNRepairSingleImpl(const void *task, CFStringRef entitlement,
                                    CFErrorRef *error) {
    GNResolveOriginals();
    if (!gOriginalCopyValue) {
        if (error) *error = NULL;
        return NULL;
    }

    // Belt and braces. Chaining through dlsym cannot recurse into this function,
    // but a pathological caller in the middle of dyld init should get an
    // untouched answer rather than a stack that never unwinds. The guard answers
    // with NULL instead of calling through: if four nested entries happened, the
    // call-through itself is what is looping, and calling it a fifth time is the
    // one thing that cannot help.
    if (__atomic_add_fetch(&gDepth, 1, __ATOMIC_SEQ_CST) > 4) {
        __atomic_sub_fetch(&gDepth, 1, __ATOMIC_SEQ_CST);
        GNLogC("repair: re-entry guard - answered without repairing and without "
               "calling through");
        if (error) *error = NULL;
        return NULL;
    }

    CFTypeRef value = gOriginalCopyValue(task, entitlement, error);
    CFTypeRef result = GNRepairApply(entitlement, value);

    __atomic_sub_fetch(&gDepth, 1, __ATOMIC_SEQ_CST);
    return result;
}

/// The door itself. Everything below this line is unchanged behaviour; the only
/// addition is that the call is now attributed - door, caller return address,
/// and whether the answer was rewritten. v18 could prove the replacement ran;
/// it could not say on whose call. That is the distinction that decided v19, so
/// it is measured rather than assumed.
CFTypeRef GNRepairCopyValueForEntitlement(const void *task, CFStringRef entitlement,
                                          CFErrorRef *error) {
    const void *caller = __builtin_return_address(0);
    int32_t before = (int32_t)__atomic_load_n(&gRepairCount, __ATOMIC_SEQ_CST);
    CFTypeRef result = GNRepairSingleImpl(task, entitlement, error);
    int32_t after = (int32_t)__atomic_load_n(&gRepairCount, __ATOMIC_SEQ_CST);
    GNReadAuditNote(GNReadDoorSingle, caller, after != before);
    return result;
}

static CFTypeRef GNRepairBatchImpl(const void *task, CFArrayRef entitlements,
                                  CFErrorRef *error) {
    GNResolveOriginals();

    if (!entitlements || CFGetTypeID(entitlements) != CFArrayGetTypeID()) {
        if (gOriginalCopyValues) return gOriginalCopyValues(task, entitlements, error);
        if (error) *error = NULL;
        return NULL;
    }

    if (!gOriginalCopyValues) {
        // The batch symbol is gone but the single one is not: answer key by key
        // so the repair still happens instead of quietly falling back to the
        // malformed values.
        if (!gOriginalCopyValue) {
            if (error) *error = NULL;
            return NULL;
        }
        CFMutableDictionaryRef built =
            CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                      &kCFTypeDictionaryKeyCallBacks,
                                      &kCFTypeDictionaryValueCallBacks);
        if (!built) { if (error) *error = NULL; return NULL; }

        CFIndex count = CFArrayGetCount(entitlements);
        for (CFIndex i = 0; i < count; i++) {
            CFStringRef key = (CFStringRef)CFArrayGetValueAtIndex(entitlements, i);
            if (!key || CFGetTypeID(key) != CFStringGetTypeID()) continue;
            CFTypeRef value = GNRepairCopyValueForEntitlement(task, key, NULL);
            if (!value) continue;
            CFDictionarySetValue(built, key, value);
            CFRelease(value);
        }
        if (error) *error = NULL;
        return built;
    }

    CFTypeRef result = gOriginalCopyValues(task, entitlements, error);
    if (!result || CFGetTypeID(result) != CFDictionaryGetTypeID()) return result;

    CFMutableDictionaryRef repaired =
        CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, (CFDictionaryRef)result);
    if (!repaired) return result;

    BOOL changed = NO;
    CFIndex count = CFArrayGetCount(entitlements);
    for (CFIndex i = 0; i < count; i++) {
        CFStringRef key = (CFStringRef)CFArrayGetValueAtIndex(entitlements, i);
        if (!key || CFGetTypeID(key) != CFStringGetTypeID()) continue;

        CFTypeRef current = CFDictionaryGetValue(repaired, key);
        if (!current) continue;

        CFTypeRef candidate = GNRepairApply(key, (CFTypeRef)CFRetain(current));
        if (candidate != current) {
            CFDictionarySetValue(repaired, key, candidate);
            changed = YES;
        }
        if (candidate) CFRelease(candidate);
    }

    if (!changed) {
        CFRelease(repaired);
        return result;
    }

    CFRelease(result);
    return repaired;
}

CFTypeRef GNRepairCopyValuesForEntitlements(const void *task, CFArrayRef entitlements,
                                            CFErrorRef *error) {
    const void *caller = __builtin_return_address(0);
    int32_t before = (int32_t)__atomic_load_n(&gRepairCount, __ATOMIC_SEQ_CST);
    CFTypeRef result = GNRepairBatchImpl(task, entitlements, error);
    int32_t after = (int32_t)__atomic_load_n(&gRepairCount, __ATOMIC_SEQ_CST);
    GNReadAuditNote(GNReadDoorBatch, caller, after != before);
    return result;
}

#pragma mark - The third read path: the code signature dictionary

/// Repairs every rule key inside a dictionary of entitlements, returning a +1
/// value: the same dictionary untouched (already correct, nothing to do) or a
/// repaired mutable copy.
///
/// This is shared by the plural SecTask call and by
/// SecCodeCopySigningInformation, because both hand back the entitlements as a
/// dictionary and both are ways CloudKit can reach the same malformed value.
static CFTypeRef GNRepairDictionary(CFDictionaryRef source) {
    if (!source || CFGetTypeID(source) != CFDictionaryGetTypeID()) {
        return source ? (CFTypeRef)CFRetain(source) : NULL;
    }

    CFMutableDictionaryRef copy = NULL;
    for (size_t index = 0; index < gRuleCount; index++) {
        CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, gRules[index].key,
                                                    kCFStringEncodingUTF8);
        if (!key) continue;

        CFTypeRef current = CFDictionaryGetValue(source, key);
        CFTypeRef candidate = NULL;
        if (current) {
            // GNRepairApply takes ownership, so hand it a reference of its own.
            candidate = GNRepairApply(key, (CFTypeRef)CFRetain(current));
            if (candidate == current) {
                CFRelease(candidate);   // unchanged: nothing to install
                candidate = NULL;
            }
        } else if (gFillMissing) {
            candidate = GNRepairApply(key, NULL);
        }

        if (candidate) {
            if (!copy) {
                copy = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, source);
            }
            if (copy) CFDictionarySetValue(copy, key, candidate);
            CFRelease(candidate);
        }
        CFRelease(key);
    }

    if (!copy) return (CFTypeRef)CFRetain(source);
    return copy;
}

/// SecCodeCopySigningInformation(), with the entitlements dictionary inside it
/// repaired.
///
/// CloudKit has more than one way to read the process's entitlements, and the
/// v17 log proved the obvious one (the singular SecTask call) was not the only
/// one on the path. This is the other public door: the signing information
/// dictionary carries `entitlements-dict` (and, on older systems,
/// `entitlements`), and a client that reads it gets the same "*" the SecTask
/// call was returning.
///
/// Everything else in the dictionary is passed through untouched - this is the
/// same type repair, applied to a different container.
static uint32_t GNRepairSigningInfoImpl(const void *code, uint32_t flags,
                                        CFDictionaryRef *information) {
    GNResolveOriginals();
    if (!gOriginalCopySigningInformation) {
        if (information) *information = NULL;
        return 1;                       // errSecUnimplemented-shaped failure
    }

    uint32_t status = gOriginalCopySigningInformation(code, flags, information);
    if (status != 0 || !information || !*information) return status;
    if (CFGetTypeID(*information) != CFDictionaryGetTypeID()) return status;

    CFTypeRef repaired = GNRepairDictionary((CFDictionaryRef)*information);
    if (!repaired) return status;

    if (repaired != (CFTypeRef)*information) {
        CFRelease(*information);
        *information = (CFDictionaryRef)repaired;
    } else {
        CFRelease(repaired);
    }
    return status;
}

uint32_t GNRepairCopySigningInformation(const void *code, uint32_t flags,
                                        CFDictionaryRef *information) {
    const void *caller = __builtin_return_address(0);
    int32_t before = (int32_t)__atomic_load_n(&gRepairCount, __ATOMIC_SEQ_CST);
    uint32_t status = GNRepairSigningInfoImpl(code, flags, information);
    int32_t after = (int32_t)__atomic_load_n(&gRepairCount, __ATOMIC_SEQ_CST);
    GNReadAuditNote(GNReadDoorSigningInfo, caller, after != before);
    return status;
}

#pragma mark - Install / report

int GNEntitlementRepairCount(void) {
    return (int)gRepairCount;
}

const char *GNEntitlementRepairStatus(void) {
    return gStatus;
}

void GNInstallEntitlementRepair(NSDictionary *cfg) {
    (void)cfg;
    if (gInstalled) return;
    gInstalled = YES;

    gLogBudget = (int32_t)GNCGI(@"EntitlementRepairLogBudget", 6);
    gFillMissing = GNCFG(@"EntitlementRepairFill", NO);

    // Per key overrides, so the same dylib can answer with the container and
    // team identifiers the signature really carries. Read once: this runs in the
    // constructor and the repair itself runs on CloudKit's thread.
    id overrides = cfg ? [cfg objectForKey:@"EntitlementRepairValues"] : nil;
    if ([overrides isKindOfClass:[NSDictionary class]]) {
        for (size_t index = 0; index < gRuleCount; index++) {
            id value = [(NSDictionary *)overrides objectForKey:
                            [NSString stringWithUTF8String:gRules[index].key]];
            if (![value isKindOfClass:[NSString class]]) continue;
            const char *text = [(NSString *)value UTF8String];
            if (!text || !text[0]) continue;
            snprintf(gOverrideText[index], sizeof(gOverrideText[index]), "%s", text);
        }
    }

    GNResolveOriginals();

    // What the linker and dyld actually did with the table. A replacee of 0
    // means the symbol was not in the process at all (a weak import that did
    // not resolve); the repair is then dead code, and the log has to say so
    // rather than let the next launch look like a fix that did not work.
    int entries = GNEntitlementInterposeCount();
    int bound = 0;
    for (int i = 0; i < entries; i++) {
        const void *target = GNEntitlementInterposeBoundTarget(i);
        if (target) bound++;
        GNLogC("repair: interpose[%d] %s: %s", i, GNEntitlementInterposeName(i),
               target ? "bound by dyld" : "NOT BOUND (symbol absent)");
    }

    if (!gOriginalCopyValue) {
        snprintf(gStatus, sizeof(gStatus), "unavailable (Security not loaded)");
        GNLogC("repair: %s - nothing can be repaired in this process", gStatus);
        return;
    }

    if (bound == 0) {
        snprintf(gStatus, sizeof(gStatus), "table bound nothing");
        GNLogC("repair: the interpose table bound no address - the signer still owns "
               "this entitlement");
        return;
    }

    snprintf(gStatus, sizeof(gStatus), "armed (n=%d, fill=%s)",
             GNEntitlementRepairCount(), gFillMissing ? "on" : "off");

    GNLogC("repair: armed - SecTaskCopyValueForEntitlement intercepted for the whole "
           "process (dyld interpose, no code page touched)");
    GNLogC("repair: %d rule(s). icloud-services, icloud-container-identifiers, "
           "icloud-container-development-container-identifiers, "
           "ubiquity-container-identifiers -> array of strings; "
           "ubiquity-kvstore-identifier and icloud-container-environment -> string. "
           "Type only, untouched when already correct.", (int)gRuleCount);
    GNLogC("repair: v18 - the answer's shape is decided by src/GNRepairPolicy.h and "
           "checked on the build host over every combination of inputs; a rule that "
           "wants an array can no longer be answered with a bare string");
    if (gOriginalCopySigningInformation) {
        GNLogC("repair: SecCodeCopySigningInformation is also covered - the entitlements "
               "dictionary inside the signing information is repaired the same way");
    } else {
        GNLogC("repair: SecCodeCopySigningInformation is absent in this process - only "
               "the SecTask paths are covered");
    }
    GNLogC("repair: proof is a 'repair:' line above. A launch that still dies with no "
           "such line means the interposition did not reach the caller - then, and "
           "only then, the signer has to fix the value.");
}
