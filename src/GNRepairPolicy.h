//
//  GNRepairPolicy.h
//  The decision half of the entitlement type repair, as pure C.
//
//  ======================= why this is a separate header =======================
//
//  v17 shipped this decision inline, and it was wrong in a way that a thousand
//  lines of surrounding CoreFoundation obscured:
//
//      repair: #1 com.apple.developer.icloud-services: string "*" -> string "CloudKit"
//                                                                  ^^^^^^^^^^^^^^^^^^
//  The rule says "array of strings". The replacement built a bare string. So the
//  repair ran, the counter moved, the self-test printed "interception is LIVE",
//  and CloudKit was handed exactly the malformed *type* it had just refused -
//  one more launch, one more crash, and the log looked like a success.
//
//  The bug is not "a missing branch". It is that the code that decides *what to
//  answer* was untestable: it needed a live CoreFoundation to run, so nothing
//  ever checked the answer against the rule. This header is that decision with
//  no CoreFoundation in it: inputs are plain integers, the output is a plan, and
//  scripts/repair_policy_test.c executes every combination and asserts the one
//  property that v17 broke:
//
//      a repair never produces a value whose kind is not the expected kind
//
//  src/GNEntitlementRepair.m turns the plan into CF objects. It has no policy
//  left in it: no "if the type is a string then wrap it", no per-key special
//  cases, nothing that can drift from what the test proved.
//
//  ============================== the rules ==============================
//
//  Three kinds of change, and nothing else:
//
//    wrong type        a scalar where an array belongs, an array where a string
//                      belongs. Answer with the expected type.
//    wildcard          the literal "*" (or the empty string) that a signer writes
//                      when it does not know the real value. A string saying "*"
//                      is the wrong *value* even when the type is right, and
//                      CloudKit refuses it by name in the exception text.
//    absent            only when fillMissing is on, and only then: a key the
//                      signature does not carry at all is left absent by default,
//                      because inventing one is a grant, not a type repair.
//
//  A value that is already the right type and is not a wildcard is never
//  touched, whatever it says. That gate is what keeps this a repair.
//
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/// What a value currently is. The CF side maps CFTypeID onto these; that mapping
/// is the only place a CoreFoundation type is named.
typedef enum {
    GNRKindAbsent = 0,
    GNRKindString = 1,
    GNRKindArray  = 2,
    GNRKindOther  = 3,
} GNRKind;

/// What Apple's schema requires for the key.
typedef enum {
    GNRExpectStringArray = 0,
    GNRExpectString      = 1,
} GNRExpect;

/// Where the string inside the answer comes from.
typedef enum {
    GNRSourceNone        = 0,   // change == 0: nothing is built
    GNRSourceLiteral     = 1,   // the rule's literal ("CloudKit", "Production")
    GNRSourceBundle      = 2,   // the rule's prefix + the main bundle identifier
    GNRSourceKeptString  = 3,   // the string that is already there
    GNRSourceFirstString = 4,   // the first element of the array that is there
} GNRSource;

/// The answer: whether to change anything, and exactly what to build.
///
/// `produce` is the *final* kind, after wrapping. When `produce` is
/// GNRKindArray the CF side builds a one element CFArray around the sourced
/// string; when it is GNRKindString it builds the string itself. There is no
/// third shape and no "wrap later" flag that a caller could ignore: the wrap is
/// part of the kind, which is what makes the test below possible.
typedef struct {
    int       change;     // 0 = leave the value exactly as it is
    GNRKind   produce;    // GNRKindString or GNRKindArray when change != 0
    GNRSource source;
} GNRPlan;

/// The decision.
///
///   expect          what the schema requires for this key
///   kind            what the value currently is
///   isWildcard      the value is a string, and it is "*" or ""
///   arrayAllStrings every element of the value (when it is an array) is a string
///   arrayCount      element count (0 when not an array)
///   fillMissing     EntitlementRepairFill: also answer for absent/empty values
static inline GNRPlan GNRKeepValue(GNRKind kind) {
    GNRPlan plan;
    plan.change = 0;
    plan.produce = kind;
    plan.source = GNRSourceNone;
    return plan;
}

static inline GNRPlan GNRBuild(GNRKind kind, GNRSource source) {
    GNRPlan plan;
    plan.change = 1;
    plan.produce = kind;
    plan.source = source;
    return plan;
}

static inline GNRPlan GNRPlanRepair(GNRExpect expect, GNRKind kind, int isWildcard,
                                    int arrayAllStrings, long arrayCount,
                                    int fillMissing) {
    if (expect == GNRExpectStringArray) {
        if (kind == GNRKindArray) {
            // Right type. Only an empty array is worth touching, and only when the
            // caller asked for missing values to be filled - an array of strings
            // that is already there, whatever it contains, is not our business.
            if (arrayAllStrings && (arrayCount > 0 || !fillMissing)) {
                return GNRKeepValue(kind);
            }
            if (fillMissing && arrayCount == 0) {
                return GNRBuild(GNRKindArray, GNRSourceLiteral);
            }
            return GNRKeepValue(kind);
        }
        if (kind == GNRKindString) {
            if (!isWildcard) {
                // A real value with the wrong shape: keep the value, fix the shape.
                return GNRBuild(GNRKindArray, GNRSourceKeptString);
            }
            return GNRBuild(GNRKindArray, GNRSourceLiteral);
        }
        if (kind == GNRKindAbsent) {
            if (fillMissing) return GNRBuild(GNRKindArray, GNRSourceLiteral);
            return GNRKeepValue(kind);
        }
        return GNRBuild(GNRKindArray, GNRSourceLiteral);
    }

    // A string is required.
    if (kind == GNRKindString) {
        if (!isWildcard) return GNRKeepValue(kind);
        return GNRBuild(GNRKindString, GNRSourceLiteral);
    }
    if (kind == GNRKindArray) {
        // The array's first element is a usable string: that is the value the
        // signer meant, so keep it and drop the shape.
        if (arrayCount > 0 && arrayAllStrings) {
            return GNRBuild(GNRKindString, GNRSourceFirstString);
        }
        return GNRBuild(GNRKindString, GNRSourceLiteral);
    }
    if (kind == GNRKindAbsent) {
        if (fillMissing) return GNRBuild(GNRKindString, GNRSourceLiteral);
        return GNRKeepValue(kind);
    }
    return GNRBuild(GNRKindString, GNRSourceLiteral);
}

/// The expected kind for a rule. Used by the test, and by the CF side when it
/// logs what it is about to answer with.
static inline GNRKind GNRKindForExpect(GNRExpect expect) {
    return expect == GNRExpectStringArray ? GNRKindArray : GNRKindString;
}

/// Name for the log. ASCII, never NULL.
static inline const char *GNRKindName(GNRKind kind) {
    switch (kind) {
        case GNRKindAbsent: return "absent";
        case GNRKindString: return "string";
        case GNRKindArray:  return "array";
        default:            return "other";
    }
}

#ifdef __cplusplus
}
#endif
