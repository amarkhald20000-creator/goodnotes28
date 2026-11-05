//
//  repair_policy_test.c
//  Executes the entitlement repair policy on the host, over every combination.
//
//  This exists because v17 shipped a repair that produced
//
//      com.apple.developer.icloud-services:  string "*"  ->  string "CloudKit"
//
//  for a key whose schema says *array of strings*. Nothing caught it, because
//  the decision lived inside CoreFoundation code and the only test that ran was
//  a launch on a device. The decision is now pure C in src/GNRepairPolicy.h, and
//  this file is the test that would have failed:
//
//      every plan either changes nothing, or produces exactly the kind the
//      schema requires
//
//  Enumerating is cheap (2 x 4 x 2 x 2 x 3 x 2 = 192 cases), so it is exhaustive
//  rather than illustrative, and `--selfcheck` runs the same assertions against
//  a deliberately wrong planner - v17's - to prove the assertions can fail.
//
#include "../src/GNRepairPolicy.h"

#include <stdio.h>
#include <string.h>

static int gChecks;
static int gFailures;

#define CHECK(condition, ...)                                                  \
    do {                                                                       \
        gChecks++;                                                             \
        if (!(condition)) {                                                    \
            gFailures++;                                                       \
            printf("FAIL %s:%d  ", __FILE__, __LINE__);                        \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

typedef GNRPlan (*GNRPlanner)(GNRExpect, GNRKind, int, int, long, int);

static const char *kExpectNames[] = { "array-of-strings", "string" };
static const char *kKindNames[] = { "absent", "string", "array", "other" };

/// The v17 decision, reproduced exactly, so the assertions below have something
/// they are known to reject.
///
/// v17's shape, from the log: for an array rule with a string value it called
/// the "default for rule" helper, which built a CFString - and the array-ness of
/// the rule was only reflected in the *other* branch (a non-wildcard string was
/// wrapped). A wildcard string therefore escaped unwrapped.
static GNRPlan GNV17Planner(GNRExpect expect, GNRKind kind, int isWildcard,
                           int arrayAllStrings, long arrayCount, int fillMissing) {
    if (expect == GNRExpectStringArray) {
        if (kind == GNRKindString) {
            if (!isWildcard) return GNRBuild(GNRKindArray, GNRSourceKeptString);
            return GNRBuild(GNRKindString, GNRSourceLiteral);   // <- the defect
        }
        if (kind == GNRKindArray) return GNRKeepValue(kind);
        if (kind == GNRKindAbsent && !fillMissing) return GNRKeepValue(kind);
        return GNRBuild(GNRKindString, GNRSourceLiteral);        // <- and here
    }
    if (kind == GNRKindString) {
        if (!isWildcard) return GNRKeepValue(kind);
        return GNRBuild(GNRKindString, GNRSourceLiteral);
    }
    if (kind == GNRKindArray) {
        if (arrayCount > 0 && arrayAllStrings) {
            return GNRBuild(GNRKindString, GNRSourceFirstString);
        }
        return GNRBuild(GNRKindString, GNRSourceLiteral);
    }
    if (kind == GNRKindAbsent && !fillMissing) return GNRKeepValue(kind);
    return GNRBuild(GNRKindString, GNRSourceLiteral);
}

/// The invariants every plan has to satisfy, whatever produced it.
///
/// 1. a change produces the kind the schema requires - the v17 defect
/// 2. a change carries a source, and no change has one
/// 3. a "kept string" source is only used when the value *is* a string
/// 4. a "first element" source is only used when the value *is* an array
/// 5. right type + not a wildcard = untouched
/// 6. absent stays absent unless filling was requested
static void GNRCheckPlan(const char *label, GNRPlanner planner, GNRExpect expect,
                         GNRKind kind, int isWildcard, int arrayAllStrings,
                         long arrayCount, int fillMissing) {
    GNRPlan plan = planner(expect, kind, isWildcard, arrayAllStrings, arrayCount, fillMissing);
    GNRKind wanted = GNRKindForExpect(expect);

    if (plan.change) {
        CHECK(plan.produce == wanted,
              "%s: %s rule answered with %s (change=1) - the value a repair builds must be "
              "the kind the schema requires, or the repair hands CloudKit the same malformed "
              "type it just refused", label, kExpectNames[expect], GNRKindName(plan.produce));
        CHECK(plan.source != GNRSourceNone,
              "%s: %s rule set change=1 with no source - there is nothing to build from",
              label, kExpectNames[expect]);
        CHECK(plan.source != GNRSourceKeptString || kind == GNRKindString,
              "%s: source=kept-string for a value that is %s", label, kKindNames[kind]);
        CHECK(plan.source != GNRSourceFirstString || kind == GNRKindArray,
              "%s: source=first-string for a value that is %s", label, kKindNames[kind]);
    } else {
        CHECK(plan.source == GNRSourceNone,
              "%s: change=0 but a source was set (%d)", label, (int)plan.source);
    }

    // A value that is already the right type, and is not the wildcard, is never
    // rewritten. This is the gate that keeps a type repair from being a grant.
    int typeCorrect = (kind == wanted);
    int contentsFine = (kind == GNRKindArray)
                           ? (arrayAllStrings && (arrayCount > 0 || !fillMissing))
                           : !isWildcard;
    if (typeCorrect && contentsFine) {
        CHECK(plan.change == 0,
              "%s: %s value was rewritten even though its type and contents were already "
              "acceptable", label, kExpectNames[expect]);
    }

    if (kind == GNRKindAbsent && !fillMissing) {
        CHECK(plan.change == 0,
              "%s: an absent value was invented without EntitlementRepairFill", label);
    }

    if (kind == GNRKindString && !isWildcard && expect == GNRExpectString) {
        CHECK(plan.change == 0 && plan.produce == GNRKindString,
              "%s: a good string was replaced", label);
    }
}

static void GNRRunAll(const char *label, GNRPlanner planner) {
    static const int kCounts[] = { 0, 1, 3 };

    for (int expect = 0; expect <= 1; expect++) {
        for (int kind = 0; kind <= 3; kind++) {
            for (int wildcard = 0; wildcard <= 1; wildcard++) {
                for (int allStrings = 0; allStrings <= 1; allStrings++) {
                    for (unsigned c = 0; c < sizeof(kCounts) / sizeof(kCounts[0]); c++) {
                        for (int fill = 0; fill <= 1; fill++) {
                            GNRCheckPlan(label, planner, (GNRExpect)expect, (GNRKind)kind,
                                         wildcard, allStrings, (long)kCounts[c], fill);
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char **argv) {
    int selfcheck = (argc > 1 && strcmp(argv[1], "--selfcheck") == 0);

    // 1. The shipped policy, over every combination.
    GNRRunAll("shipped", GNRPlanRepair);
    printf("repair policy: %d check(s), %d failure(s)\n", gChecks, gFailures);
    int shippedFailures = gFailures;

    // 2. The exact case from the device log, in isolation, with the expected
    //    answer spelled out. This is the line v17 got wrong.
    {
        GNRPlan plan = GNRPlanRepair(GNRExpectStringArray, GNRKindString,
                                     /*isWildcard=*/1, /*arrayAllStrings=*/0,
                                     /*arrayCount=*/0, /*fillMissing=*/0);
        CHECK(plan.change == 1, "icloud-services: string \"*\" was not repaired at all");
        CHECK(plan.produce == GNRKindArray,
              "icloud-services: string \"*\" repaired to %s - CloudKit asks for an array of "
              "strings and refuses a scalar", GNRKindName(plan.produce));
        CHECK(plan.source == GNRSourceLiteral,
              "icloud-services: expected the rule's literal (\"CloudKit\"), got source %d",
              (int)plan.source);
        printf("icloud-services: string \"*\" -> %s[%s] (source=%d)\n",
               GNRKindName(plan.produce), plan.produce == GNRKindArray ? "1 element" : "",
               (int)plan.source);
    }

    // 3. A real value with the wrong shape keeps the value and fixes the shape.
    {
        GNRPlan plan = GNRPlanRepair(GNRExpectStringArray, GNRKindString,
                                     /*isWildcard=*/0, 0, 0, 0);
        CHECK(plan.change == 1 && plan.produce == GNRKindArray &&
                  plan.source == GNRSourceKeptString,
              "a non-wildcard scalar must be wrapped in place, keeping its value");
    }

    // 4. A correct array of strings is never touched.
    {
        GNRPlan plan = GNRPlanRepair(GNRExpectStringArray, GNRKindArray,
                                     /*isWildcard=*/0, /*arrayAllStrings=*/1,
                                     /*arrayCount=*/2, /*fillMissing=*/1);
        CHECK(plan.change == 0, "a well formed array was rewritten");
    }

    // 5. A string rule given an array takes the first element.
    {
        GNRPlan plan = GNRPlanRepair(GNRExpectString, GNRKindArray, 0, 1, 1, 0);
        CHECK(plan.change == 1 && plan.produce == GNRKindString &&
                  plan.source == GNRSourceFirstString,
              "kvstore-identifier given an array must become its first element");
    }

    printf("repair policy: %d check(s), %d failure(s)\n", gChecks, gFailures);

    if (selfcheck) {
        // The assertions above must reject the shape v17 shipped. If they accept
        // it, they are theatre and the next regression ships just as quietly.
        int before = gFailures;
        int checksBefore = gChecks;
        GNRRunAll("v17", GNV17Planner);
        int caught = gFailures - before;
        printf("repair policy: v17 planner -> %d new check(s), %d caught\n",
               gChecks - checksBefore, caught);
        if (caught <= 0) {
            printf("FAIL selfcheck: the v17 planner passed every assertion - the check is "
                   "theatre\n");
            return 1;
        }
        return shippedFailures == 0 ? 0 : 1;
    }

    return shippedFailures == 0 ? 0 : 1;
}
