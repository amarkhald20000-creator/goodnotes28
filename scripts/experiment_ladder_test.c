/*
 * experiment_ladder_test.c - executes the experiment ladder's state machine.
 *
 *   zig cc scripts/experiment_ladder_test.c -o /tmp/experiment_ladder_test
 *   /tmp/experiment_ladder_test
 *
 * The subject is src/GNExperimentLadder.h, the same file the dylib includes -
 * not a copy of its logic. That distinction is the difference between a test and
 * a second opinion.
 *
 * What is asserted, and why each one matters:
 *
 *   1. One launch changes one thing: the step either stays or advances by
 *      exactly 1. Two changes at once would leave the surviving launch naming
 *      neither of them.
 *   2. A ladder whose every launch fails terminates. This is the difference
 *      between a bisect and a boot loop.
 *   3. Once won or exhausted, the state never moves again - otherwise a working
 *      configuration would keep changing under the user.
 *   4. The step is always inside [0, count).
 */

#include <stdio.h>
#include <stdlib.h>

#include "../src/GNExperimentLadder.h"

static int failures = 0;

#define CHECK(condition, ...)                                   \
    do {                                                        \
        if (!(condition)) {                                     \
            fprintf(stderr, "FAIL %s:%d  ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                        \
            fprintf(stderr, "\n");                               \
            failures++;                                          \
        }                                                        \
    } while (0)

int main(void) {
    const int count = 6;

    /* 1 + 2: a ladder where every launch fails walks 0,1,2,...,5 and then
     *        settles on exhausted - in at most count launches. */
    GNExperimentState state = { 0, GNExperimentTrying };
    bool storedValid = false;                  /* first ever launch */
    int launches = 0;

    state = GNExperimentNext(state, storedValid, false, true, count);
    CHECK(state.step == 0 && state.outcome == GNExperimentTrying,
          "a fresh ladder must start at 0 (got %d/%d)", state.step, state.outcome);

    int highest = 0;
    for (int i = 0; i < count + 5; i++) {
        GNExperimentState next = GNExperimentNext(state, true, true, true, count);
        launches++;

        if (next.outcome != GNExperimentExhausted) {
            CHECK(next.step == state.step + 1,
                  "step moved by %d, must be exactly +1", next.step - state.step);
        }
        CHECK(next.step >= 0 && next.step < count,
              "step %d outside [0,%d)", next.step, count);

        if (next.step > highest) highest = next.step;
        state = next;
        if (state.outcome == GNExperimentExhausted) break;   // settled: stop counting
    }
    CHECK(highest == count - 1, "the ladder never reached the last step (highest %d)", highest);
    CHECK(state.outcome == GNExperimentExhausted,
          "a ladder whose launches all fail must end exhausted (got %d)", state.outcome);
    CHECK(launches <= count, "took %d launches to terminate, ladder has %d steps",
          launches, count);

    /* 3: exhausted never moves */
    for (int i = 0; i < 10; i++) {
        GNExperimentState next = GNExperimentNext(state, true, true, true, count);
        CHECK(next.step == state.step && next.outcome == state.outcome,
              "exhausted moved to %d/%d", next.step, next.outcome);
        state = next;
    }

    /* 3: won never moves */
    GNExperimentState won = { 2, GNExperimentWon };
    for (int i = 0; i < 10; i++) {
        GNExperimentState next = GNExperimentNext(won, true, true, true, count);
        CHECK(next.step == won.step && next.outcome == won.outcome,
              "won moved to %d/%d", next.step, next.outcome);
        won = next;
    }

    /* a launch that succeeded keeps the same step for the next launch */
    GNExperimentState holding = { 3, GNExperimentTrying };
    GNExperimentState same = GNExperimentNext(holding, true, false, true, count);
    CHECK(same.step == 3 && same.outcome == GNExperimentTrying,
          "a successful launch must not advance (got %d/%d)", same.step, same.outcome);

    /* an unreadable / stale / out-of-range file starts over */
    GNExperimentState junk = { 4, GNExperimentWon };
    GNExperimentState reset = GNExperimentNext(junk, false, false, true, count);
    CHECK(reset.step == 0 && reset.outcome == GNExperimentTrying,
          "an invalid state file must reset to 0 (got %d/%d)", reset.step, reset.outcome);

    GNExperimentState outOfRange = { 99, GNExperimentTrying };
    GNExperimentState fixed = GNExperimentNext(outOfRange, true, true, true, count);
    CHECK(fixed.step == 0 && fixed.outcome == GNExperimentTrying,
          "an out-of-range step must reset (got %d/%d)", fixed.step, fixed.outcome);

    /* auto-advance off means the ladder is a fixed choice */
    GNExperimentState pinned = { 1, GNExperimentTrying };
    GNExperimentState stayed = GNExperimentNext(pinned, true, true, false, count);
    CHECK(stayed.step == 1 && stayed.outcome == GNExperimentTrying,
          "AutoBisect=false must pin the step (got %d/%d)", stayed.step, stayed.outcome);

    if (failures) {
        fprintf(stderr, "\n%d assertion(s) failed\n", failures);
        return 1;
    }

    printf("ok: ladder advances one step at a time, terminates within %d launches, "
           "and never moves once it has settled\n", count);
    return 0;
}
