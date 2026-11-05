//
//  GNExperimentLadder.h
//  The experiment ladder's state machine, as pure C.
//
//  Why this is a header and not a few lines inside GNSupport.m: it is the only
//  piece of v11 with state that survives between launches, so "it looks right"
//  is not good enough. Written as a total function with no I/O, it can be
//  executed by scripts/experiment_ladder_test.c on the build host - which is
//  what actually proves the three properties that matter:
//
//    * every launch changes at most one thing (step advances by exactly 1)
//    * a ladder whose every launch fails terminates (reaches exhausted, and
//      then never moves again)
//    * a ladder that found something that works stops (won never moves again)
//
//  A ladder that violates any of those either never ends or keeps changing
//  configuration after a working one was found - both worse than not having it.
//

#ifndef GN_EXPERIMENT_LADDER_H
#define GN_EXPERIMENT_LADDER_H

#include <stdbool.h>

typedef enum {
    GNExperimentTrying = 0,
    GNExperimentWon = 1,
    GNExperimentExhausted = 2,
} GNExperimentOutcome;

typedef struct {
    int step;
    GNExperimentOutcome outcome;
} GNExperimentState;

/// Decides the state for *this* launch.
///
///   current              what the state file said
///   storedValid          that file was readable, from this ConfigVersion, and
///                        in range - anything else means "start over"
///   previousLaunchFailed the previous launch never reached
///                        UIApplicationDidFinishLaunchingNotification
///   autoAdvance          the AutoBisect switch
///   count                number of steps in the ladder
static inline GNExperimentState GNExperimentNext(GNExperimentState current,
                                                 bool storedValid,
                                                 bool previousLaunchFailed,
                                                 bool autoAdvance,
                                                 int count) {
    if (count <= 0) {
        return (GNExperimentState){ 0, GNExperimentExhausted };
    }
    if (!storedValid) {
        return (GNExperimentState){ 0, GNExperimentTrying };
    }
    if (current.outcome != GNExperimentTrying) {
        return current;                     // won / exhausted never move again
    }
    if (current.step < 0 || current.step >= count) {
        return (GNExperimentState){ 0, GNExperimentTrying };
    }
    if (!autoAdvance || !previousLaunchFailed) {
        return current;                     // the same step again
    }

    int next = current.step + 1;
    if (next >= count) {
        return (GNExperimentState){ 0, GNExperimentExhausted };
    }
    return (GNExperimentState){ next, GNExperimentTrying };
}

#endif
