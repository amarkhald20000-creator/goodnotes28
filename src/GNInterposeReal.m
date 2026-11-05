//
//  GNInterposeReal.m
//  The one place that answers "what is the function this replacement replaced".
//  (v22)
//
//  Read GNInterposeReal.h first: it states the two sources and why they are
//  tried in that order. This file is only the mechanism plus the logging, and the
//  logging matters as much as the answer - "the gate is installed" and "the gate
//  calls the real function" are different claims, and this project has already
//  shipped a version that confused them.
//

#import "GNInterposeReal.h"
#import "GNBeacon.h"

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#pragma mark - Logging

static volatile int32_t gRealLogs = 0;
static volatile int32_t gRealLogBudget = 12;

static void GNInterposeRealSay(const char *tag, const char *fmt, ...)
    __attribute__((format(__printf__, 2, 3)));

static void GNInterposeRealSay(const char *tag, const char *fmt, ...) {
    if (__sync_add_and_fetch(&gRealLogs, 1) > gRealLogBudget) return;

    va_list args;
    va_start(args, fmt);
    char text[512];
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);
    GNBeaconLine("%s: %s", tag ?: "interpose", text);
}

#pragma mark - Public

void *GNInterposeReal(const char *name, const void *tableHalf, const void *replacement,
                      const char *tag) {
    if (!name || !*name) return NULL;

    // -- source 1: dlsym, refused when it answers with this replacement -----
    void *viaLookup = dlsym(RTLD_DEFAULT, name);
    BOOL lookupRefused = (viaLookup != NULL) && (viaLookup == replacement);

    if (viaLookup && !lookupRefused) {
        GNInterposeRealSay(tag, "original for %s resolved through dlsym (%p); nothing in this "
                           "file calls it by name", name, viaLookup);
        return viaLookup;
    }

    // -- source 2: the replacee half of our own tuple -----------------------
    void *viaTable = (tableHalf && tableHalf != replacement) ? (void *)tableHalf : NULL;

    if (viaTable) {
        GNInterposeRealSay(tag, "%s: dlsym answered %s, so the tuple half is the real function "
                           "(%p)", name,
                           lookupRefused ? "this dylib's own replacement" : "nothing",
                           viaTable);
        return viaTable;
    }

    // -- neither: say exactly what was seen, and answer NULL ----------------
    GNInterposeRealSay(tag, "%s: no trustworthy address - dlsym answered %p and the tuple "
                       "half is %p; the caller degrades instead of calling either one",
                       name, viaLookup, tableHalf);
    return NULL;
}

int32_t GNInterposeRealLogCount(void) {
    return gRealLogs;
}
