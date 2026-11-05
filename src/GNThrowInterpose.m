//
//  GNThrowInterpose.m
//  Reach every throw in the process - the shared cache included. (v21)
//
//  ======================= what v20 covered, and why it was three =======================
//
//  v20 found objc_exception_throw the only way a data-page-only design can: it
//  walked every loaded image, looked for the address the function already had in
//  an import slot, and rewrote that slot. Three images held one - Goodnotes,
//  MSAL, CoreUI - and the log on the device said so:
//
//      slot: 'objc_exception_throw' 3 slot section(s) held its address
//
//  CloudKit was not one of them. Not because the walk failed, but because a slot
//  is a property of the *caller's* image and CloudKitCore may reach the function
//  through a stub, a shared thunk, or an address it kept in a local; none of
//  those is a slot, and a slot-oriented tool has nothing to say about them.
//
//  ======================= what this file does instead =======================
//
//  __DATA,__interpose is a different mechanism with a different coverage rule.
//  It is not a hunt for a pointer: it is a table dyld reads, and dyld applies it
//  to every *binding* in the process - shared cache images included, whether they
//  were loaded before this dylib or after it. The question "does this image have
//  a slot" stops being asked.
//
//  That is what turns v20's trampoline from a three-image curiosity into the
//  process-wide gate the last four versions were trying to build: the decoder,
//  the return-site proof, the swallow budget and the stack record in
//  GNThrowTrampoline.m are unchanged. Only the reach changed.
//
//  ======================= the one thing this cannot do =======================
//
//  The table is link time. It cannot be removed at run time, so "ThrowInterpose =
//  false" cannot un-install it - it can only make it a pass-through, which is
//  what the flag does: one branch and a tail call to the real function, with the
//  same arguments, i.e. the same behaviour and one extra frame. The header says
//  so, the log says so, and the config comment says so, because a switch that
//  silently keeps working is worse than no switch.
//
//  ======================= why no behaviour change by default =======================
//
//  A default launch rethrows: the replacement classifies, records, and tail calls
//  the real objc_exception_throw. The exception is the same object, thrown from
//  the same site, unwound the same way. What is different is that the log now
//  names the throw - the thing every version since v16 asked for and none of them
//  could get out of a framework the dylib could not see into.
//

//  ======================= v22: the rethrow path was the weak part =======================
//
//  Everything above is about *reach*. The part that was never checked is what the
//  replacement does after it has classified the exception: it calls the real
//  objc_exception_throw, and v21 found that address with
//
//      dlsym(RTLD_DEFAULT, "objc_exception_throw")
//
//  dyld is entitled to apply an interpose table to a dlsym result - in dyld4 the
//  result of every lookup ends in interpose(state, resolved) - so on a launch
//  where that happens the "real function" is this file's own replacement, and the
//  rethrow is unbounded recursion. Nothing in v21 could have noticed: the table
//  and the trampoline both look armed.
//
//  v22 resolves through GNInterposeReal(), which refuses an answer that is this
//  replacement and falls back to the replacee half of the tuple above, and logs
//  which source answered. The behaviour when dlsym is honest is identical.
//

#import "GNUnlock.h"
#import "GNThrowTrampoline.h"
#import "GNInterposeReal.h"
#import "GNBeacon.h"

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#pragma mark - The symbol

/// Declared under an identifier of this file's own, bound to the runtime's
/// symbol by an asm label. This is not pedantry: objc_exception_throw is
/// declared `noreturn` in the headers, and a second declaration of a `noreturn`
/// function from a translation unit that may return from it is the kind of
/// mismatch clang is entitled to act on. A distinct identifier has no
/// declaration to conflict with, and the address in the interpose table is what
/// dyld actually consumes.
extern void GNThrowInterposeReplacee(id exception) __asm__("_objc_exception_throw");

#pragma mark - The table

typedef struct {
    const void *replacement;
    const void *replacee;
} GNThrowInterposeTuple;

static void GNThrowInterposed(id exception);

/// Apple's layout: an array of {replacement, replacee} pairs in a section named
/// __interpose, read by dyld at image load. `used` because nothing in this image
/// refers to it - the consumer is dyld, and without the attribute the linker is
/// entitled to drop the whole thing, which would leave this file as a very quiet
/// no-op with a log line claiming the opposite.
///
/// It is also the second source of the real address in v22: the replacee half is
/// what dyld read in order to install the replacement, so if the replacement runs
/// at all, that half holds the function to call through. See GNInterposeReal.h
/// for why that matters - dyld is entitled to interpose a dlsym result, and in
/// that world a dlsym-only call-through is recursion with a convincing log in
/// front of it.
__attribute__((used))
static GNThrowInterposeTuple GNThrowInterposeTable[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)&GNThrowInterposed, (const void *)&GNThrowInterposeReplacee },
};

#pragma mark - The real function

/// The address to call *through*, never by name: a call by name from this image
/// is a binding, and dyld has already redirected every binding to the replacement
/// below. Calling by name here is recursion with extra steps.
///
/// v21 resolved this with a bare dlsym and trusted it. v22 asks GNInterposeReal(),
/// which refuses an answer that is this replacement and falls back to the tuple
/// half, and logs which of the two answered.
static void *GNThrowInterposeRealAddress(void) {
    static void *real = NULL;
    if (!real) {
        real = GNInterposeReal("objc_exception_throw",
                               GNThrowInterposeTable[0].replacee,
                               (const void *)&GNThrowInterposed,
                               "throw-interpose");
    }
    return real;
}

#pragma mark - State

static volatile int32_t gInterposeArmed   = 0;
static volatile int32_t gInterposeCalls   = 0;
static volatile int32_t gInterposePasses  = 0;
static BOOL             gInterposeEnabled = YES;

static void GNThrowInterposeSay(const char *fmt, ...) __attribute__((format(__printf__, 1, 2)));

static void GNThrowInterposeSay(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char text[512];
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);
    GNBeaconLine("throw-interpose: %s", text);
}

#pragma mark - The replacement

/// Called for every Objective-C exception in this process from the moment the
/// dylib is loaded - which is before this dylib's constructor runs, and before
/// any framework is initialised. So the first job is not diagnosis, it is
/// "never be the reason a throw becomes something else": if the trampoline is
/// not armed yet, or the gate is off, rethrow through the real address.
static void GNThrowInterposed(id exception) {
    int32_t call = __sync_add_and_fetch(&gInterposeCalls, 1);

    if (!gInterposeArmed || !gInterposeEnabled) {
        __sync_add_and_fetch(&gInterposePasses, 1);
        void *real = GNThrowInterposeRealAddress();
        if (real) {
            ((void (*)(id))real)(exception);
            return;     // the real function does not return; this is unreachable
        }
        // There is no way to rethrow a pointer we could not resolve. Stopping
        // here is louder and earlier than continuing into a process that has no
        // exception machinery.
        _exit(133);
    }

    if (call == 1) {
        GNThrowInterposeSay("first exception of this launch is arriving through the "
                            "interpose table - coverage is every binding in the process");
    }

    // Everything else - classification, the return-site proof, the swallow
    // budget, the symbolicated stack - is v20's trampoline, reached now from
    // images v20 could not see.
    (void)GNThrowTrampolineObject((__bridge void *)exception);
}

#pragma mark - Public

int32_t GNThrowInterposeCount(void) {
    return (int32_t)(sizeof(GNThrowInterposeTable) / sizeof(GNThrowInterposeTable[0]));
}

int32_t GNThrowInterposeCallCount(void) {
    return gInterposeCalls;
}

BOOL GNThrowInterposeIsArmed(void) {
    return gInterposeArmed != 0;
}

void GNInstallThrowInterpose(NSDictionary *cfg) {
    if (![cfg isKindOfClass:[NSDictionary class]]) {
        GNBeaconLine("throw-interpose: no config - the table is link time and stays "
                     "pass-through only");
        return;
    }

    gInterposeEnabled = GNCFG(@"ThrowInterpose", YES);

    void *real = GNThrowInterposeRealAddress();
    if (!real) {
        GNBeaconLine("throw-interpose: objc_exception_throw could not be resolved - the table "
                     "is installed but every call will pass through unresolved");
        return;
    }

    // Arm the v20 trampoline with the address that is *not* the table's
    // replacement. If the slot walker armed it first, GNThrowTrampolineArm keeps
    // the earlier (equally real) address and nothing changes.
    GNThrowTrampolineArm(real);

    gInterposeArmed = 1;

    GNThrowInterposeSay("installed - %d entr(y|ies) in __DATA,__interpose, coverage is every "
                        "binding in the process including the dyld shared cache",
                        (int)(sizeof(GNThrowInterposeTable) / sizeof(GNThrowInterposeTable[0])));
    GNThrowInterposeSay("gate %s; the table itself cannot be removed at run time, so off means "
                        "pass-through, not absent",
                        gInterposeEnabled ? "ON" : "OFF");
    GNThrowInterposeSay("swallow is %s - the proven-return rule still applies%s",
                        GNCFG(@"ThrowSwallowAtSite", NO) ? "ARMED" : "off",
                        GNCFG(@"ThrowSwallowForce", NO)
                            ? "; ThrowSwallowForce is ON, so a site whose continuation is not a "
                              "return is swallowed too - read the FORCED lines, they name the "
                              "address the block resumes at"
                            : "; a site that cannot be proven is rethrown, and the log names it");
}
