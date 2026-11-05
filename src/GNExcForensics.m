//
//  GNExcForensics.m
//  Names the exception that kills the launch.
//
//  Why the previous attempts failed, precisely:
//
//    * NSSetUncaughtExceptionHandler (v8-v11) is not called at all on this
//      path. When an Objective-C exception reaches the top of the stack with no
//      handler, libc++abi calls __cxa_throw -> _Unwind_RaiseException with no
//      landing pad, which routes to __cxa_terminate / failed_throw. At that
//      point __cxa_current_exception_type() is null, so _objc_terminate takes
//      its "there is no current exception" branch and calls the *default*
//      terminate handler. The uncaught-exception handler lives on the other
//      branch. That is why v10 logged nothing even though it installed one.
//
//    * The @try nets (v10, v11) only wrapped the app delegate's launch
//      selectors. The crash report shows the throw arriving under
//      _dispatch_once_callout with no frame of ours anywhere in between, so the
//      net was not on that call path.
//
//  So this module goes one level down, to the point every Objective-C exception
//  must pass through: -[NSException initWithName:reason:userInfo:]. Nothing can
//  construct an NSException without it, including exceptions Foundation raises
//  internally (NSInvalidArgumentException from a bad selector, the
//  NSInternalInconsistencyException a store or a manager raises when a
//  container is missing).
//
//  Cost control, because this hook is on a hot-ish path:
//    - it records at most GN_FORENSIC_BUDGET exceptions, then puts the original
//      implementation back and gets out of the way for the rest of the launch;
//    - the first one it sees is the one that matters, and it is written with
//      open/write/fsync before this function returns to whoever threw.
//

#import "GNUnlock.h"
#import "GNBeacon.h"

#import <objc/runtime.h>
#import <string.h>

/// How many exceptions are recorded before the hook removes itself.
///
/// The first exception of a launch is the one that explains a launch crash.
/// Recording more than a handful buys nothing and would leave a swizzled
/// initialiser in the process for its whole lifetime, which is exactly the kind
/// of quiet behavioural change v12 exists to remove.
#define GN_FORENSIC_BUDGET 3

/// Signature of the original implementation.
///
/// The `ns_returns_retained` annotation is load bearing. This selector is in
/// the init family: the runtime's caller consumes a +1 object, and a plain C
/// function is not covered by ARC's related-result-type inference. Without the
/// annotation ARC would treat the returned object as +0 and hand the caller a
/// reference it is about to over-release - the same class of defect that took
/// down v7 through -[NSUserDefaults initWithSuiteName:].
typedef id (*GNExceptionInitFn)(id, SEL, id, id, id) __attribute__((ns_returns_retained));

static GNExceptionInitFn gOrigExceptionInit = NULL;
static Method            gExceptionInitMethod = NULL;
static volatile int32_t  gForensicDepth = 0;
static volatile int32_t  gForensicBudget = GN_FORENSIC_BUDGET;
static volatile int32_t  gForensicInstalled = 0;

static id GNExceptionInitForensics(id self, SEL _cmd, id name, id reason, id userInfo)
    __attribute__((ns_returns_retained));

static void GNRestoreExceptionInit(void) {
    if (gExceptionInitMethod && gOrigExceptionInit) {
        method_setImplementation(gExceptionInitMethod, (IMP)gOrigExceptionInit);
    }
    gForensicInstalled = 0;
    GNBeaconLine("forensics: hook removed, %d exception(s) recorded, app continues untouched",
                 GN_FORENSIC_BUDGET - gForensicBudget);
}

static id GNExceptionInitForensics(id self, SEL _cmd, id name, id reason, id userInfo) {
    // Build the real object first: this function must not change what the
    // caller receives, under any circumstance.
    id result = gOrigExceptionInit(self, _cmd, name, reason, userInfo);

    // Re-entrancy: anything we call below could itself raise. The flag makes
    // that a pass-through instead of an infinite descent.
    if (__sync_lock_test_and_set(&gForensicDepth, 1) == 0) {
        int32_t left = __sync_sub_and_fetch(&gForensicBudget, 1);

        // Everything from here on is diagnosis. It must be impossible for a
        // failed diagnosis to change what the caller receives, so the whole
        // block is one @try: if reading a reason string or building the symbol
        // list throws, the exception is swallowed here and the app's exception
        // continues on its way untouched.
        @try {
        @autoreleasepool {
            const char *cls = "?";
            const char *nme = "(none)";
            const char *rsn = "(none)";

            const char *clsC = class_getName(object_getClass(result));
            if (clsC) cls = clsC;

            // name / reason are already objects; ask for their UTF8String only
            // if they really are strings, so a malformed exception cannot turn
            // a diagnostic into a second crash.
            if ([name isKindOfClass:[NSString class]]) {
                const char *s = [(NSString *)name UTF8String];
                if (s) nme = s;
            }
            if ([reason isKindOfClass:[NSString class]]) {
                const char *s = [(NSString *)reason UTF8String];
                if (s) rsn = s;
            }

            GNBeaconLine("EXCEPTION name=%s reason=%s class=%s", nme, rsn, cls);

            // Throw site. These are return addresses into the code that called
            // the initialiser, i.e. the frame that decided to raise. The crash
            // report gives bare offsets; this gives the address that maps to
            // them.
            // Only level 0. __builtin_return_address(1) walks one frame past
            // ours, which is defined to be unreliable - and a diagnostic that
            // can itself fault is worse than one frame less. The full stack
            // comes from callStackSymbols below, which the runtime builds.
            void *caller = __builtin_extract_return_addr(__builtin_return_address(0));
            GNBeaconLine("EXCEPTION object=%p raised-from=%p",
                         (__bridge void *)result, caller);

            if (userInfo) {
                const char *ui = [[userInfo description] UTF8String];
                if (ui) GNBeaconLine("EXCEPTION userInfo=%s", ui);
            }

            // The runtime's own symbolication. Available even when the process
            // is about to abort, and it is the one stack that will survive into
            // the log.
            if ([result isKindOfClass:[NSException class]]) {
                NSArray<NSString *> *symbols = [(NSException *)result callStackSymbols];
                for (NSString *line in symbols) {
                    const char *s = [line UTF8String];
                    if (s) GNBeaconLine("  %s", s);
                }
            }
        }
        } @catch (__unused NSException *ignored) {
            GNBeaconLine("forensics: reading the exception threw - capture abandoned, "
                         "the app's exception is unaffected");
        }

        __sync_lock_release(&gForensicDepth);

        if (left <= 0) GNRestoreExceptionInit();
    }

    return result;
}

void GNInstallExceptionForensics(void) {
    if (gForensicInstalled) {
        GNBeaconLine("forensics: already installed");
        return;
    }

    Class cls = objc_getClass("NSException");
    if (!cls) {
        // libobjc owns NSException; it cannot be missing. Say so rather than
        // silently ending up with no capture at all.
        GNBeaconLine("forensics: NSException class not found - NO capture this launch");
        return;
    }

    SEL sel = sel_registerName("initWithName:reason:userInfo:");
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        GNBeaconLine("forensics: -[NSException initWithName:reason:userInfo:] not found - "
                     "NO capture this launch");
        return;
    }

    gExceptionInitMethod = m;
    gOrigExceptionInit = (GNExceptionInitFn)method_getImplementation(m);
    if (!gOrigExceptionInit) {
        GNBeaconLine("forensics: original implementation was NULL - refusing to install");
        return;
    }

    // "@@:@@@" = object, self, _cmd, name, reason, userInfo.
    class_replaceMethod(cls, sel, (IMP)GNExceptionInitForensics, "@@:@@@");

    gForensicInstalled = 1;
    GNBeaconLine("forensics: -[NSException initWithName:reason:userInfo:] captured "
                 "(budget %d, reads only, removes itself afterwards)", GN_FORENSIC_BUDGET);
}
