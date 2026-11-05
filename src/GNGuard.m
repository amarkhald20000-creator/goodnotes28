//
//  GNGuard.m
//  Launch-time forensics.
//
//  The crash this file exists for:
//
//      SIGABRT, asi = "abort() called",
//      lastExceptionBacktrace =
//          __exceptionPreprocess / objc_exception_throw
//          <framework, imageIndex 38>
//          _dispatch_client_callout
//          _dispatch_once_callout
//          <framework, imageIndex 38>
//          <app binary, imageIndex 0>  x4
//          -[UIApplication _handleDelegateCallbacksWithOptions:...]
//
//  That is not a memory fault and it is not a silent integrity check tripping.
//  It is an NSException raised inside a dispatch_once block, during the app
//  delegate callbacks, and left uncaught - the ObjC runtime then calls
//  std::terminate, libsystem_c calls abort(), and the kernel writes SIGABRT.
//
//  An anti-tamper check that wants the process dead does not do any of that: it
//  calls exit()/abort() straight, or it traps (SIGILL / SIGTRAP, no
//  lastExceptionBacktrace, no exceptionReason). The presence of that backtrace
//  means *some* Objective-C code raised, and that code is named in
//  exception.name / exception.reason - which is exactly the piece the .ips
//  report throws away.
//
//  So this module does not guess which hook is guilty. It puts a @try/@catch
//  around the app's own launch entry points, and when something throws it
//  records:
//
//      exception.name, exception.reason, exception.userInfo
//      exception.callStackSymbols      (symbolicated, so imageIndex 38 is named)
//      the dyld image table            (so an .ips imageIndex can be resolved)
//      the run level, phase, signature mode
//
//  ...writes it to Documents/gnunlock-lastcrash.txt, copies it to the
//  pasteboard (the one channel that works without container access), drops the
//  auto-bisect ladder one rung, and puts it on screen. Then - by default - it
//  swallows the exception and lets the launch continue, because a launch that
//  limps is more useful than a launch that dies.
//
//  Nothing here writes executable memory. Everything is a method list change
//  or a data file, so it is safe under a Distribution certificate.
//
//  Two hazards are worth naming, because both would be silent:
//
//    * The abort tracer rebinds `abort` / `exit` import slots in *app owned*
//      images - and this dylib is app owned, so its own slots get rebound too.
//      The tracer therefore calls the real functions through pointers saved
//      before rebinding, and falls back to _exit() (never rebound) rather than
//      to abort(). build.sh lints for a bare abort()/exit() in this file.
//
//    * It is scheduled for after launch, not run from the constructor. v9 ran
//      it inline, so an import-table walk that faulted took the process down
//      during dyld init - before the log, the bisect ladder or the notice could
//      say anything. See GNScheduleAbortTracer().
//
//    * Swallowing an exception thrown from a dispatch_once block leaves that
//      block's gate entered. The app may hang later instead of crashing. That
//      is a legitimate outcome to report, and GuardSwallow=false goes back to
//      rethrowing - the report is recorded either way, before the rethrow.
//

#import "GNUnlock.h"

#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>
#import <mach-o/dyld.h>
#import <dispatch/dispatch.h>

#pragma mark - State

static BOOL gGuardInstalled = NO;
static BOOL gDelegateInstrumented = NO;
static BOOL gInAbortTracer = NO;

/// Number of @try nets that are actually in the chain. Logged, and handed to
/// GNInstallThrowTracer(): zero here means this launch cannot name an exception
/// no matter what happens next.
static NSInteger gGuardNets = 0;

static BOOL (*gOrigWillFinish)(id, SEL, id, id);
static BOOL (*gOrigDidFinish)(id, SEL, id, id);
/// The original IMP. Declared returning void because we do not use its result;
/// calling a value-returning function through a void prototype only discards
/// x0, which is safe - the reverse (calling void through a value prototype) is
/// the direction that would hand a garbage read back to UIKit.
static void (*gOrigHandleDelegateCallbacks)(id, SEL, id, BOOL, BOOL);
static void (*gRealAbort)(void);
static void (*gRealExit)(int);

/// Wrappers installed on the app delegate's launch selectors. Declared here
/// because the instrumenter references them before their bodies.
static BOOL GNGuardWillFinishCaller(id self, SEL _cmd, id application, id options);
static BOOL GNGuardDidFinishCaller(id self, SEL _cmd, id application, id options);

#pragma mark - Report building

/// The dyld image table. This is what turns `"imageIndex": 38` in an .ips into
/// a name: the report is written by the same process that has the table.
static NSString *GNGuardImageTable(BOOL appOwnedOnly) {
    NSMutableString *table = [NSMutableString string];
    uint32_t count = _dyld_image_count();
    NSUInteger listed = 0;

    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        if (appOwnedOnly && !GNIsAppOwnedImage(i)) continue;
        if (listed >= 400) {
            [table appendFormat:@"  ... %u images loaded, list truncated\n", count];
            break;
        }
        [table appendFormat:@"  image[%3u] %s\n", i, path];
        listed++;
    }

    if (listed == 0) [table appendString:@"  (no images matched)\n"];
    return table;
}

static NSString *GNGuardStackText(NSArray<NSString *> *symbols, NSUInteger limit) {
    if (![symbols isKindOfClass:[NSArray class]] || symbols.count == 0) {
        return @"  (no symbols: exception.callStackSymbols was empty)\n";
    }

    NSMutableString *text = [NSMutableString string];
    NSUInteger index = 0;
    for (NSString *line in symbols) {
        if (limit && index >= limit) {
            [text appendFormat:@"  ... %lu more frames\n", (unsigned long)(symbols.count - limit)];
            break;
        }
        [text appendFormat:@"  %2lu  %@\n", (unsigned long)index, line ?: @"?"];
        index++;
    }
    return text;
}

/// Shared header: the facts that only the live process can answer.
static void GNGuardAppendEnvironment(NSMutableString *text) {
    int level = GNRunLevel();
    [text appendFormat:@"phase      : %s\n", GNCurrentPhase()];
    [text appendFormat:@"run level  : %d (%s)\n", level, GNRunLevelName(level)];
    [text appendFormat:@"signature  : %s\n", GNSignatureMode()];
    // Which experiment was running when this happened. Without it, a report from
    // step 3 and a report from step 0 read identically.
    [text appendFormat:@"experiment : %@\n", GNExperimentStatus()];
    [text appendFormat:@"memory     : %s\n", GNMemoryPolicySummary()];
    [text appendFormat:@"main image : %s\n", GNMainImageName()];
    [text appendFormat:@"time       : %.0f (unix seconds)\n",
                       [NSDate date].timeIntervalSince1970];
}

static void GNGuardWriteFile(NSString *text) {
    const char *utf8 = text.UTF8String;
    if (!utf8) return;

    const char *path = GNLastCrashPath().fileSystemRepresentation;
    if (!path) return;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        GNLogC("guard: could not open %s for writing", GNLastCrashPath().UTF8String ?: "?");
        return;
    }

    size_t length = strlen(utf8);
    size_t written = 0;
    while (written < length) {
        ssize_t chunk = write(fd, utf8 + written, length - written);
        if (chunk <= 0) break;
        written += (size_t)chunk;
    }
    fsync(fd);
    close(fd);
}

/// The pasteboard is the only channel that reaches the user without container
/// access, a working app or a Mac. Writing it does not prompt.
static void GNGuardCopyToPasteboard(NSString *text) {
    if (!GNCFG(@"GuardCopyToPasteboard", YES)) return;
    if (!text.length) return;

    @try {
        [UIPasteboard generalPasteboard].string = text;
        GNLogC("guard: report copied to the pasteboard (%lu chars)",
               (unsigned long)text.length);
    } @catch (NSException *exception) {
        GNLogC("guard: pasteboard copy failed - %s", (exception.reason ?: @"?").UTF8String);
    }
}

#pragma mark - Catch reporting

static void GNGuardRecord(NSString *title, NSString *full, NSString *onScreen) {
    GNGuardWriteFile(full);
    GNGuardCopyToPasteboard(full);

    for (NSString *line in [full componentsSeparatedByString:@"\n"]) {
        if (line.length) GNLogC("guard| %s", line.UTF8String ?: "");
    }

    GNPresentDiagnostic(title, onScreen);
}

static void GNGuardHandleException(NSException *exception, const char *where, BOOL swallow) {
    if (!exception) return;

    NSMutableString *full = [NSMutableString string];
    [full appendString:@"=== GNUnlock launch forensics ===\n"];
    [full appendString:@"result     : NSException caught by GNGuard (the app did NOT die here)\n"];
    [full appendFormat:@"where      : %s\n", where ?: "?"];
    GNGuardAppendEnvironment(full);
    [full appendFormat:@"action     : %s\n", swallow ? "swallowed, launch continued"
                                                    : "rethrown, launch dies as it did before"];
    [full appendString:@"\n--- the exception ---\n"];
    [full appendFormat:@"name       : %@\n", exception.name ?: @"(none)"];
    [full appendFormat:@"reason     : %@\n", exception.reason ?: @"(none)"];
    if ([exception.userInfo count]) {
        [full appendFormat:@"userInfo   : %@\n", exception.userInfo];
    }

    [full appendString:@"\n--- stack at throw time (symbolicated) ---\n"];
    [full appendString:GNGuardStackText(exception.callStackSymbols, 0)];

    NSArray *addresses = exception.callStackReturnAddresses;
    if ([addresses isKindOfClass:[NSArray class]] && addresses.count) {
        [full appendString:@"\n--- stack addresses (image + offset, matches .ips) ---\n"];
        NSUInteger index = 0;
        for (id entry in addresses) {
            uintptr_t address = (uintptr_t)[entry unsignedLongLongValue];
            Dl_info info;
            if (dladdr((const void *)address, &info) && info.dli_fname) {
                const char *base = strrchr(info.dli_fname, '/');
                [full appendFormat:@"  %2lu  %-34s + 0x%llx\n",
                                   (unsigned long)index,
                                   base ? base + 1 : info.dli_fname,
                                   (unsigned long long)(address - (uintptr_t)info.dli_fbase)];
            } else {
                [full appendFormat:@"  %2lu  0x%llx (unresolved)\n",
                                   (unsigned long)index, (unsigned long long)address];
            }
            index++;
            if (index >= 64) break;
        }
    }

    [full appendString:@"\n--- dyld image table (index == \"imageIndex\" in an .ips) ---\n"];
    [full appendString:GNGuardImageTable(NO)];

    // The on screen version stays short: the reason and the frames that matter.
    NSMutableString *onScreen = [NSMutableString string];
    [onScreen appendFormat:@"%@\n%@\n\n", exception.name ?: @"(no name)", exception.reason ?: @"(no reason)"];
    [onScreen appendFormat:@"caught in %s\nrun level %d\n\n", where ?: "?", GNRunLevel()];
    [onScreen appendString:GNGuardStackText(exception.callStackSymbols, 14)];
    [onScreen appendString:@"\nApp-owned images:\n"];
    [onScreen appendString:GNGuardImageTable(YES)];
    [onScreen appendString:@"\nThe full report (with the complete image table) is on the "
                       "clipboard - paste it into the chat.\nIt is also in Documents/gnunlock-lastcrash.txt."];

    GNGuardRecord(@"GNUnlock: launch exception caught", full, onScreen);

    // This rung is guilty by definition - whatever threw, it threw with this
    // much of the dylib installed. The next launch starts one level lower.
    GNDropRunLevel(where ?: "launch exception");
}

#pragma mark - Delegate instrumentation

/// Wraps the UIKit boundary that calls the app delegate, not just the delegate.
///
/// This is the v11 fix for the blind spot that made v9 and v10 useless on this
/// crash. Both of those wrapped -[<Delegate> application:didFinishLaunching-
/// WithOptions:] and nothing else, and the exception arrived on a stack in which
/// no frame of ours appeared at all - so the wrapping never happened (delegate
/// set by a path other than -[UIApplication setDelegate:], or the launch
/// callback that threw was not one of the two wrapped selectors), and the
/// report was never written.
///
/// -[UIApplication _handleDelegateCallbacksWithOptions:isSuspended:restoreState:]
/// sits directly under those callbacks - it is frame 22 in the .ips - and above
/// -[UIApplication _callInitializationDelegatesWithActions:...]. Wrapping it
/// catches willFinishLaunching, didFinishLaunching and anything the app does
/// inside either of them, whoever the delegate is and however it was installed.
///
/// It is a private method. That is acceptable here: this dylib is not shipping
/// to the App Store, and the alternative - guessing the delegate class - is what
/// already failed twice.
/// Returns BOOL although the method is almost certainly void, on purpose: if
/// UIKit does read x0 (i.e. the real method returns something), returning a
/// defined YES is safe, while a void wrapper leaves x0 holding whatever the last
/// call left there. If the method is void, the caller ignores it. Either way
/// this is the only choice that is defined behaviour in both cases.
static BOOL GNGuardHandleDelegateCallbacks(id self, SEL _cmd, id options,
                                           BOOL isSuspended, BOOL restoreState) {
    BOOL swallow = GNCFG(@"GuardSwallow", YES);
    @try {
        if (gOrigHandleDelegateCallbacks) {
            gOrigHandleDelegateCallbacks(self, _cmd, options, isSuspended, restoreState);
        }
    } @catch (NSException *exception) {
        GNGuardHandleException(exception,
                               "-[UIApplication _handleDelegateCallbacksWithOptions:"
                               "isSuspended:restoreState:]", swallow);
        if (!swallow) @throw;
        // Swallowed: return and let UIKit carry on with a partially initialised
        // delegate. The report is already on disk, so this costs nothing.
    }
    return YES;
}

static BOOL GNGuardInstallBoundaryNet(void) {
    if (!GNCFG(@"GuardCatchBoundary", YES)) {
        GNLogC("guard: boundary net disabled by config (GuardCatchBoundary=false)");
        return NO;
    }

    Class application = objc_getClass("UIApplication");
    if (!application) {
        GNLogC("guard: UIApplication missing - boundary net not possible");
        return NO;
    }

    IMP original = NULL;
    if (!GNHookInstance(application,
                        "_handleDelegateCallbacksWithOptions:isSuspended:restoreState:",
                        (IMP)&GNGuardHandleDelegateCallbacks, &original)) {
        GNLogC("guard: -[UIApplication _handleDelegateCallbacks...] not present on this "
               "iOS version - falling back to the delegate net alone");
        return NO;
    }

    gOrigHandleDelegateCallbacks = (void (*)(id, SEL, id, BOOL, BOOL))original;
    gGuardNets++;
    GNLogC("guard: boundary net installed on -[UIApplication "
           "_handleDelegateCallbacksWithOptions:isSuspended:restoreState:]");
    return YES;
}

NSInteger GNGuardNetCount(void) {
    return gGuardNets;
}

/// Wraps the app's own launch entry points. These are the frames between
/// -[UIApplication _handleDelegateCallbacksWithOptions:...] and the framework
/// that threw, so an exception raised there is caught here, typed, and with the
/// correct return value (BOOL YES - the app is asked to keep going).
static void GNGuardInstrumentDelegate(id delegate) {
    if (gDelegateInstrumented || !delegate) return;

    Class cls = object_getClass(delegate);
    if (!cls || class_isMetaClass(cls)) return;

    const char *name = class_getName(cls);
    const char *image = class_getImageName(cls);
    if (!name) return;

    if (image && GNIsSystemImagePath(image)) {
        GNLogC("guard: delegate class %s belongs to a system image - not instrumented", name);
        return;
    }

    GNLogC("guard: delegate is %s (%s)", name, image ?: "?");

    BOOL hooked = NO;
    if (GNCFG(@"GuardCatchWillFinish", YES)) {
        IMP original = NULL;
        if (GNHookInstance(cls, "application:willFinishLaunchingWithOptions:",
                           (IMP)&GNGuardWillFinishCaller, &original)) {
            gOrigWillFinish = (BOOL (*)(id, SEL, id, id))original;
            hooked = YES;
        }
    }
    if (GNCFG(@"GuardCatchDidFinish", YES)) {
        IMP original = NULL;
        if (GNHookInstance(cls, "application:didFinishLaunchingWithOptions:",
                           (IMP)&GNGuardDidFinishCaller, &original)) {
            gOrigDidFinish = (BOOL (*)(id, SEL, id, id))original;
            hooked = YES;
        }
    }

    if (!hooked) {
        GNLogC("guard: neither launch selector could be wrapped on %s - the "
               "uncaught exception handler is the only net this launch", name);
        return;
    }

    gDelegateInstrumented = YES;
    if (hooked) gGuardNets++;
    GNLogC("guard: launch entry points wrapped on %s (nets now %ld)",
           name, (long)gGuardNets);
}

static BOOL GNGuardWillFinishCaller(id self, SEL _cmd, id application, id options) {
    BOOL swallow = GNCFG(@"GuardSwallow", YES);
    @try {
        return gOrigWillFinish ? gOrigWillFinish(self, _cmd, application, options) : YES;
    } @catch (NSException *exception) {
        GNGuardHandleException(exception, "-[delegate application:willFinishLaunchingWithOptions:]", swallow);
        if (!swallow) @throw;
        return YES;
    }
}

static BOOL GNGuardDidFinishCaller(id self, SEL _cmd, id application, id options) {
    BOOL swallow = GNCFG(@"GuardSwallow", YES);
    @try {
        return gOrigDidFinish ? gOrigDidFinish(self, _cmd, application, options) : YES;
    } @catch (NSException *exception) {
        GNGuardHandleException(exception, "-[delegate application:didFinishLaunchingWithOptions:]", swallow);
        if (!swallow) @throw;
        return YES;
    }
}

static void (*gOrigSetDelegateHookTarget)(id, SEL, id);

static void GNGuardSetDelegate(id self, SEL _cmd, id delegate) {
    if (gOrigSetDelegateHookTarget) gOrigSetDelegateHookTarget(self, _cmd, delegate);

    @try {
        GNGuardInstrumentDelegate(delegate);
    } @catch (NSException *exception) {
        GNLogC("guard: instrumenting the delegate threw %s: %s",
               (exception.name ?: @"?").UTF8String, (exception.reason ?: @"?").UTF8String);
    }
}

#pragma mark - Abort / exit tracing

/// Reached only when *app owned* code calls abort(). An anti-tamper check that
/// kills the process silently lands here; libobjc's own terminate path does
/// not, because that call is inside a system image and is not rebound.
static void GNGuardAbortTracer(void) __attribute__((noreturn));
static void GNGuardAbortTracer(void) {
    if (gInAbortTracer) {
        // Never recurse: our own images were rebound too.
        if (gRealAbort) gRealAbort();
        _exit(134);
    }
    gInAbortTracer = YES;

    NSMutableString *full = [NSMutableString string];
    [full appendString:@"=== GNUnlock launch forensics ===\n"];
    [full appendString:@"result     : abort() called from app owned code\n"];
    GNGuardAppendEnvironment(full);
    [full appendString:@"\nThis is what an integrity / anti-tamper kill looks like when it\n"
                    "does not go through the ObjC exception machinery. The stack below\n"
                    "names the caller.\n"];
    [full appendString:@"\n--- stack (this thread) ---\n"];
    [full appendString:GNGuardStackText([NSThread callStackSymbols], 0)];
    [full appendString:@"\n--- dyld image table ---\n"];
    [full appendString:GNGuardImageTable(NO)];

    GNGuardWriteFile(full);
    GNGuardCopyToPasteboard(full);
    for (NSString *line in [full componentsSeparatedByString:@"\n"]) {
        if (line.length) GNLogC("guard-abort| %s", line.UTF8String ?: "");
    }

    if (gRealAbort) gRealAbort();
    _exit(134);
}

static void GNGuardExitTracer(int status) __attribute__((noreturn));
static void GNGuardExitTracer(int status) {
    if (!gInAbortTracer) {
        gInAbortTracer = YES;
        NSString *text = [NSString stringWithFormat:
            @"=== GNUnlock launch forensics ===\n"
            @"result : exit(%d) called from app owned code\n"
            @"stack  :\n%@", status, GNGuardStackText([NSThread callStackSymbols], 40)];
        GNGuardWriteFile(text);
        GNGuardCopyToPasteboard(text);
        GNLogC("guard: exit(%d) traced, see Documents/gnunlock-lastcrash.txt", status);
    }
    if (gRealExit) gRealExit(status);
    _exit(status);
}

static void GNInstallAbortTracerNow(void) {
    if (gRealAbort || gRealExit) return;        // already installed, once only
    if (gInAbortTracer) return;                 // re-entered from a tracer

    gRealAbort = (void (*)(void))dlsym(RTLD_DEFAULT, "abort");
    gRealExit = (void (*)(int))dlsym(RTLD_DEFAULT, "exit");
    if (!gRealAbort || !gRealExit) {
        GNLogC("guard: abort/exit not resolvable - tracing skipped");
        gRealAbort = NULL;
        gRealExit = NULL;
        return;
    }

    // Data pages only: this rewrites import slots, it never touches code, so a
    // Distribution signature cannot be tripped by it. Deliberately not routed
    // through GNInterposeSymbol(): that one is gated behind EnableGOTRebinding,
    // and this tracer is a diagnostic, not a behaviour change.
    NSInteger abortSites = GNRebindSymbolInAppImages("abort", (void *)GNGuardAbortTracer, NULL);
    NSInteger exitSites = GNRebindSymbolInAppImages("exit", (void *)GNGuardExitTracer, NULL);

    GNLogC("guard: abort tracer on %ld slot(s), exit tracer on %ld slot(s)",
           (long)abortSites, (long)exitSites);
}

/// Schedules the tracers for after the app is up.
///
/// This is the v10 fix for the launch crash. v9 called the rebinder straight
/// from the dylib constructor, which means the whole import-table walk ran
/// inside dyld initialisation: a SIGBUS there kills the process before any of
/// our own diagnostics, before the auto-bisect ladder and before a single line
/// of the log reaches disk. Two things changed:
///
///   * the work is deferred, so a defect in it can no longer stop the launch;
///   * it is gated on both GuardTraceAbort *and* EnableGOTRebinding, because it
///     is the same data-page rewrite as the rest of the C level fixes. The old
///     code bypassed that switch, which is why a feature documented as off by
///     default was running on every launch.
static void GNScheduleAbortTracer(void) {
    if (!GNCFG(@"GuardTraceAbort", NO)) {
        GNLogC("guard: abort / exit tracing disabled (GuardTraceAbort=false)");
        return;
    }
    if (!GNCFG(@"EnableGOTRebinding", NO)) {
        GNLogC("guard: abort / exit tracing needs EnableGOTRebinding=true - skipped");
        return;
    }
    if (GNSafeModeActive()) {
        GNLogC("guard: abort / exit tracing skipped in safe mode");
        return;
    }

    double delay = GNCFGD(@"GuardTraceAbortDelay", 2.0);
    if (delay < 0 || delay > 30) delay = 2.0;

    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   queue, ^{
        @autoreleasepool {
            @try {
                GNInstallAbortTracerNow();
            } @catch (NSException *exception) {
                GNLogC("guard: abort tracer install threw %s: %s",
                       (exception.name ?: @"?").UTF8String,
                       (exception.reason ?: @"?").UTF8String);
            }
        }
    });

    GNLogC("guard: abort / exit tracing scheduled in %.1fs (after launch)", delay);
}

#pragma mark - Entry point

void GNInstallLaunchGuard(void) {
    if (gGuardInstalled) return;

    if (!GNCFG(@"GuardEnabled", YES)) {
        GNLogC("guard: disabled by config - a launch crash will be as opaque as before");
        return;
    }

    gGuardInstalled = YES;
    GNLogC("guard: installing launch forensics (swallow=%s, traceAbort=%s)",
           GNCFG(@"GuardSwallow", YES) ? "yes" : "no",
           GNCFG(@"GuardTraceAbort", YES) ? "yes" : "no");

    Class application = objc_getClass("UIApplication");
    if (!application) {
        // UIKit is a load command of this dylib, so it is normally already
        // there by the time a constructor runs. Ask for it anyway rather than
        // silently losing the guard on an unusual load order.
        dlopen("/System/Library/Frameworks/UIKit.framework/UIKit", RTLD_LAZY | RTLD_GLOBAL);
        application = objc_getClass("UIApplication");
    }

    if (!application) {
        GNLogC("guard: UIApplication not loaded - delegate wrapper skipped");
    } else {
        // Boundary first: it does not depend on who the delegate is, so it is
        // the net that survives a delegate class this code cannot predict.
        GNGuardInstallBoundaryNet();

        IMP original = NULL;
        if (GNHookInstance(application, "setDelegate:", (IMP)&GNGuardSetDelegate, &original)) {
            gOrigSetDelegateHookTarget = (void (*)(id, SEL, id))original;
        } else {
            GNLogC("guard: -[UIApplication setDelegate:] not found - the app delegate "
                   "will not be wrapped");
        }

        // A delegate may already be in place (UIApplicationMain sets it through
        // a path that is not the public setter on some iOS versions). Ask once,
        // now, rather than discovering it never happened on the next crash.
        @try {
            // +sharedApplication, not the class object: -delegate on a Class
            // sends a class method, and UIApplication has no +delegate - that
            // would be an unrecognized selector on every launch. Before
            // UIApplicationMain the singleton is nil, which is fine here.
            id existing = [(UIApplication *)[application sharedApplication] delegate];
            if (existing) {
                GNLogC("guard: a delegate was already installed at load time - wrapping it now");
                GNGuardInstrumentDelegate(existing);
            }
        } @catch (NSException *exception) {
            GNLogC("guard: asking UIApplication for its delegate threw %s",
                   (exception.name ?: @"?").UTF8String);
        }
    }

    GNScheduleAbortTracer();

    if (gGuardNets == 0) {
        GNLogC("guard: WARNING no net installed - an exception this launch would be as "
               "anonymous as the last one (see GNInstallThrowTracer in GNUnlockEntry)");
    } else {
        GNLogC("guard: %ld net(s) live", (long)gGuardNets);
    }

    GNLogC("guard: ready (image table has %u entries)", _dyld_image_count());
}
