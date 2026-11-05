//
//  GNThrowTrace.m
//  Last-resort capture of the exception object itself.
//
//  Why the other two mechanisms were not enough
//  --------------------------------------------
//  v10 had two ways of learning what threw, and the .ips showed that neither
//  could have worked on this crash:
//
//    * NSSetUncaughtExceptionHandler (GNSupport.m). The throw went
//      __cxa_throw -> failed_throw -> std::__terminate -> <app terminate
//      handler> -> _objc_terminate -> demangling_terminate_handler -> abort.
//      `failed_throw` is the path libc++abi takes when the unwind found no
//      handler at all, and in that state __cxa_current_exception_type() is
//      null - which is exactly why _objc_terminate fell through to the default
//      handler instead of calling the uncaught handler. So the handler we
//      installed was never reached, and no name/reason was written.
//
//    * @try around the app delegate's launch selectors (GNGuard.m). The .ips
//      contains no frame of ours, so the wrapper was not in the chain.
//
//  What is left is the one call every Objective-C exception must pass through,
//  wherever it is thrown from and whoever catches it:
//
//      objc_exception_throw(id exception)
//
//  Rebinding its import slots in app owned images gives us the exception object
//  before the unwind starts: name, reason, userInfo, and the stack *at the throw
//  site* - which is the frame the .ips renders as `(imageIndex 37)`. We log it
//  and then call the real function, so behaviour is unchanged: this is a tap,
//  not a handler.
//
//  Two hazards, both handled rather than commented away
//  ---------------------------------------------------
//    * This dylib is app owned, so its own call to objc_exception_throw is
//      rebound too. gInThrowTracer is per-thread and set for the whole of the
//      logging block: a throw from inside our own report takes the real path
//      instead of recursing.
//    * It is the only part of v11 that rewrites a data page during dyld init,
//      and this project has already lost a launch to a decoder defect there.
//      So "auto" (the default) installs it *only* when GNGuardNetCount() is
//      zero, i.e. only when the cheap nets are known to be missing. When the
//      @try nets are live, this never runs and the launch path is unchanged
//      from v10.
//

#import "GNUnlock.h"
#import "GNThrowTrampoline.h"

#import <dlfcn.h>
#import <fcntl.h>
#import <mach-o/dyld.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#if __has_include(<execinfo.h>)
#import <execinfo.h>
#define GN_THROW_HAVE_BACKTRACE 1
#endif

/// The real objc_exception_throw, resolved by the rebinder before it rewrites
/// anything. Never rebound itself: we call it through this pointer.
static void (*gRealObjcExceptionThrow)(id) = NULL;

/// Per-thread, not a plain static: two threads can throw at the same time, and
/// a global flag would turn the second one into a silent pass-through.
static __thread BOOL gInThrowTracer = NO;

/// Remaining reports this launch. -1 = not resolved yet.
static long gThrowBudget = -1;
static BOOL gWroteImageTable = NO;

static NSString *GNThrowPath(void) {
    return [GNDocumentsPath() stringByAppendingPathComponent:@"gnunlock-exceptions.txt"];
}

static void GNThrowAppend(NSString *text) {
    const char *utf8 = text.UTF8String;
    if (!utf8) return;

    const char *path = GNThrowPath().fileSystemRepresentation;
    if (!path) return;

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;

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

/// One line per frame: image basename + offset, which is the same arithmetic the
/// .ips does with `imageIndex` and `imageOffset`. This is what turns
/// `(imageIndex 37)` into a filename without needing the user's report.
static NSString *GNThrowAddressLines(void) {
    NSMutableString *text = [NSMutableString string];

#ifdef GN_THROW_HAVE_BACKTRACE
    // backtrace() rather than -[NSThread callStackReturnAddresses]: the thread
    // API only exists as a class method on some SDK versions, and this code has
    // to compile against the oldest one we support. The frames below ours
    // (GNThrowTracer) are the throw site, which is the point.
    void *frames[48];
    int count = backtrace(frames, 48);
    if (count <= 0) return @"  (backtrace() returned nothing)\n";

    for (int i = 0; i < count && i < 40; i++) {
        uintptr_t address = (uintptr_t)frames[i];
        Dl_info info;
        if (dladdr((const void *)address, &info) && info.dli_fname) {
            const char *base = strrchr(info.dli_fname, '/');
            [text appendFormat:@"  %2d  %-32s + 0x%llx\n",
                                i, base ? base + 1 : info.dli_fname,
                                (unsigned long long)(address - (uintptr_t)info.dli_fbase)];
        } else {
            [text appendFormat:@"  %2d  0x%llx (unresolved)\n",
                                i, (unsigned long long)address];
        }
    }
#else
    [text appendString:@"  (execinfo.h unavailable - no addresses)\n"];
#endif

    return text;
}

static NSString *GNThrowImageTable(void) {
    NSMutableString *table = [NSMutableString string];
    uint32_t count = _dyld_image_count();
    uint32_t listed = 0;

    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        if (listed >= 400) {
            [table appendFormat:@"  ... %u images loaded, list truncated\n", count];
            break;
        }
        [table appendFormat:@"  image[%3u] %s\n", i, path];
        listed++;
    }
    if (listed == 0) [table appendString:@"  (no images)\n"];
    return table;
}

static void GNThrowRecord(id exception) {
    NSString *name = @"(not an NSException)";
    NSString *reason = @"(none)";
    NSString *userInfo = @"(none)";

    if ([exception isKindOfClass:[NSException class]]) {
        NSException *ns = (NSException *)exception;
        name = ns.name ?: @"(no name)";
        reason = ns.reason ?: @"(no reason)";
        userInfo = ns.userInfo.count ? [ns.userInfo description] : @"(none)";
    } else if (exception) {
        name = [exception description] ?: @"(no description)";
    }

    NSMutableString *text = [NSMutableString string];
    [text appendString:@"\n=== GNUnlock throw trace ===\n"];
    [text appendFormat:@"when       : %.0f (unix seconds)\n", [NSDate date].timeIntervalSince1970];
    [text appendFormat:@"phase      : %s\n", GNCurrentPhase()];
    [text appendFormat:@"run level  : %d (%s)\n", GNRunLevel(), GNRunLevelName(GNRunLevel())];
    [text appendFormat:@"experiment : %@\n", GNExperimentStatus()];
    [text appendFormat:@"name       : %@\n", name];
    [text appendFormat:@"reason     : %@\n", reason];
    [text appendFormat:@"userInfo   : %@\n", userInfo];

    [text appendString:@"\n--- throw site (symbolicated) ---\n"];
    NSArray<NSString *> *symbols = [NSThread callStackSymbols];
    if (symbols.count == 0) {
        [text appendString:@"  (no symbols)\n"];
    } else {
        NSUInteger index = 0;
        for (NSString *line in symbols) {
            if (index >= 40) {
                [text appendFormat:@"  ... %lu more frames\n",
                                    (unsigned long)(symbols.count - index)];
                break;
            }
            [text appendFormat:@"  %2lu  %@\n", (unsigned long)index, line ?: @"?"];
            index++;
        }
    }

    [text appendString:@"\n--- throw site (image + offset, matches .ips) ---\n"];
    [text appendString:GNThrowAddressLines()];

    if (!gWroteImageTable) {
        gWroteImageTable = YES;
        [text appendString:@"\n--- dyld image table (index == \"imageIndex\" in an .ips) ---\n"];
        [text appendString:GNThrowImageTable()];
    }

    GNThrowAppend(text);

    for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
        if (line.length) GNLogC("throw| %s", line.UTF8String ?: "");
    }
}

/// YES for the exceptions this project is actually chasing.
///
/// v18 installs the tap by default, so it now runs for every ObjC exception in
/// the process, and most of those are control flow rather than a crash. The full
/// record (symbolicated stack + dyld image table) is written for the interesting
/// names always, and for everything else only while the budget lasts - which
/// keeps a chatty launch from turning into a 40 second one.
static BOOL GNThrowNameInteresting(NSString *name) {
    if (!name) return NO;
    if ([name rangeOfString:@"CK" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    if ([name rangeOfString:@"Cloud" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    if ([name rangeOfString:@"entitle" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    return NO;
}

/// Writes the record and returns. Split out in v20 so the trampoline can decide
/// what to do *after* the evidence exists: a swallow that leaves no trace would
/// be indistinguishable from a throw that never happened.
void GNThrowTraceRecord(id exception) {
    NSString *throwName = [exception isKindOfClass:[NSException class]]
                              ? [(NSException *)exception name] : nil;
    BOOL interesting = GNThrowNameInteresting(throwName);

    if (gInThrowTracer || (!interesting && gThrowBudget == 0)) return;

    gInThrowTracer = YES;
    if (!interesting && gThrowBudget > 0) gThrowBudget--;

    @autoreleasepool {
        @try {
            GNThrowRecord(exception);
        } @catch (NSException *inner) {
            GNLogC("throw trace: report failed - %s: %s",
                   (inner.name ?: @"?").UTF8String,
                   (inner.reason ?: @"?").UTF8String);
        }
    }

    gInThrowTracer = NO;
}

/// The real function, resolved by the slot walker before any slot was rewritten.
/// The v20 trampoline asks for it here rather than resolving again, so there is
/// exactly one place that can hold a pointer to the un-rebound function.
void *GNThrowTapRealThrow(void) {
    return (void *)gRealObjcExceptionThrow;
}

/// Never changes control flow: log, then throw for real.
static void GNThrowTracer(id exception) __attribute__((noreturn));
static void GNThrowTracer(id exception) {
    GNThrowTraceRecord(exception);

    if (gRealObjcExceptionThrow) gRealObjcExceptionThrow(exception);

    // objc_exception_throw is noreturn; this is only reachable if the rebinding
    // gave us a pointer that returns, in which case dying here is the honest
    // outcome - continuing would resume an unwind that never started.
    _exit(134);
}

static NSString *GNThrowMode(void) {
    NSString *mode = GNCGS(@"GuardTraceThrow");
    return mode.length ? mode.lowercaseString : @"auto";
}

#pragma mark - The v18 tap, installed through the slot walker

/// Hands the tap the real function and the budget. Called from the slot installer
/// after objc_exception_throw's slots have been rewritten, because the slot
/// walker is what resolves the real address.
void GNThrowTapActivate(void *real) {
    if (real && !gRealObjcExceptionThrow) {
        gRealObjcExceptionThrow = (void (*)(id))real;
    }
    if (gThrowBudget < 0) {
        NSInteger budget = GNCGI(@"GuardTraceThrowBudget", 40);
        if (budget < 1) budget = 1;
        if (budget > 200) budget = 200;
        gThrowBudget = (long)budget;
    }
}

/// The replacement the slot walker installs for objc_exception_throw, in every
/// image that has a slot for it - the dyld shared cache included.
///
/// Why a C function and not an assembly stub
/// -----------------------------------------
/// A slot rewrite is an indirect branch: the caller is already `blr x16` into
/// whatever the slot holds, so the first argument is in x0 and the return
/// address in x30, exactly as for the real function. An assembly stub would have
/// to do one of two things, and neither is available:
///
///   * tail-call the real function after saving x0 - which is what this function
///     does, and the compiler already emits it;
///   * skip the call and return to the caller - which is not a catch. The throw
///     call is the last instruction of its basic block because the compiler knows
///     objc_exception_throw does not return; there is no landing pad to resume at,
///     and the registers still hold the operands of the throw. In CloudKit that
///     code sits inside a dispatch_once, so the "resumed" process is one with a
///     half-initialised container - a crash that is harder to explain than the
///     one being avoided, and not reproducible on demand.
///
/// So the tap records and re-throws. What it buys is the thing v17's log could
/// not answer: the exception's *name*, its *reason* (which names the exact
/// entitlement and the type CloudKit wants), and the throw site with image and
/// offset - for exceptions thrown from the shared cache, where -[NSException
/// raise] is never called because the compiler emits a direct @throw.
void GNThrowTapObject(id exception) {
    // v20: the slot now points at GNThrowTrampolineObject, which owns the
    // decision. This entry point stays because the legacy rebinder in this file
    // names it, and one place to install from is worth more than one fewer
    // forwarding call.
    (void)GNThrowTrampolineObject((__bridge void *)exception);
}

void GNInstallThrowTracer(NSInteger netsInstalled) {
    NSString *mode = GNThrowMode();

    if ([mode isEqualToString:@"never"] || [mode isEqualToString:@"off"]) {
        GNLogC("throw trace: disabled by config (GuardTraceThrow=%s)", mode.UTF8String ?: "?");
        return;
    }
    if (![mode isEqualToString:@"always"] && netsInstalled > 0) {
        GNLogC("throw trace: %ld @try net(s) live, so the cheap capture is enough - "
               "not rebinding objc_exception_throw (GuardTraceThrow=auto)",
               (long)netsInstalled);
        return;
    }
    if (GNSafeModeActive()) {
        GNLogC("throw trace: safe mode (the previous launch died in our code) - skipped");
        return;
    }

    if (gThrowBudget < 0) {
        // 40, not 12: an app throws ObjC exceptions for control flow all the
        // time, and a small budget would be spent by the harmless ones before
        // the fatal throw ever happens. The entries are appended, so the last
        // one in the file is the one that killed the launch.
        NSInteger budget = GNCGI(@"GuardTraceThrowBudget", 40);
        if (budget < 1) budget = 1;
        if (budget > 200) budget = 200;
        gThrowBudget = (long)budget;
    }

    void *real = NULL;
    NSInteger sites = GNRebindSymbolInAppImages("objc_exception_throw",
                                                (void *)GNThrowTracer, &real);
    gRealObjcExceptionThrow = (void (*)(id))real;

    if (!gRealObjcExceptionThrow) {
        GNLogC("throw trace: objc_exception_throw not resolvable - nothing installed");
        return;
    }
    if (sites <= 0) {
        GNLogC("throw trace: no import slot to rebind - the next crash stays anonymous");
        return;
    }

    GNLogC("throw trace: objc_exception_throw traced in %ld slot(s), budget %ld -> "
           "Documents/gnunlock-exceptions.txt", (long)sites, gThrowBudget);
}
