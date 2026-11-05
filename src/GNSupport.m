//
//  GNSupport.m
//  Logging, crash-loop state, config resolution, Mach-O helpers, safe memory
//  writes and the inline hook engine.
//
//  Everything here has to work from a dylib constructor, i.e. before
//  UIApplicationMain exists. No NSBundle lookups at that point, no
//  NSUserDefaults, no dispatch to the main queue.
//

#import "GNUnlock.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_param.h>
#import <mach/vm_region.h>
#import <mach/vm_map.h>
// NOT <mach/mach_vm.h>. On iOS that header is a poison pill whose entire
// contents are `#error mach_vm.h unsupported.`, and the mach_vm_* family is not
// available to user space on the phone at all. vm_region_64 / vm_protect from
// <mach/vm_map.h> are the supported equivalents, and on a 64 bit only target
// the two address types are the same width.
#import <libkern/OSCacheControl.h>
#import <dlfcn.h>
#import <pthread.h>
#import <unistd.h>
#import <fcntl.h>
#import <string.h>
#import <stdlib.h>
#import <stdarg.h>
#import <stdio.h>
#import <signal.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <sys/time.h>
#import <time.h>

#if __has_include(<execinfo.h>)
#import <execinfo.h>
#define GN_HAVE_BACKTRACE 1
#endif

#include "GNExperimentLadder.h"

#if __has_include("GNBakedConfig.h")
#import "GNBakedConfig.h"
#define GN_HAVE_BAKED 1
#endif

#pragma mark - Globals

static int               gLogFD = -1;
static pthread_mutex_t   gLogLock = PTHREAD_MUTEX_INITIALIZER;
static char              gPhase[48] = "boot";
static volatile BOOL     gSafeMode = NO;
static NSString         *gDocsPath = nil;
static int               gRunLevel = -1;
static struct timespec   gBootTime = { 0, 0 };

/// What the *previous* launch left in the state file.
///
/// It has to be captured in GNLogBoot(), before that function overwrites the
/// file with "boot". Reading GNStatePath() later - which is what v8 to v10 did -
/// always returns the "boot" this launch just wrote, i.e. the ladder saw
/// "previous launch died during launch" on every single boot and stepped down
/// one level per launch even when nothing was wrong. Four launches of a healthy
/// build therefore ended at level 0 with every hook disabled.
static NSString         *gPreviousPhase = nil;

/// Milliseconds since this dylib's constructor started. Every log line carries
/// it, because "the process died at +0.9s" is a completely different diagnosis
/// from "it died at +12s".
static double GNUptimeMs(void) {
    if (gBootTime.tv_sec == 0 && gBootTime.tv_nsec == 0) return 0;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (double)(now.tv_sec - gBootTime.tv_sec) * 1000.0 +
           (double)(now.tv_nsec - gBootTime.tv_nsec) / 1000000.0;
}

#pragma mark - Paths

NSString *GNDocumentsPath(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // NSSearchPathForDirectoriesInDomains does not touch cfprefsd and is
        // safe this early.
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                             NSUserDomainMask, YES);
        gDocsPath = [paths firstObject] ?: NSTemporaryDirectory();
    });
    return gDocsPath;
}

static NSString *GNStatePath(void) {
    return [GNDocumentsPath() stringByAppendingPathComponent:@"gnunlock.state"];
}

static NSString *GNLogPath(void) {
    return [GNDocumentsPath() stringByAppendingPathComponent:@"gnunlock.log"];
}

#pragma mark - Low level logging

static void GNOpenLog(void) {
    if (gBootTime.tv_sec == 0 && gBootTime.tv_nsec == 0) {
        clock_gettime(CLOCK_MONOTONIC, &gBootTime);
    }
    if (gLogFD >= 0) return;
    const char *path = GNLogPath().fileSystemRepresentation;
    if (!path) return;
    gLogFD = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
}

static void GNRawWrite(const char *bytes, size_t len) {
    if (gLogFD < 0) GNOpenLog();
    if (gLogFD < 0) return;
    ssize_t ignored = write(gLogFD, bytes, len);
    (void)ignored;
}

static void GNFormatTimestamp(char *buf, size_t cap) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    time_t t = tv.tv_sec;
    localtime_r(&t, &tm);
    snprintf(buf, cap, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));
}

void GNLogC(const char *fmt, ...) {
    char stamped[1024];
    char ts[40];
    GNFormatTimestamp(ts, sizeof(ts));

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(stamped, sizeof(stamped), fmt, ap);
    va_end(ap);

    char line[1200];
    int n = snprintf(line, sizeof(line), "%s  +%7.1fms [%s]  %s\n",
                     ts, GNUptimeMs(), gPhase, stamped);
    if (n <= 0) return;
    if ((size_t)n > sizeof(line)) n = (int)sizeof(line);

    pthread_mutex_lock(&gLogLock);
    GNRawWrite(line, (size_t)n);
    pthread_mutex_unlock(&gLogLock);

    fputs(line, stderr);
}

/// No locks, no malloc - usable from a signal handler.
static void GNSignalWrite(const char *text) {
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "%s  [%s]  %s\n", "CRASH", gPhase, text);
    if (n <= 0) return;
    if (n > (int)sizeof(buf)) n = (int)sizeof(buf);
    if (gLogFD >= 0) {
        ssize_t ignored = write(gLogFD, buf, (size_t)n);
        (void)ignored;
    }
}

void GNLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    GNLogC("%s", msg.UTF8String ?: "");
}

#pragma mark - State / crash loop breaker

static void GNWriteState(NSString *value) {
    NSString *path = GNStatePath();
    [value writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
}

static int gDroppedTo = -1;

const char *GNCurrentPhase(void) {
    return gPhase;
}

void GNSetPhase(const char *phase) {
    if (phase && *phase) {
        strncpy(gPhase, phase, sizeof(gPhase) - 1);
        gPhase[sizeof(gPhase) - 1] = '\0';
    }
    GNWriteState([NSString stringWithFormat:@"%s", gPhase]);
}

BOOL GNSafeModeActive(void) {
    return gSafeMode;
}

#pragma mark - Crash handlers

/// Writes a self contained crash note. The log is useful when you can pull the
/// container; this file is what GNShowLaunchNotice() puts on screen on the next
/// launch, so the reason is readable even when nothing can be copied off the
/// device.
static void GNWriteLastCrash(NSException *exception) {
    if (!exception) return;

    NSString *path = GNLastCrashPath();
    NSMutableString *text = [NSMutableString string];
    [text appendFormat:@"phase      : %s\n", gPhase];
    int level = gRunLevel >= 0 ? gRunLevel : -1;
    [text appendFormat:@"run level  : %d (%s)\n", level,
                       level >= 0 ? GNRunLevelName(level) : "not resolved yet"];
    [text appendFormat:@"uptime     : %.1f ms\n", GNUptimeMs()];
    [text appendFormat:@"signature  : %s\n", GNSignatureMode()];
    [text appendFormat:@"exception  : %@\n", exception.name ?: @"(no name)"];
    [text appendFormat:@"reason     : %@\n", exception.reason ?: @"(no reason)"];
    if (exception.userInfo) {
        [text appendFormat:@"userInfo   : %@\n", exception.userInfo];
    }
    [text appendString:@"\nstack (symbolicated by the runtime):\n"];
    NSArray<NSString *> *symbols = exception.callStackSymbols;
    if (symbols.count == 0) {
        [text appendString:@"  (none)\n"];
    }
    for (NSString *line in symbols) {
        [text appendFormat:@"  %@\n", line ?: @""];
    }

    const char *utf8 = text.UTF8String;
    if (!utf8) return;

    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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

    // And into the log, so a pulled log has it too.
    GNLogC("last crash note written to Documents/%s", path.lastPathComponent.UTF8String ?: "?");
}

static void GNUncaughtExceptionHandler(NSException *exception) {
    GNLogC("UNCAUGHT EXCEPTION: %s: %s",
           exception.name.UTF8String ?: "?",
           exception.reason.UTF8String ?: "?");
    for (NSString *line in exception.callStackSymbols) {
        GNLogC("  %s", line.UTF8String ?: "");
    }
    GNWriteLastCrash(exception);
    GNWriteState([NSString stringWithFormat:@"crashed:%s", gPhase]);

    // The kernel is about to send SIGABRT; make sure nothing is still sitting in
    // a buffer when it does.
    if (gLogFD >= 0) fsync(gLogFD);
}

static void GNSignalHandler(int sig) {
    GNSignalWrite(sig == SIGSEGV ? "SIGSEGV" :
                  sig == SIGBUS  ? "SIGBUS"  :
                  sig == SIGABRT ? "SIGABRT" :
                  sig == SIGILL  ? "SIGILL"  :
                  sig == SIGTRAP ? "SIGTRAP" :
                  sig == SIGFPE  ? "SIGFPE"  : "SIGNAL");
#ifdef GN_HAVE_BACKTRACE
    void *frames[48];
    int count = backtrace(frames, 48);
    backtrace_symbols_fd(frames, count, gLogFD >= 0 ? gLogFD : 2);
#endif
    GNSignalWrite("--- end of crash dump ---");
    signal(sig, SIG_DFL);
    raise(sig);
}

static void GNInstallCrashHandlers(void) {
    NSSetUncaughtExceptionHandler(&GNUncaughtExceptionHandler);
    int sigs[] = { SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        signal(sigs[i], &GNSignalHandler);
    }
}

#pragma mark - Boot

void GNLogBoot(void) {
    GNOpenLog();

    NSString *prev = [NSString stringWithContentsOfFile:GNStatePath()
                                                encoding:NSUTF8StringEncoding
                                                   error:NULL];
    NSString *trimmed = [prev stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];

    // Capture before the state file is rewritten below: this value is the only
    // answer to "did the previous launch finish", and both the run level ladder
    // and the experiment ladder depend on it. See gPreviousPhase.
    gPreviousPhase = [trimmed copy];

    // "hooks" and "patching" mean the previous launch died inside our own code.
    BOOL crashedInOurCode = (trimmed.length > 0 &&
                             ![trimmed hasPrefix:@"ready"] &&
                             ![trimmed hasPrefix:@"crashed"]);

    if (crashedInOurCode && ![trimmed isEqualToString:@"boot"]) {
        gSafeMode = YES;
    }

    GNInstallCrashHandlers();

    GNWriteState(@"boot");

    GNLogC("================ GNUnlock start ================");
    GNLogC("main image: %s", GNMainImageName());
    GNLogC("documents: %s", GNDocumentsPath().UTF8String ?: "?");
    if (crashedInOurCode) {
        GNLogC("previous launch died at phase '%s' (no patches this launch unless the "
               "auto-bisect ladder says otherwise)", trimmed.UTF8String ?: "?");
    }

    // The image table is what turns the `"imageIndex": 38` in a crash report
    // into a name. It is cheap (two dyld calls per image) and it has to happen
    // before anything can abort, i.e. here and not in the delayed pipeline.
    if (GNCFG(@"LogImages", YES)) {
        uint32_t count = _dyld_image_count();
        GNLogC("images: %u loaded", count);
        for (uint32_t i = 0; i < count && i < 800; i++) {
            const char *path = _dyld_get_image_name(i);
            if (!path) continue;
            const char *slash = strrchr(path, '/');
            GNLogC("  image[%3u] %-34s %s", i, slash ? slash + 1 : path, path);
        }
    }
}

#pragma mark - Run level

NSString *GNLastCrashPath(void) {
    return [GNDocumentsPath() stringByAppendingPathComponent:@"gnunlock-lastcrash.txt"];
}

static NSString *GNBisectPath(void) {
    return [GNDocumentsPath() stringByAppendingPathComponent:@"gnunlock.bisect"];
}

static NSString *GNReadTrimmed(NSString *path) {
    NSString *text = [NSString stringWithContentsOfFile:path
                                               encoding:NSUTF8StringEncoding
                                                  error:NULL];
    if (!text) return nil;
    NSString *trimmed = [text stringByTrimmingCharactersInSet:
                         [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return trimmed.length ? trimmed : nil;
}

/// Phases that are written before the app is up. If the previous launch is
/// still sitting in one of them, it never finished launching.
static BOOL GNPhaseIsEarly(NSString *phase) {
    if (!phase.length) return NO;
    // "crashed:<phase the crash happened in>" - the inner phase is what counts,
    // so a crash after the app was already up does not cost a run level.
    if ([phase hasPrefix:@"crashed:"]) {
        return GNPhaseIsEarly([phase substringFromIndex:8]);
    }
    // v7 wrote this before UIApplicationMain and then went on to die during
    // app init, so on the first v8 launch it means "the previous launch never
    // finished launching" even though the prefix looks like a finished one.
    if ([phase isEqualToString:@"ready:hooks"]) return YES;
    return [phase hasPrefix:@"boot"] || [phase hasPrefix:@"hook"] ||
           [phase hasPrefix:@"patch"];
}

/// YES when the launch before this one never reached
/// UIApplicationDidFinishLaunchingNotification. Both ladders step on this and
/// nothing else - see gPreviousPhase for why the state file cannot be re-read.
BOOL GNPreviousLaunchWasEarly(void) {
    return GNPhaseIsEarly(gPreviousPhase);
}

const char *GNRunLevelName(int level) {
    switch (level) {
        case 0:  return "inert (log only, nothing installed)";
        case 1:  return "data hooks (NSUserDefaults overrides)";
        case 2:  return "data hooks + container fallbacks";
        case 3:  return "everything (+ keychain / SecCode / SecTask interposition)";
        default: return "unknown";
    }
}

int GNRunLevel(void) {
    if (gRunLevel >= 0) return gRunLevel;

    int configured = (int)GNCGI(@"RunLevel", 3);
    if (configured < 0) configured = 0;
    if (configured > 3) configured = 3;

    int level = configured;

    // The file is "<ConfigVersion>:<level>", so a new build (new ConfigVersion)
    // starts the ladder from RunLevel again instead of inheriting the level a
    // previous build settled on.
    NSInteger configVersion = GNCGI(@"ConfigVersion", 0);
    NSString *stored = GNReadTrimmed(GNBisectPath());
    if (stored) {
        NSArray *parts = [stored componentsSeparatedByString:@":"];
        BOOL stamped = (parts.count == 2);
        NSInteger stamp = stamped ? [[parts firstObject] integerValue] : 0;
        NSInteger value = stamped ? [[parts lastObject] integerValue] : stored.integerValue;
        if (value >= 0 && value <= configured) {
            if (stamped && stamp == configVersion) {
                level = (int)value;
            } else if (!stamped) {
                level = (int)value;
            } else {
                GNLogC("auto-bisect: bisect file is from config version %ld, this build is %ld "
                       "- starting at level %d", (long)stamp, (long)configVersion, level);
            }
        }
    }

    if (GNCFG(@"AutoBisect", YES) && !GNExperimentControlsRunLevel()) {
        if (GNPreviousLaunchWasEarly() && level > 0) {
            int next = level - 1;
            GNLogC("auto-bisect: previous launch stopped at '%s', before the app "
                   "finished launching -> level %d (%s) this launch",
                   gPreviousPhase.UTF8String ?: "?", next, GNRunLevelName(next));
            level = next;
            [[NSString stringWithFormat:@"%ld:%d", (long)configVersion, level]
                writeToFile:GNBisectPath() atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        }
    }

    gRunLevel = level;
    return level;
}

int GNDroppedToLevel(void) {
    return gDroppedTo;
}

void GNDropRunLevel(const char *reason) {
    // Two ladders, one signal. While an experiment step is being tried it owns
    // the run level, because dropping a level *and* changing the container
    // answer in the same relaunch would leave neither one named.
    if (GNExperimentControlsRunLevel()) {
        GNLogC("auto-bisect: not moving (%s) - the experiment ladder owns the run level",
               reason ?: "?");
        return;
    }
    if (!GNCFG(@"AutoBisect", YES)) {
        GNLogC("auto-bisect: %s - ladder disabled, level kept", reason ?: "?");
        return;
    }

    int current = gRunLevel >= 0 ? gRunLevel : GNRunLevel();
    int next = current - 1;
    if (next < 0) next = 0;
    if (next == current) {
        GNLogC("auto-bisect: already at level 0 - a crash from here on is not ours");
        return;
    }

    NSInteger configVersion = GNCGI(@"ConfigVersion", 0);
    [[NSString stringWithFormat:@"%ld:%d", (long)configVersion, next]
        writeToFile:GNBisectPath() atomically:YES encoding:NSUTF8StringEncoding error:NULL];

    gDroppedTo = next;
    GNLogC("auto-bisect: dropped level %d -> %d (%s) because %s; "
           "relaunch the app to test it", current, next, GNRunLevelName(next), reason ?: "?");
}

#pragma mark - Experiment ladder

//  The run level answers "is it us at all" and narrows to a group. It cannot
//  answer the question this crash asks: *within* level 2 there is more than one
//  way to be wrong. "docs" invents an empty container, "nil" reports no
//  container, "home" reports the app's own container, and the hook can be
//  removed entirely - four different app-visible worlds, four different code
//  paths in the app, one of which may be the one that throws.
//
//  So the ladder changes exactly one of those per launch, in this order:
//
//      0  baseline                      what the plist says
//      1  app group -> nil              no container, the honest answer
//      2  app group -> home             the app's own container
//      3  app group hook removed        the real API answer
//      4  keychain hook removed         only meaningful once rebinding is on
//      5  control: level 0, nothing     if this still dies, it is not us
//
//  A step is abandoned when the launch before it never finished; the first step
//  that survives to UIApplicationDidFinishLaunchingNotification is kept, and
//  the ladder stops. Bounded, self-terminating, and it needs no Mac, no plist
//  editing and no re-sign between attempts.

static NSString *GNExperimentPath(void) {
    return [GNDocumentsPath() stringByAppendingPathComponent:@"gnunlock.experiment"];
}

static NSArray<NSDictionary *> *GNExperimentSteps(void) {
    return @[
        @{ @"name": @"baseline (plist as shipped)" },
        @{ @"name": @"app group answers nil",
           @"overrides": @{ @"ResignFix": @{ @"AppGroupFallbackMode": @"nil" } } },
        @{ @"name": @"app group answers the app container",
           @"overrides": @{ @"ResignFix": @{ @"AppGroupFallbackMode": @"home" } } },
        @{ @"name": @"app group hook removed",
           @"overrides": @{ @"ResignFix": @{ @"AppGroupFallback": @NO } } },
        @{ @"name": @"keychain hook removed",
           @"overrides": @{ @"ResignFix": @{ @"StripKeychainAccessGroup": @NO } } },
        @{ @"name": @"control: run level 0, nothing of ours installed",
           @"overrides": @{ @"RunLevel": @0, @"ResignFix": @{ @"Enabled": @NO } } },
    ];
}

static int       gExperimentStep = -2;      // -2 = not resolved yet, -1 = off
static NSString *gExperimentState = nil;

static GNExperimentOutcome GNExperimentOutcomeFromString(NSString *state) {
    if ([state isEqualToString:@"won"]) return GNExperimentWon;
    if ([state isEqualToString:@"exhausted"]) return GNExperimentExhausted;
    return GNExperimentTrying;
}

static NSString *GNExperimentStringFromOutcome(GNExperimentOutcome outcome) {
    switch (outcome) {
        case GNExperimentWon:       return @"won";
        case GNExperimentExhausted: return @"exhausted";
        default:                    return @"trying";
    }
}

/// Reads "<ConfigVersion>:<step>:<state>" back. NO means "ignore the file and
/// start at step 0": unreadable, written by a different ConfigVersion, or out
/// of range for this build's ladder.
static BOOL GNExperimentRead(int count, NSInteger version, GNExperimentState *state) {
    NSString *stored = GNReadTrimmed(GNExperimentPath());
    if (!stored) return NO;

    NSArray *parts = [stored componentsSeparatedByString:@":"];
    if (parts.count != 3) return NO;
    if ([[parts firstObject] integerValue] != version) {
        GNLogC("experiment: stored step is from config version %ld, this build is %ld - reset",
               (long)[[parts firstObject] integerValue], (long)version);
        return NO;
    }

    int value = (int)[[parts objectAtIndex:1] integerValue];
    if (value < 0 || value >= count) return NO;

    state->step = value;
    state->outcome = GNExperimentOutcomeFromString([parts lastObject]);
    return YES;
}

static void GNExperimentWrite(int step, NSInteger version, NSString *state) {
    NSString *text = [NSString stringWithFormat:@"%ld:%d:%@", (long)version, step, state];
    [text writeToFile:GNExperimentPath() atomically:YES
             encoding:NSUTF8StringEncoding error:NULL];
}

/// Resolved once per launch. Takes its inputs as arguments on purpose: it runs
/// inside GNConfig(), and asking GNCFG() for its own switch would re-enter the
/// dispatch_once that is still running.
static int GNExperimentResolve(BOOL enabled, BOOL autoAdvance, NSInteger version) {
    if (gExperimentStep != -2) return gExperimentStep;

    if (!enabled) {
        gExperimentStep = -1;
        gExperimentState = @"off";
        return gExperimentStep;
    }

    int count = (int)GNExperimentSteps().count;

    GNExperimentState stored = { 0, GNExperimentTrying };
    BOOL storedValid = GNExperimentRead(count, version, &stored);

    // The decision itself lives in GNExperimentLadder.h so that it can be
    // executed by scripts/experiment_ladder_test.c instead of merely read.
    GNExperimentState next = GNExperimentNext(stored, storedValid,
                                             GNPreviousLaunchWasEarly(),
                                             autoAdvance, count);

    NSString *state = GNExperimentStringFromOutcome(next.outcome);
    gExperimentStep = next.step;
    gExperimentState = state;

    if (storedValid && next.outcome == GNExperimentExhausted &&
        stored.outcome == GNExperimentTrying) {
        GNLogC("experiment: all %d steps were tried and none survived - back to baseline; "
               "delete Documents/gnunlock.experiment to run the ladder again", count);
    } else if (storedValid && next.outcome == GNExperimentTrying && next.step != stored.step) {
        NSString *nextName = GNExperimentSteps()[next.step][@"name"];
        GNLogC("experiment: step %d did not survive launch -> trying step %d (%s)",
               stored.step, next.step, nextName.UTF8String ?: "?");
    }

    // Persist whenever the decision differs from the file, or the file was not
    // usable in the first place.
    if (!storedValid || next.step != stored.step || next.outcome != stored.outcome) {
        GNExperimentWrite(next.step, version, state);
    }
    return gExperimentStep;
}

/// The overrides the current step contributes to the parsed config, or nil.
static NSDictionary *GNExperimentOverridesForStep(int step) {
    if (step < 0) return nil;
    NSArray<NSDictionary *> *steps = GNExperimentSteps();
    if (step >= (int)steps.count) return nil;
    NSDictionary *overrides = steps[step][@"overrides"];
    return [overrides isKindOfClass:[NSDictionary class]] ? overrides : nil;
}

int GNExperimentStep(void) {
    return gExperimentStep == -2 ? -1 : gExperimentStep;
}

/// YES while a step is still being tried.
///
/// The run level ladder and this one both step on "the previous launch died",
/// and running both at once would change two things per launch: the level would
/// drop to 2 and the container answer would change in the same relaunch, so a
/// surviving launch would not name either. While a step is being tried, this
/// ladder owns the level; once it settles, the run level ladder has it back.
BOOL GNExperimentControlsRunLevel(void) {
    return (gExperimentStep >= 0 && [gExperimentState isEqualToString:@"trying"]);
}

NSString *GNExperimentStatus(void) {
    if (gExperimentStep < 0) return @"experiment ladder off";

    NSArray<NSDictionary *> *steps = GNExperimentSteps();
    NSString *name = (gExperimentStep < (int)steps.count)
        ? steps[gExperimentStep][@"name"] : @"?";
    return [NSString stringWithFormat:@"step %d/%lu - %@ (%@)",
            gExperimentStep, (unsigned long)steps.count, name,
            gExperimentState ?: @"trying"];
}

/// Called once the app is actually up. The current step is the one that
/// survived, so it is kept and the ladder stops moving.
void GNExperimentNoteSurvived(void) {
    if (gExperimentStep < 0) return;
    if (![gExperimentState isEqualToString:@"trying"]) return;
    if (!GNCFG(@"ExperimentLadder", NO)) return;

    gExperimentState = @"won";
    GNExperimentWrite(gExperimentStep, GNCGI(@"ConfigVersion", 0), @"won");
    GNLogC("experiment: %s survived launch - keeping it, ladder stopped",
           GNExperimentStatus().UTF8String ?: "?");
}

/// Recursive merge, so a step can change one key of ResignFix without having to
/// restate the other twenty.
static NSDictionary *GNDeepMerge(NSDictionary *base, NSDictionary *override) {
    if (![override isKindOfClass:[NSDictionary class]] || !override.count) return base;
    NSMutableDictionary *merged = [(base ?: @{}) mutableCopy];
    for (id key in override) {
        id value = override[key];
        id existing = merged[key];
        if ([value isKindOfClass:[NSDictionary class]] &&
            [existing isKindOfClass:[NSDictionary class]]) {
            merged[key] = GNDeepMerge(existing, value);
        } else {
            merged[key] = value;
        }
    }
    return merged;
}

#pragma mark - Config

static NSDictionary *gConfig = nil;

static NSDictionary *GNBakedDictionary(void) {
#ifdef GN_HAVE_BAKED
    NSData *data = [NSData dataWithBytes:GNBakedConfigData length:GNBakedConfigSize];
    if (data.length) {
        id plist = [NSPropertyListSerialization propertyListWithData:data
                                                             options:0
                                                              format:NULL
                                                               error:NULL];
        if ([plist isKindOfClass:[NSDictionary class]]) return plist;
    }
#endif
    return nil;
}

static NSDictionary *GNLoadPlistAtPath(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) return nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data
                                                         options:0
                                                          format:NULL
                                                           error:NULL];
    return [plist isKindOfClass:[NSDictionary class]] ? plist : nil;
}

static NSDictionary *GNDefaults(void) {
    return @{
        @"Enabled"        : @YES,
        @"Verbose"        : @YES,
        @"DryRun"         : @NO,
        @"Delay"          : @1.0,
        @"Recon"          : @NO,
        @"ProbeClasses"   : @[],
        @"BytePatches"    : @[],
        @"Anchors"        : @[],
        @"Swizzles"       : @[],
        @"BoolKeysTrue"   : @[],
        @"BoolKeysFalse"  : @[],
        @"DefaultsSet"    : @{},
        @"LogImages"      : @NO,
        // Capability switches. Both default to "off" so a v3 build never writes
        // a code page; the kernel's CS_DEBUGGED flag is the second, unbypassable
        // gate. See GNCapability.m.
        @"AllowCodePatching"  : @NO,
        @"EnableGOTRebinding" : @NO,
        @"Hooks"              : @{},
    };
}

NSDictionary *GNConfig(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSMutableDictionary *merged = [GNDefaults() mutableCopy];

        NSDictionary *baked = GNBakedDictionary();
        if (!baked) {
            GNLogC("config: no baked plist at build time (fine, using runtime files)");
        } else {
            [merged addEntriesFromDictionary:baked];
            GNLogC("config: baked plist loaded (%lu top-level keys)",
                   (unsigned long)baked.count);
        }

        NSString *bundlePath = nil;
        @try {
            bundlePath = [[NSBundle mainBundle] pathForResource:@"GNUnlock" ofType:@"plist"];
        } @catch (NSException *exception) {
            (void)exception;
            bundlePath = nil;
        }
        NSDictionary *inBundle = bundlePath ? GNLoadPlistAtPath(bundlePath) : nil;
        if (inBundle) {
            [merged addEntriesFromDictionary:inBundle];
            GNLogC("config: bundle override loaded (%s)", bundlePath.UTF8String ?: "");
        }

        NSString *docsPath = [GNDocumentsPath() stringByAppendingPathComponent:@"GNUnlock.plist"];
        NSDictionary *inDocs = GNLoadPlistAtPath(docsPath);
        if (inDocs) {
            [merged addEntriesFromDictionary:inDocs];
            GNLogC("config: Documents override loaded");
        }

        // The experiment ladder is applied last, so it wins over every file -
        // that is the whole point: it is the one thing that changes between
        // launches while the plist on disk stays untouched.
        BOOL ladder = [merged[@"ExperimentLadder"] respondsToSelector:@selector(boolValue)]
                    ? [merged[@"ExperimentLadder"] boolValue] : NO;
        BOOL autoAdvance = [merged[@"AutoBisect"] respondsToSelector:@selector(boolValue)]
                         ? [merged[@"AutoBisect"] boolValue] : YES;
        NSInteger version = [merged[@"ConfigVersion"] respondsToSelector:@selector(integerValue)]
                          ? [merged[@"ConfigVersion"] integerValue] : 0;

        int step = GNExperimentResolve(ladder, autoAdvance, version);
        NSDictionary *overrides = GNExperimentOverridesForStep(step);
        if (overrides.count) {
            merged = [GNDeepMerge(merged, overrides) mutableCopy];
            GNLogC("config: experiment %s", GNExperimentStatus().UTF8String ?: "?");
        } else if (ladder) {
            GNLogC("config: experiment %s", GNExperimentStatus().UTF8String ?: "?");
        }

        gConfig = [merged copy];
    });
    return gConfig;
}

BOOL GNCFG(NSString *key, BOOL def) {
    id v = GNConfig()[key];
    return [v respondsToSelector:@selector(boolValue)] ? [v boolValue] : def;
}

NSInteger GNCGI(NSString *key, NSInteger def) {
    id v = GNConfig()[key];
    return [v respondsToSelector:@selector(integerValue)] ? [v integerValue] : def;
}

double GNCFGD(NSString *key, double def) {
    id v = GNConfig()[key];
    return [v respondsToSelector:@selector(doubleValue)] ? [v doubleValue] : def;
}

NSString *GNCGS(NSString *key) {
    id v = GNConfig()[key];
    return [v isKindOfClass:[NSString class]] ? v : nil;
}

NSDictionary *GNCFGDict(NSString *key) {
    id v = GNConfig()[key];
    return [v isKindOfClass:[NSDictionary class]] ? v : nil;
}

NSArray *GNCFGArray(NSString *key) {
    id v = GNConfig()[key];
    return [v isKindOfClass:[NSArray class]] ? v : nil;
}

#pragma mark - Mach-O helpers

int GNImageIndexForName(const char *image) {
    uint32_t count = _dyld_image_count();
    if (!image || !*image) return 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        const char *base = strrchr(path, '/');
        base = base ? base + 1 : path;
        if (strcmp(base, image) == 0) return (int)i;
    }
    return -1;
}

const char *GNMainImageName(void) {
    static char name[256];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        const char *path = _dyld_get_image_name(0);
        const char *base = path ? strrchr(path, '/') : NULL;
        base = base ? base + 1 : path;
        if (base) {
            strncpy(name, base, sizeof(name) - 1);
        } else {
            strncpy(name, "main", sizeof(name) - 1);
        }
    });
    return name;
}

BOOL GNImageIsLoaded(const char *image) {
    return GNImageIndexForName(image) >= 0;
}

BOOL GNIsSystemImagePath(const char *path) {
    if (!path || !*path) return YES;

    static const char *prefixes[] = {
        "/System/", "/usr/", "/Developer/", "/Library/", "/AppleInternal/", "/bin/", "/sbin/",
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t len = strlen(prefixes[i]);
        if (strncmp(path, prefixes[i], len) == 0) return YES;
    }
    // CryptoKit / SwiftUI style system frameworks also live under /System, but
    // a third party bundle can never legally contain this component.
    if (strstr(path, "/System/Library/")) return YES;
    return NO;
}

BOOL GNIsAppOwnedImage(uint32_t imageIndex) {
    static char bundleDir[1024] = { 0 };
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        const char *mainPath = _dyld_get_image_name(0);
        if (!mainPath) return;
        strncpy(bundleDir, mainPath, sizeof(bundleDir) - 1);
        char *slash = strrchr(bundleDir, '/');
        if (slash) *slash = '\0';
    });

    if (!bundleDir[0]) return NO;

    const char *path = _dyld_get_image_name(imageIndex);
    if (!path || !*path) return NO;
    if (GNIsSystemImagePath(path)) return NO;

    size_t length = strlen(bundleDir);
    if (strncmp(path, bundleDir, length) != 0) return NO;
    return (path[length] == '/' || path[length] == '\0');
}

uintptr_t GNImageBase(const char *image) {
    int idx = GNImageIndexForName(image);
    if (idx < 0) return 0;
    return (uintptr_t)_dyld_get_image_header((uint32_t)idx);
}

intptr_t GNImageSlide(const char *image) {
    int idx = GNImageIndexForName(image);
    if (idx < 0) return 0;
    return _dyld_get_image_vmaddr_slide((uint32_t)idx);
}

static const struct segment_command_64 *GNSegmentFor(const struct mach_header_64 *hdr,
                                                     const char *segname) {
    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == 0) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strncmp(seg->segname, segname, 16) == 0) return seg;
        }
        cursor += lc->cmdsize;
    }
    return NULL;
}

BOOL GNSection(const char *image, const char *seg, const char *sect,
               uintptr_t *addr, uint64_t *size) {
    int idx = GNImageIndexForName(image);
    if (idx < 0) return NO;

    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header((uint32_t)idx);
    if (!hdr) return NO;

    intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)idx);
    const uint8_t *cursor = (const uint8_t *)(hdr + 1);

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == 0) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)lc;
            if (strncmp(segment->segname, seg, 16) == 0) {
                const struct section_64 *sections =
                    (const struct section_64 *)(segment + 1);
                for (uint32_t s = 0; s < segment->nsects; s++) {
                    if (strncmp(sections[s].sectname, sect, 16) == 0) {
                        if (addr) *addr = (uintptr_t)(slide + sections[s].addr);
                        if (size) *size = sections[s].size;
                        return YES;
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return NO;
}

BOOL GNContainsAddress(const char *image, uintptr_t addr, uint64_t len) {
    int idx = GNImageIndexForName(image);
    if (idx < 0) return NO;

    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header((uint32_t)idx);
    if (!hdr) return NO;

    intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)idx);
    const uint8_t *cursor = (const uint8_t *)(hdr + 1);

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == 0) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            uintptr_t start = (uintptr_t)(slide + seg->vmaddr);
            uintptr_t end = start + seg->vmsize;
            if (addr >= start && (addr + len) <= end) return YES;
        }
        cursor += lc->cmdsize;
    }
    return NO;
}

static BOOL GNSegmentForAddress(uintptr_t addr, const struct segment_command_64 **outSeg,
                                uintptr_t *outBase) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header_64 *hdr =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const uint8_t *cursor = (const uint8_t *)(hdr + 1);
        for (uint32_t c = 0; c < hdr->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)cursor;
            if (lc->cmd == 0) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                uintptr_t start = (uintptr_t)(slide + seg->vmaddr);
                if (addr >= start && addr < start + seg->vmsize) {
                    if (outSeg) *outSeg = seg;
                    if (outBase) *outBase = start;
                    return YES;
                }
            }
            cursor += lc->cmdsize;
        }
    }
    return NO;
}

BOOL GNIsExecutableAddress(uintptr_t addr) {
    const struct segment_command_64 *seg = NULL;
    if (!GNSegmentForAddress(addr, &seg, NULL) || !seg) return NO;
    return (seg->initprot & VM_PROT_EXECUTE) != 0;
}

#pragma mark - Memory writes

/// The protection a page has *right now*, which is not always the segment's
/// initprot: dyld rewrites __DATA_CONST to read-only after applying fixups.
///
/// `vm_region_64` is the iOS-safe way to ask, and it is resolved through dlsym
/// rather than linked. Two reasons, both of them lessons:
///   * `mach_vm_region` is the obvious call and it is not usable here - iOS
///     ships <mach/mach_vm.h> as a header whose entire body is
///     "#error mach_vm.h unsupported." and the mach_vm_* family is not
///     available to user space on the phone. That single include is what
///     stopped v5 and v6 from compiling.
///   * resolving at run time means a missing symbol costs us the query, not the
///     load: we fall back to the segment's initprot, which is what this
///     function already did for regions it could not describe.
typedef kern_return_t (*GNVMRegion64Fn)(vm_map_t, vm_address_t *, vm_size_t *,
                                        vm_region_flavor_t, vm_region_info_t,
                                        mach_msg_type_number_t *, mach_port_t *);

static GNVMRegion64Fn GNRegionFunction(void) {
    static GNVMRegion64Fn function = NULL;
    static BOOL resolved = NO;
    if (!resolved) {
        resolved = YES;
        function = (GNVMRegion64Fn)dlsym(RTLD_DEFAULT, "vm_region_64");
        if (!function) {
            GNLogC("memory: vm_region_64 not resolvable - using segment initprot");
        }
    }
    return function;
}

static vm_prot_t GNCurrentProtection(uintptr_t addr) {
    vm_address_t regionAddress = (vm_address_t)(addr & ~((uintptr_t)vm_page_size - 1));
    vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t objectName = MACH_PORT_NULL;

    GNVMRegion64Fn region = GNRegionFunction();
    if (region) {
        kern_return_t kr = region(mach_task_self(), &regionAddress, &regionSize,
                                  VM_REGION_BASIC_INFO_64,
                                  (vm_region_info_t)&info, &count, &objectName);
        if (kr == KERN_SUCCESS) {
            if (objectName != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), objectName);
            }
            return info.protection;
        }
    }

    const struct segment_command_64 *seg = NULL;
    if (!GNSegmentForAddress(addr, &seg, NULL) || !seg) {
        return VM_PROT_READ | VM_PROT_WRITE;
    }
    return seg->initprot;
}

size_t GNReadableRunLength(uintptr_t addr, size_t maxLen) {
    if (addr == 0 || maxLen == 0) return 0;

    // Without a region query there is no way to answer this question honestly,
    // so the answer is "nothing is readable" and every caller skips its work.
    GNVMRegion64Fn region = GNRegionFunction();
    if (!region) return 0;

    size_t total = 0;
    uintptr_t cursor = addr;

    while (total < maxLen) {
        vm_address_t regionAddress = (vm_address_t)cursor;
        vm_size_t regionSize = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objectName = MACH_PORT_NULL;

        kern_return_t kr = region(mach_task_self(), &regionAddress, &regionSize,
                                  VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
                                  &count, &objectName);
        if (objectName != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), objectName);
        }
        if (kr != KERN_SUCCESS || regionSize == 0) break;

        uintptr_t start = (uintptr_t)regionAddress;
        uintptr_t end = start + (uintptr_t)regionSize;
        if (end <= start) break;
        if (start > cursor) break;      // unmapped hole: the run stops here
        if (end <= cursor) break;       // no forward progress

        if ((info.protection & VM_PROT_READ) == 0) break;

        size_t available = (size_t)(end - cursor);
        size_t want = maxLen - total;
        size_t take = available < want ? available : want;
        total += take;
        cursor += take;
    }

    return total;
}

BOOL GNRangeIsReadable(uintptr_t addr, size_t len) {
    if (len == 0) return YES;
    if (addr == 0) return NO;
    if (addr + len < addr) return NO;       // overflow
    return GNReadableRunLength(addr, len) == len;
}

static BOOL GNMakeWritable(uintptr_t addr, size_t len, BOOL allowCopy) {
    vm_size_t pageSize = vm_page_size;
    uintptr_t start = addr & ~((uintptr_t)pageSize - 1);
    uintptr_t end = (addr + len + pageSize - 1) & ~((uintptr_t)pageSize - 1);
    vm_size_t span = (vm_size_t)(end - start);

    vm_prot_t wanted = VM_PROT_READ | VM_PROT_WRITE;
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)start, span,
                                  false, wanted);
    if (kr == KERN_SUCCESS) return YES;

    // A read-only data page (__DATA_CONST, __TEXT,__const) rejects RW until it
    // is allowed to fork into a private copy. That is harmless for data - the
    // page was never executable, so no signature is involved.
    if (allowCopy) {
        kr = vm_protect(mach_task_self(), (vm_address_t)start, span,
                        false, wanted | VM_PROT_COPY);
        if (kr == KERN_SUCCESS) return YES;
    }

    GNLogC("vm_protect(RW) failed at %p (kr=%d)", (void *)start, (int)kr);
    return NO;
}

static void GNRestoreProtection(uintptr_t addr, size_t len, vm_prot_t original,
                                BOOL executable) {
    vm_size_t pageSize = vm_page_size;
    uintptr_t start = addr & ~((uintptr_t)pageSize - 1);
    uintptr_t end = (addr + len + pageSize - 1) & ~((uintptr_t)pageSize - 1);
    vm_size_t span = (vm_size_t)(end - start);

    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)start, span,
                                  false, original);
    if (kr != KERN_SUCCESS) {
        GNLogC("vm_protect(restore %d) failed at %p (kr=%d)", (int)original,
               (void *)start, (int)kr);
    }
    if (executable) {
        sys_icache_invalidate((void *)start, span);
    }
}

BOOL GNWriteBytes(uintptr_t addr, const void *bytes, size_t len) {
    if (!addr || !bytes || !len || len > (16u << 20)) return NO;

    BOOL executable = GNIsExecutableAddress(addr);
    if (executable && !GNCodePatchingAllowed()) {
        GNLogC("write refused at %p: executable page and this process is %s signed",
               (void *)addr, GNSignatureMode());
        GNLogC("  a patched code page loses its signature; amfi kills the task on "
               "the next instruction fetch (CODESIGNING / Invalid Page)");
        return NO;
    }

    vm_prot_t original = GNCurrentProtection(addr);
    // VM_PROT_COPY is what turns a code page into an anonymous copy. It is only
    // ever safe for read-only *data*, so it is not offered to code pages.
    BOOL allowCopy = !executable;

    if (!GNMakeWritable(addr, len, allowCopy)) return NO;
    memcpy((void *)addr, bytes, len);
    GNRestoreProtection(addr, len, original, executable);
    return YES;
}

BOOL GNPatchCodeBytes(uintptr_t addr, const void *bytes, size_t len) {
    if (!GNIsExecutableAddress(addr)) {
        GNLogC("refusing code patch at %p: page is not executable", (void *)addr);
        return NO;
    }
    if (!GNCodePatchingAllowed()) {
        GNLogC("code patch refused at %p: %s signature, no get-task-allow",
               (void *)addr, GNSignatureMode());
        return NO;
    }
    if (!GNWriteBytes(addr, bytes, len)) return NO;
    sys_icache_invalidate((void *)(addr & ~((uintptr_t)vm_page_size - 1)),
                          len + vm_page_size);
    return YES;
}

#pragma mark - Parsing helpers

BOOL GNParseAddress(NSString *string, uint64_t *out) {
    if (![string isKindOfClass:[NSString class]]) return NO;
    NSString *clean = [string stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    clean = [clean stringByReplacingOccurrencesOfString:@"_" withString:@""];
    if (clean.length == 0) return NO;
    if ([clean hasPrefix:@"0x"] || [clean hasPrefix:@"0X"]) {
        clean = [clean substringFromIndex:2];
    }
    unsigned long long value = 0;
    NSScanner *scanner = [NSScanner scannerWithString:clean];
    if (![scanner scanHexLongLong:&value]) return NO;
    if (!scanner.isAtEnd) return NO;
    if (out) *out = (uint64_t)value;
    return YES;
}

BOOL GNDataFromHex(NSString *hex, void **out, size_t *len) {
    if (![hex isKindOfClass:[NSString class]]) return NO;

    NSMutableString *clean = [NSMutableString string];
    for (NSUInteger i = 0; i < hex.length; i++) {
        unichar c = [hex characterAtIndex:i];
        BOOL isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (isHex) [clean appendFormat:@"%C", (unichar)c];
    }

    if (clean.length == 0 || (clean.length % 2) != 0) {
        GNLogC("hex parse failed: '%s' -> %lu nibbles",
               hex.UTF8String ?: "", (unsigned long)clean.length);
        return NO;
    }

    size_t count = clean.length / 2;
    uint8_t *buffer = malloc(count);
    if (!buffer) return NO;

    for (size_t i = 0; i < count; i++) {
        unichar hi = [clean characterAtIndex:i * 2];
        unichar lo = [clean characterAtIndex:i * 2 + 1];
        int h = (hi <= '9') ? (hi - '0') : ((hi | 0x20) - 'a' + 10);
        int l = (lo <= '9') ? (lo - '0') : ((lo | 0x20) - 'a' + 10);
        buffer[i] = (uint8_t)((h << 4) | l);
    }

    if (out) *out = buffer;
    if (len) *len = count;
    return YES;
}

#pragma mark - Inline hook engine (arm64)

#define GN_HOOK_STUB_WORDS 4
#define GN_HOOK_STUB_SIZE  (GN_HOOK_STUB_WORDS * 4)

static size_t GNPageSpan(size_t size) {
    vm_size_t pageSize = vm_page_size;
    return ((size + pageSize - 1) / pageSize) * pageSize;
}

static void *GNAllocTrampoline(size_t size) {
    size_t span = GNPageSpan(size);
    void *page = mmap(NULL, span, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED) {
        GNLogC("trampoline mmap failed (%zu bytes)", span);
        return NULL;
    }
    return page;
}

/// Instructions that cannot be copied verbatim into a trampoline.
static BOOL GNInstructionNeedsRelocation(uint32_t insn) {
    if ((insn & 0x9F000000) == 0x90000000) return YES; // ADRP
    if ((insn & 0x9F000000) == 0x10000000) return YES; // ADR
    if ((insn & 0x7C000000) == 0x14000000) return YES; // B
    if ((insn & 0xFF000010) == 0x54000000) return YES; // B.cond
    if ((insn & 0x7E000000) == 0x34000000) return YES; // CBZ / CBNZ
    if ((insn & 0x7E000000) == 0x36000000) return YES; // TBZ / TBNZ
    if ((insn & 0x3B000000) == 0x18000000) return YES; // LDR (literal)
    return NO;
}

typedef struct {
    uint32_t ldr_x16;          // ldr x16, #8
    uint32_t br_x16;           // br  x16
    uint32_t lo;
    uint32_t hi;
} GNAbsoluteJump;

static GNAbsoluteJump GNMakeJump(uint64_t destination) {
    GNAbsoluteJump jump;
    jump.ldr_x16 = 0x58000050u;
    jump.br_x16  = 0xD61F0200u;
    jump.lo      = (uint32_t)(destination & 0xFFFFFFFFu);
    jump.hi      = (uint32_t)((destination >> 32) & 0xFFFFFFFFu);
    return jump;
}

BOOL GNInlineHookSymbol(const char *symbol, void *replacement, void **original) {
    if (!symbol || !replacement) return NO;

    // Bail before allocating a trampoline: on a Distribution signature neither
    // the trampoline page nor the patched prologue is executable, and the
    // attempt itself is what gets the process killed.
    if (!GNCodePatchingAllowed()) {
        GNLogC("inline hook '%s': refused (%s signature, no get-task-allow)",
               symbol, GNSignatureMode());
        return NO;
    }

    void *target = dlsym(RTLD_DEFAULT, symbol);
    if (!target) {
        GNLogC("hook: symbol '%s' not found", symbol);
        return NO;
    }

    const uint32_t *insns = (const uint32_t *)target;
    for (int i = 0; i < GN_HOOK_STUB_WORDS; i++) {
        if (GNInstructionNeedsRelocation(insns[i])) {
            GNLogC("hook: '%s' prologue at %p has a PC-relative instruction (idx %d, 0x%08x) - skipped",
                   symbol, target, i, insns[i]);
            return NO;
        }
    }

    uint8_t *trampoline = NULL;
    if (original) {
        trampoline = (uint8_t *)GNAllocTrampoline(GN_HOOK_STUB_SIZE * 2);
        if (!trampoline) return NO;

        memcpy(trampoline, target, GN_HOOK_STUB_SIZE);
        GNAbsoluteJump back = GNMakeJump((uint64_t)(uintptr_t)target + GN_HOOK_STUB_SIZE);
        memcpy(trampoline + GN_HOOK_STUB_SIZE, &back, sizeof(back));

        // mmap'd page is RW; make it executable once the code is in place.
        if (mprotect(trampoline, GNPageSpan(GN_HOOK_STUB_SIZE * 2),
                     PROT_READ | PROT_EXEC) != 0) {
            GNLogC("hook: mprotect(RX) failed for trampoline of '%s'", symbol);
            munmap(trampoline, GNPageSpan(GN_HOOK_STUB_SIZE * 2));
            return NO;
        }
        sys_icache_invalidate(trampoline, GN_HOOK_STUB_SIZE * 2);
    }

    GNAbsoluteJump jump = GNMakeJump((uint64_t)(uintptr_t)replacement);
    if (!GNWriteBytes((uintptr_t)target, &jump, sizeof(jump))) {
        GNLogC("hook: write failed for '%s' at %p", symbol, target);
        return NO;
    }

    if (original) *original = trampoline;
    GNLogC("hook: '%s' at %p -> %p (trampoline %p)", symbol, target, replacement, trampoline);
    return YES;
}

#pragma mark - ObjC swizzling

BOOL GNHookInstance(Class cls, const char *selector, IMP replacement, IMP *original) {
    if (!cls || !selector || !replacement) return NO;
    SEL sel = sel_registerName(selector);
    Method method = class_getInstanceMethod(cls, sel);
    if (!method) {
        GNLogC("swizzle: -[%s %s] not found", class_getName(cls), selector);
        return NO;
    }
    IMP previous = method_getImplementation(method);
    const char *types = method_getTypeEncoding(method);
    if (original) *original = previous;
    class_replaceMethod(cls, sel, replacement, types);
    GNLogC("swizzle: -[%s %s] %p -> %p", class_getName(cls), selector,
           (void *)previous, (void *)replacement);
    return YES;
}

BOOL GNHookClass(Class cls, const char *selector, IMP replacement, IMP *original) {
    if (!cls || !selector || !replacement) return NO;
    SEL sel = sel_registerName(selector);
    Class meta = object_getClass(cls);
    Method method = class_getInstanceMethod(meta, sel);
    if (!method) {
        GNLogC("swizzle: +[%s %s] not found", class_getName(cls), selector);
        return NO;
    }
    IMP previous = method_getImplementation(method);
    const char *types = method_getTypeEncoding(method);
    if (original) *original = previous;
    class_replaceMethod(meta, sel, replacement, types);
    GNLogC("swizzle: +[%s %s] %p -> %p", class_getName(cls), selector,
           (void *)previous, (void *)replacement);
    return YES;
}

BOOL GNHookIfExists(const char *className, const char *selector,
                    IMP replacement, IMP *original, BOOL classMethod) {
    Class cls = objc_getClass(className);
    if (!cls) {
        GNLogC("swizzle: class '%s' not loaded - skipped", className);
        return NO;
    }
    return classMethod ? GNHookClass(cls, selector, replacement, original)
                       : GNHookInstance(cls, selector, replacement, original);
}
