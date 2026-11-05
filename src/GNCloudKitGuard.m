//
//  GNCloudKitGuard.m
//  Survivability for the malformed-entitlement CKException.
//
//  ======================= the crash, in one paragraph =======================
//
//  A re-signed app has entitlements the signer synthesised, and for iCloud it
//  wrote
//
//      com.apple.developer.icloud-services = "*"          <- a string
//
//  where CloudKit wants an array of strings. CloudKit validates its own
//  entitlements in process on first use, raises
//
//      CKException: Application has malformed entitlements. Found value "*"
//      for entitlement com.apple.developer.icloud-services, expected an array
//      of strings
//
//  and because that happens inside a dispatch_once during app initialisation,
//  nothing catches it and the launch dies. v13's probe named it; this module
//  makes the launch survive it.
//
//  ============================ why not init family ============================
//
//  The obvious target - -[NSException initWithName:reason:userInfo:], which this
//  dylib already swizzles for forensics - cannot work, and it is worth writing
//  down because it is the first idea everyone has:
//
//    * init only *constructs*. It does not throw. A hook there runs before the
//      throw exists; returning nil from it hands a nil object to the raise path,
//      which turns one exception into a null dereference, and it also destroys
//      every exception object in the process, forensics included.
//    * so the interception point is -[NSException raise], the last method on the
//      path before objc_exception_throw. Every +[NSException raise:format:] call
//      funnels through it.
//
//  ==================== why swallow, not unwind to a boundary ====================
//
//  Catching higher up (around +[CKContainer ...]) means unwinding an ObjC
//  exception through GoodNotes' Swift frames. Swift frames have no ObjC landing
//  pad, so that unwind is undefined behaviour and usually terminates the process
//  anyway - and the boundary has to invent a return value for a non-optional
//  Swift API, which is its own crash.
//
//  Swallowing at -raise unwinds nothing. CloudKit's function continues after the
//  raise call and returns its own failure value, which is the same path it takes
//  when the network is down. That is why -raise is the primary mechanism here and
//  the boundaries below are secondary.
//
//  The cost is honest and bounded: the code after a raise was written as if unreachable,
//  and with a raise that returns it is reachable. In CloudKit that path returns a
//  nil / error value. A function that instead relied on the throw to leave a
//  critical section would keep running - which is why every swallow is logged,
//  counted, and limited to exceptions whose *name* is on an allow list.
//
//  ============================== what is installed ==============================
//
//    1. -[NSException raise]   swallow, then log name/reason/class, when the
//                              name is allow listed (default: CKException) and,
//                              if reason filters are set, the reason matches.
//                              Nothing else is touched: every other exception of
//                              every other class is raised exactly as before.
//
//    2. boundaries             optional @try/@catch around selected ObjC entry
//                              points that CloudKit clients call, for the case
//                              where the framework used @throw instead of -raise
//                              and never reaches the hook above. Config driven,
//                              built-in default is the two sites whose nil / NO
//                              answer is a documented "not available" rather
//                              than a lie.
//
//  Both are data-only: class_replaceMethod on a method list. No code page, no
//  import slot, no memory protection change. Safe on a Distribution signature,
//  which is the only signature this project ships against.
//

#import "GNCloudKitGuard.h"
#import "GNUnlock.h"
#import "GNBeacon.h"

#import <objc/runtime.h>
#import <string.h>

#pragma mark - Suppression policy

/// Exception names the guard is allowed to swallow.
///
/// A name allow list rather than a reason substring is deliberate: the reason
/// text is localised-ish, reworded between OS versions, and contains the very
/// entitlement value we are trying to tolerate. The name is stable.
static NSArray *gSuppressedNames = nil;

/// Optional additional filter on the reason. Empty means "any reason, as long as
/// the name matched" - which is what we want here, because once CloudKit has one
/// malformed entitlement it raises several different reasons on the same launch.
static NSArray *gReasonFilters = nil;

static void (*gOriginalRaise)(id, SEL) = NULL;
static BOOL gGuardInstalled = NO;
static volatile int32_t gGuardDepth = 0;
static volatile int32_t gSuppressed = 0;
static volatile int32_t gLogBudget = 8;

#pragma mark - Logging

static void GNCloudKitGuardRecord(NSException *exception) {
    int32_t count = __sync_add_and_fetch(&gSuppressed, 1);
    if (count > gLogBudget) return;

    const char *name = "(none)";
    const char *reason = "(none)";
    const char *cls = "?";

    // @try because this runs on the path of a framework that is already in
    // trouble: a malformed exception must not turn a diagnostic into a second
    // failure. Nothing below changes what the caller sees.
    @try {
        const char *nameC = class_getName(object_getClass(exception));
        if (nameC) cls = nameC;

        NSString *n = [exception name];
        if ([n isKindOfClass:[NSString class]] && n.UTF8String) name = n.UTF8String;

        NSString *r = [exception reason];
        if ([r isKindOfClass:[NSString class]] && r.UTF8String) reason = r.UTF8String;
    } @catch (__unused NSException *ignored) {
        GNBeaconLine("cloudkit-guard: reading the exception threw - logged what was known");
    }

    GNBeaconLine("cloudkit-guard: SWALLOWED #%d %s: %s (class %s)",
                 (int)count, name, reason, cls);
    GNBeaconLine("cloudkit-guard: the raise returned instead of unwinding; CloudKit continues "
                 "on its failure path and the launch goes on");
}

#pragma mark - Policy evaluation

/// YES only for an exception this guard is allowed to swallow.
///
/// The name allow list is the narrow gate: with it gone this becomes a blanket
/// exception suppressor, which would hide every defect in the app instead of
/// the one malformed entitlement. scripts/v12_lint.py enforces its presence.
static BOOL GNCloudKitGuardShouldSuppress(id object) {
    if (!object) return NO;

    // The whole decision is wrapped: this is called from a catch handler in the
    // boundary path, where an exception escaping would propagate out of the
    // handler and be the second failure of a launch that is already in trouble.
    // A decision that cannot be made is NO - the app's exception continues.
    BOOL suppress = NO;
    @try {
        if (![object isKindOfClass:[NSException class]]) return NO;

        NSException *exception = (NSException *)object;

        NSString *name = [exception name];
        if (![name isKindOfClass:[NSString class]]) return NO;

        BOOL nameMatched = [gSuppressedNames containsObject:name];
        if (!nameMatched) return NO;

        if (gReasonFilters.count > 0) {
            NSString *reason = [exception reason];
            if (![reason isKindOfClass:[NSString class]]) return NO;

            BOOL reasonMatched = NO;
            for (NSString *needle in gReasonFilters) {
                if ([reason rangeOfString:needle].location != NSNotFound) {
                    reasonMatched = YES;
                    break;
                }
            }
            if (!reasonMatched) return NO;
        }

        suppress = YES;
    } @catch (__unused NSException *ignored) {
        suppress = NO;
    }
    return suppress;
}

#pragma mark - 1. -[NSException raise]

/// The hook. Runs before objc_exception_throw, i.e. before anything unwinds.
static void GNCloudKitGuardRaise(id self, SEL _cmd) {
    BOOL suppress = NO;

    // Re-entrancy guard: recording an exception must not be able to raise into
    // the recorder. If the flag is already held, pass straight through.
    if (__sync_lock_test_and_set(&gGuardDepth, 1) == 0) {
        @try {
            suppress = GNCloudKitGuardShouldSuppress(self);
            if (suppress) GNCloudKitGuardRecord((NSException *)self);
        } @catch (__unused NSException *ignored) {
            suppress = NO;
        }
        __sync_lock_release(&gGuardDepth);
    }

    if (suppress) return;           // <- the throw never happens
    if (gOriginalRaise) gOriginalRaise(self, _cmd);
}

#pragma mark - 2. boundaries

/// Return conventions a boundary replacement has to honour at the ABI level.
/// The declared type is not consulted; the caller's registers are.
typedef enum {
    GNBoundaryReturnObject = 0,
    GNBoundaryReturnBool,
    GNBoundaryReturnVoid,
} GNBoundaryReturn;

typedef enum {
    GNBoundaryInstance = 0,
    GNBoundaryClass,
} GNBoundaryKind;

/// What a boundary does with a caught exception.
///
///   swallow   record it and return the "not available" value. This is the v14
///             behaviour and it changes what the app sees: the caller gets nil
///             or NO instead of unwinding.
///
///   observe   record it and rethrow. Identical behaviour to no boundary at
///             all, plus one log line naming the class, the selector and the
///             exception. v19 needs this because the v18 log said the guard
///             caught nothing: before deciding whether a boundary may swallow,
///             we first have to learn *which* call is the one that throws.
///
/// Observe is the default for the probe list, and deliberately so - it is the
/// only boundary mode that cannot make a launch worse.
typedef enum {
    GNBoundarySwallow = 0,
    GNBoundaryObserve,
} GNBoundaryMode;

typedef struct {
    SEL     selector;
    Class   cls;
    int     kind;
    int     returnKind;
    int     arguments;      // 0 or 1 - the two shapes this project needs
    int     mode;           // GNBoundaryMode
    IMP     original;
    char    className[64];
    char    selectorName[96];
} GNBoundarySite;

static GNBoundarySite gBoundarySites[24];
static int gBoundarySiteCount = 0;

static GNBoundarySite *GNBoundarySiteFor(SEL command) {
    for (int i = 0; i < gBoundarySiteCount; i++) {
        if (gBoundarySites[i].selector == command) return &gBoundarySites[i];
    }
    return NULL;
}

/// Observe mode: leave control flow exactly as it was and let the one log line
/// carry the information instead. Called from every boundary catch, so the six
/// wrappers differ only in what they return when a boundary really swallows.
static bool GNBoundaryObserveRethrow(GNBoundarySite *site, NSException *exception) {
    if (!site || site->mode != GNBoundaryObserve) return false;
    GNBeaconLine("boundary(observe): %c[%s %s] threw %s: %s - recorded, then rethrown "
                 "(observe mode cannot change what the app sees)",
                 site->kind == GNBoundaryClass ? '+' : '-',
                 site->className, site->selectorName,
                 (exception.name ?: @"?").UTF8String,
                 (exception.reason ?: @"?").UTF8String);
    return true;
}

static id GNBoundaryObject0(id self, SEL _cmd) {
    GNBoundarySite *site = GNBoundarySiteFor(_cmd);
    if (!site || !site->original) return nil;
    @try {
        return ((id (*)(id, SEL))site->original)(self, _cmd);
    } @catch (NSException *exception) {
        if (GNCloudKitGuardShouldSuppress(exception)) {
            GNCloudKitGuardRecord(exception);
            if (GNBoundaryObserveRethrow(site, exception)) @throw;
            return nil;
        }
        @throw;
    }
}

static id GNBoundaryObject1(id self, SEL _cmd, id argument) {
    GNBoundarySite *site = GNBoundarySiteFor(_cmd);
    if (!site || !site->original) return nil;
    @try {
        return ((id (*)(id, SEL, id))site->original)(self, _cmd, argument);
    } @catch (NSException *exception) {
        if (GNCloudKitGuardShouldSuppress(exception)) {
            GNCloudKitGuardRecord(exception);
            if (GNBoundaryObserveRethrow(site, exception)) @throw;
            return nil;
        }
        @throw;
    }
}

static BOOL GNBoundaryBool0(id self, SEL _cmd) {
    GNBoundarySite *site = GNBoundarySiteFor(_cmd);
    if (!site || !site->original) return NO;
    @try {
        return ((BOOL (*)(id, SEL))site->original)(self, _cmd);
    } @catch (NSException *exception) {
        if (GNCloudKitGuardShouldSuppress(exception)) {
            GNCloudKitGuardRecord(exception);
            if (GNBoundaryObserveRethrow(site, exception)) @throw;
            return NO;
        }
        @throw;
    }
}

static BOOL GNBoundaryBool1(id self, SEL _cmd, id argument) {
    GNBoundarySite *site = GNBoundarySiteFor(_cmd);
    if (!site || !site->original) return NO;
    @try {
        return ((BOOL (*)(id, SEL, id))site->original)(self, _cmd, argument);
    } @catch (NSException *exception) {
        if (GNCloudKitGuardShouldSuppress(exception)) {
            GNCloudKitGuardRecord(exception);
            if (GNBoundaryObserveRethrow(site, exception)) @throw;
            return NO;
        }
        @throw;
    }
}

static void GNBoundaryVoid0(id self, SEL _cmd) {
    GNBoundarySite *site = GNBoundarySiteFor(_cmd);
    if (!site || !site->original) return;
    @try {
        ((void (*)(id, SEL))site->original)(self, _cmd);
    } @catch (NSException *exception) {
        if (GNCloudKitGuardShouldSuppress(exception)) {
            GNCloudKitGuardRecord(exception);
            if (GNBoundaryObserveRethrow(site, exception)) @throw;
            return;
        }
        @throw;
    }
}

static void GNBoundaryVoid1(id self, SEL _cmd, id argument) {
    GNBoundarySite *site = GNBoundarySiteFor(_cmd);
    if (!site || !site->original) return;
    @try {
        ((void (*)(id, SEL, id))site->original)(self, _cmd, argument);
    } @catch (NSException *exception) {
        if (GNCloudKitGuardShouldSuppress(exception)) {
            GNCloudKitGuardRecord(exception);
            if (GNBoundaryObserveRethrow(site, exception)) @throw;
            return;
        }
        @throw;
    }
}

static void GNInstallOneBoundary(NSDictionary *spec);

/// The probe list (v19): CloudKit entry points, in **observe** mode.
///
/// Why this list exists
/// --------------------
/// The v18 log had a contradiction that had to be resolved before any more
/// hooking: the entitlement repair was measured LIVE, and the launch still died
/// of the same CKException, and the guard recorded no SWALLOWED line. Two of
/// those three mean the throw did not pass through -[NSException raise]; the
/// third means nobody knows which call performs it.
///
/// Observe mode answers exactly that question without changing anything: each
/// wrapper calls the real method and, if it throws, writes the class, the
/// selector and the exception down and then rethrows. The app's behaviour is
/// bit-for-bit what it was; the log gains the name of the throwing call.
///
/// Why nil is *not* returned here
/// ------------------------------
/// These selectors return non-optional values in Swift. Handing back nil from
/// containerWithIdentifier: turns a caught ObjC exception into a Swift trap -
/// a different crash with a worse log. So the probe list never swallows. Once
/// the log names the culprit, a single entry can be switched to `Mode swallow`
/// in config/GNUnlock.plist, for that one selector, on purpose.
static NSArray<NSDictionary *> *GNBoundaryProbeDefaults(void) {
    return @[
        @{ @"Class": @"CKContainer", @"Selector": @"defaultContainer",
           @"ClassMethod": @YES, @"Return": @"object", @"Arguments": @0,
           @"Mode": @"observe" },

        @{ @"Class": @"CKContainer", @"Selector": @"containerWithIdentifier:",
           @"ClassMethod": @YES, @"Return": @"object", @"Arguments": @1,
           @"Mode": @"observe" },

        @{ @"Class": @"CKContainer", @"Selector": @"privateCloudDatabase",
           @"ClassMethod": @NO, @"Return": @"object", @"Arguments": @0,
           @"Mode": @"observe" },

        @{ @"Class": @"CKContainer", @"Selector": @"publicCloudDatabase",
           @"ClassMethod": @NO, @"Return": @"object", @"Arguments": @0,
           @"Mode": @"observe" },

        @{ @"Class": @"CKContainer", @"Selector": @"sharedCloudDatabase",
           @"ClassMethod": @NO, @"Return": @"object", @"Arguments": @0,
           @"Mode": @"observe" },

        @{ @"Class": @"CKContainer", @"Selector": @"accountStatusWithCompletionHandler:",
           @"ClassMethod": @NO, @"Return": @"void", @"Arguments": @1,
           @"Mode": @"observe" },

        @{ @"Class": @"CKDatabase", @"Selector": @"fetchAllRecordZonesWithCompletionHandler:",
           @"ClassMethod": @NO, @"Return": @"void", @"Arguments": @1,
           @"Mode": @"observe" },

        @{ @"Class": @"NSUbiquitousKeyValueStore", @"Selector": @"defaultStore",
           @"ClassMethod": @YES, @"Return": @"object", @"Arguments": @0,
           @"Mode": @"observe" },

        @{ @"Class": @"NSUbiquitousKeyValueStore", @"Selector": @"synchronize",
           @"ClassMethod": @NO, @"Return": @"bool", @"Arguments": @0,
           @"Mode": @"observe" },
    ];
}

/// Installs the probe list, skipping classes that are not loaded yet. Safe to
/// call more than once: GNInstallOneBoundary refuses a pair that is already
/// guarded, which is what makes the post-launch retry possible.
void GNInstallCloudKitProbeBoundaries(void) {
    if (!GNCFG(@"CloudKitBoundariesProbe", YES)) return;

    NSInteger before = gBoundarySiteCount;
    for (NSDictionary *spec in GNBoundaryProbeDefaults()) {
        GNInstallOneBoundary(spec);
    }
    NSInteger added = gBoundarySiteCount - before;
    GNBeaconLine("cloudkit-guard: probe boundaries %d new site(s), %d total "
                 "(observe mode - they can only add log lines)",
                 (int)added, (int)gBoundarySiteCount);
}

/// The built-in boundary list.
///
/// Both entries answer "not available" with the value Apple documents for
/// exactly that case, and both callers already handle it:
///
///   -[NSFileManager URLForUbiquityContainerIdentifier:] returns nil when the
///   process has no ubiquity container. That is also what an app with no iCloud
///   entitlement gets, and it is the answer the re-signed app should have had.
///
///   -[NSUbiquitousKeyValueStore synchronize] returns NO when the store cannot
///   reach its daemon.
///
/// The CloudKit container entry points are deliberately NOT in this list. They
/// return non-optional values in Swift (CKContainer.default()), so handing back
/// nil converts a caught ObjC exception into a Swift trap. They are documented
/// in config/GNUnlock.plist for the case where the log proves the throw bypassed
/// -[NSException raise].
static NSArray<NSDictionary *> *GNBoundaryDefaults(void) {
    return @[
        @{ @"Class": @"NSFileManager",
           @"Selector": @"URLForUbiquityContainerIdentifier:",
           @"ClassMethod": @NO,
           @"Arguments": @1,
           @"Return": @"object" },

        @{ @"Class": @"NSUbiquitousKeyValueStore",
           @"Selector": @"synchronize",
           @"ClassMethod": @NO,
           @"Arguments": @0,
           @"Return": @"bool" },
    ];
}

/// Reads a plist value that is expected to be a number, without trusting it.
/// A hand-edited plist with <string>yes</string> or <null/> must be a skipped
/// boundary, not an unrecognised-selector crash in the constructor.
static BOOL GNBoolValue(id value) {
    return [value isKindOfClass:[NSNumber class]] ? [value boolValue] : NO;
}

static int GNIntegerValue(id value) {
    return [value isKindOfClass:[NSNumber class]] ? [value intValue] : 0;
}

static int GNReturnKindFromString(NSString *text) {
    if ([text isEqualToString:@"bool"]) return GNBoundaryReturnBool;
    if ([text isEqualToString:@"void"]) return GNBoundaryReturnVoid;
    return GNBoundaryReturnObject;
}

/// "observe" / "swallow", else the process-wide default, else swallow.
///
/// The default is swallow because that is what the two v14 entries have always
/// done and changing it would silently stop the guard from guarding. The probe
/// list spells "observe" out per entry instead of relying on a default, so the
/// risky mode is always something someone wrote down.
static int GNBoundaryModeFrom(id value, NSDictionary *cfg) {
    NSString *text = [value isKindOfClass:[NSString class]] ? (NSString *)value : nil;
    if (!text) {
        id global = cfg[@"BoundaryMode"];
        text = [global isKindOfClass:[NSString class]] ? (NSString *)global : nil;
    }
    if ([text isKindOfClass:[NSString class]] &&
        [text caseInsensitiveCompare:@"observe"] == NSOrderedSame) {
        return GNBoundaryObserve;
    }
    return GNBoundarySwallow;
}

static IMP GNReplacementFor(int returnKind, int arguments) {
    if (returnKind == GNBoundaryReturnBool) {
        return arguments > 0 ? (IMP)GNBoundaryBool1 : (IMP)GNBoundaryBool0;
    }
    if (returnKind == GNBoundaryReturnVoid) {
        return arguments > 0 ? (IMP)GNBoundaryVoid1 : (IMP)GNBoundaryVoid0;
    }
    return arguments > 0 ? (IMP)GNBoundaryObject1 : (IMP)GNBoundaryObject0;
}

static void GNInstallOneBoundary(NSDictionary *spec) {
    if (![spec isKindOfClass:[NSDictionary class]]) {
        GNBeaconLine("cloudkit-guard: boundary entry is not a dictionary - skipped");
        return;
    }
    if (gBoundarySiteCount >= (int)(sizeof(gBoundarySites) / sizeof(gBoundarySites[0]))) {
        GNBeaconLine("cloudkit-guard: boundary table full - entry skipped");
        return;
    }

    NSString *className = spec[@"Class"];
    NSString *selectorName = spec[@"Selector"];
    if (![className isKindOfClass:[NSString class]] ||
        ![selectorName isKindOfClass:[NSString class]]) {
        GNBeaconLine("cloudkit-guard: boundary entry without Class/Selector - skipped");
        return;
    }

    const char *classNameC = className.UTF8String;
    const char *selectorNameC = selectorName.UTF8String;
    if (!classNameC || !selectorNameC) return;

    // Installing the same pair twice would make the second `original` our own
    // wrapper, i.e. a boundary that calls itself. v19 installs the probe list
    // more than once on purpose (once from the constructor, once after launch,
    // because CloudKit is often loaded late), so this check is load-bearing.
    for (int i = 0; i < gBoundarySiteCount; i++) {
        if (strcmp(gBoundarySites[i].className, classNameC) == 0 &&
            strcmp(gBoundarySites[i].selectorName, selectorNameC) == 0 &&
            gBoundarySites[i].kind == (GNBoolValue(spec[@"ClassMethod"]) ? GNBoundaryClass
                                                                        : GNBoundaryInstance)) {
            return;
        }
    }

    GNBoundarySite *site = &gBoundarySites[gBoundarySiteCount];
    memset(site, 0, sizeof(*site));
    strncpy(site->className, classNameC, sizeof(site->className) - 1);
    strncpy(site->selectorName, selectorNameC, sizeof(site->selectorName) - 1);

    site->kind = GNBoolValue(spec[@"ClassMethod"]) ? GNBoundaryClass : GNBoundaryInstance;
    site->arguments = GNIntegerValue(spec[@"Arguments"]) > 0 ? 1 : 0;
    site->returnKind = GNReturnKindFromString([spec[@"Return"] isKindOfClass:[NSString class]]
                                              ? spec[@"Return"] : @"object");
    site->mode = GNBoundaryModeFrom(spec[@"Mode"], GNConfig());

    Class cls = objc_getClass(classNameC);
    if (!cls) {
        // CloudKit is not linked into every process that loads this dylib, and
        // a boundary for a class that is not here is not an error.
        GNBeaconLine("cloudkit-guard: class %s is not loaded - boundary skipped",
                     classNameC);
        return;
    }
    site->cls = cls;
    site->selector = sel_registerName(selectorNameC);

    IMP previous = NULL;
    IMP replacement = GNReplacementFor(site->returnKind, site->arguments);
    BOOL ok = (site->kind == GNBoundaryClass)
        ? GNHookClass(cls, selectorNameC, replacement, &previous)
        : GNHookInstance(cls, selectorNameC, replacement, &previous);

    if (!ok || !previous) {
        GNBeaconLine("cloudkit-guard: boundary %c[%s %s] not installed",
                     site->kind == GNBoundaryClass ? '+' : '-',
                     classNameC, selectorNameC);
        return;
    }

    site->original = previous;
    gBoundarySiteCount++;
    GNBeaconLine("cloudkit-guard: boundary %c[%s %s] guarded (returns %s, %d arg, %s)",
                 site->kind == GNBoundaryClass ? '+' : '-',
                 classNameC, selectorNameC,
                 site->returnKind == GNBoundaryReturnBool ? "BOOL"
                 : (site->returnKind == GNBoundaryReturnVoid ? "void" : "object"),
                 site->arguments,
                 site->mode == GNBoundaryObserve ? "observe: records and rethrows"
                                                 : "swallow: returns not-available");
}

#pragma mark - Install

static NSArray *GNStringArrayFrom(NSString *key, NSDictionary *cfg) {
    id value = cfg[key];
    if (![value isKindOfClass:[NSArray class]]) return nil;

    NSMutableArray *strings = [NSMutableArray array];
    for (id entry in (NSArray *)value) {
        if ([entry isKindOfClass:[NSString class]]) [strings addObject:entry];
    }
    return strings;
}

int GNCloudKitGuardSuppressedCount(void) {
    return (int)gSuppressed;
}

void GNInstallCloudKitGuard(NSDictionary *cfg) {
    if (gGuardInstalled) {
        GNBeaconLine("cloudkit-guard: already installed");
        return;
    }
    if (![cfg isKindOfClass:[NSDictionary class]]) {
        GNBeaconLine("cloudkit-guard: no config - nothing installed");
        return;
    }

    NSArray *names = GNStringArrayFrom(@"CloudKitExceptionNames", cfg);
    if (!names) names = @[ @"CKException", @"NSCloudKitException" ];
    if (names.count == 0) {
        // An empty allow list would turn this into "swallow nothing", which is
        // safe but useless. Say so instead of pretending the guard is armed.
        GNBeaconLine("cloudkit-guard: CloudKitExceptionNames is empty - nothing will be "
                     "swallowed, the entitlement crash is unmitigated");
        return;
    }
    gSuppressedNames = names;

    NSArray *reasons = GNStringArrayFrom(@"CloudKitExceptionReasonContains", cfg);
    gReasonFilters = reasons ?: @[];

    NSInteger budget = GNCGI(@"CloudKitLogBudget", 8);
    gLogBudget = (int32_t)(budget > 0 ? budget : 8);

    Class nsException = objc_getClass("NSException");
    if (!nsException) {
        GNBeaconLine("cloudkit-guard: NSException class not found - no suppressor this launch");
        return;
    }

    IMP previous = NULL;
    if (GNHookInstance(nsException, "raise", (IMP)GNCloudKitGuardRaise, &previous) && previous) {
        gOriginalRaise = (void (*)(id, SEL))previous;
    } else {
        GNBeaconLine("cloudkit-guard: -[NSException raise] not swizzled - the entitlement "
                     "exception will kill the launch as before");
        return;
    }

    gGuardInstalled = YES;
    GNBeaconLine("cloudkit-guard: armed - swallowing %lu name(s) [%s], reason filter %s",
                 (unsigned long)gSuppressedNames.count,
                 ((NSString *)gSuppressedNames[0]).UTF8String ?: "?",
                 gReasonFilters.count ? "on" : "off (any reason for those names)");
    GNBeaconLine("cloudkit-guard: this does not fix the entitlement - it only stops the "
                 "exception. The signer still has to write a well formed value; see the "
                 "probe VERDICT lines above");

    if (!GNCFG(@"CloudKitBoundariesEnabled", YES)) {
        GNBeaconLine("cloudkit-guard: boundaries disabled by config - only -raise is guarded");
        return;
    }

    id configured = cfg[@"CloudKitBoundaries"];
    NSArray *boundaries = [configured isKindOfClass:[NSArray class]]
        ? (NSArray *)configured : GNBoundaryDefaults();

    for (NSDictionary *spec in boundaries) {
        GNInstallOneBoundary(spec);
    }
    GNInstallCloudKitProbeBoundaries();

    GNBeaconLine("cloudkit-guard: %d boundary site(s) guarded", gBoundarySiteCount);
}
