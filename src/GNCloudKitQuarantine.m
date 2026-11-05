//
//  GNCloudKitQuarantine.m
//  Neutralise, by shape, every CloudKit method that can submit work. (v21)
//
//  Read GNCloudKitQuarantine.h first: it states the property this selects on and
//  why a hand written list of selectors was the thing that kept failing.
//
//  ===================== the one thing that makes this survivable =====================
//
//  A neutralised method does not return a value. It is not a stub that answers
//  "no account"; it is a method whose body is empty. That is only acceptable
//  because of what was *not* selected: a method that returns an object is left
//  exactly as it was, because returning nil where Swift expects a non-optional
//  CKDatabase is a trap - a worse crash with a worse log, and precisely the trade
//  v20 refused to make when it built a real subclass instead of a proxy.
//
//  Void methods, by contrast, cannot hand anything back. Their only observable
//  effect is a completion handler that will not be called. That is a stall, not a
//  contradiction, and a stall in a sync subsystem on a device with no iCloud
//  account is a state every one of these apps already ships a UI for.
//
//  ===================== order matters, and the launcher enforces it =====================
//
//  This runs *before* GNCloudKitStub. The stub's fourteen entry points are
//  deliberately better than an empty body - they answer with a substitute object
//  or deliver CKErrorNotAuthenticated to the handler - so they must be the last
//  word on those selectors. Quarantine first, stub second, and the specific
//  beat the general exactly where somebody decided it should.
//

#import "GNCloudKitQuarantine.h"
#import "GNUnlock.h"
#import "GNBeacon.h"

#include <objc/runtime.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#pragma mark - State

static volatile int32_t gQuarantineReplaced = 0;
static volatile int32_t gQuarantineClasses  = 0;
static int32_t          gQuarantineNames    = 12;
static BOOL             gQuarantineArmed    = NO;   // "neutralise" vs "assert"

/// Classes already processed. CloudKit is loaded lazily and the launcher retries,
/// so this keeps a second pass from re-replacing (harmless) and, more usefully,
/// from re-printing the same twelve names.
static Class gSeenClasses[512];
static int   gSeenCount = 0;

static const char *const kDefaultPrefixes[] = {
    "addOperation",     // -[CKDatabase addOperation:]
    "save",             // saveRecord:, saveSubscription:, saveRecordZone:
    "delete",           // deleteRecordWithID:, deleteSubscriptionWithID:
    "fetch",            // fetchRecordWithID:, fetchAllRecordZones..., fetchWithCompletionHandler:
    "modify",           // modifyRecordZones:, modifySubscriptions:
    "perform",          // performQuery:, per-operation internals
    "submit",           // internal submission entry points
    "send",             // internal transport
    "start",            // -[CKOperation start] - an NSOperation subclass that never runs
    "request",          // requestApplicationPermission:completionHandler:
    "account",          // accountStatus..., accountInfo...
    "discover",         // discoverAllIdentities
    "check",            // checkbox/entitlement checks inside the daemon client
    "validate",         // internal validation entry points
    "prepare",          // container setup
    "setup",            // container setup
    "schedule",         // retry scheduling
    "enqueue",
    "reset",            // resetAccount
};

#pragma mark - Helpers

static BOOL GNQuarantineSeen(Class cls) {
    for (int i = 0; i < gSeenCount; i++) {
        if (gSeenClasses[i] == cls) return YES;
    }
    return NO;
}

static void GNQuarantineMark(Class cls) {
    if (gSeenCount < (int)(sizeof(gSeenClasses) / sizeof(gSeenClasses[0]))) {
        gSeenClasses[gSeenCount++] = cls;
    }
}

/// The image a class is defined in. This is the filter that keeps the width of
/// the rule from becoming a hazard: an app class named CKSomething is not in
/// scope, and neither is anything in Foundation.
static BOOL GNQuarantineClassIsCloudKit(Class cls) {
    const char *image = class_getImageName(cls);
    if (!image) return NO;
    return strstr(image, "CloudKit") != NULL;
}

static BOOL GNQuarantineSelectorMatches(const char *name, NSArray<NSString *> *prefixes) {
    if (!name) return NO;

    if (prefixes) {
        NSString *selector = [NSString stringWithUTF8String:name];
        if (!selector) return NO;
        for (NSString *prefix in prefixes) {
            if (![prefix isKindOfClass:[NSString class]] || prefix.length == 0) continue;
            if ([selector hasPrefix:prefix]) return YES;
        }
        return NO;
    }

    for (size_t i = 0; i < sizeof(kDefaultPrefixes) / sizeof(kDefaultPrefixes[0]); i++) {
        if (strncmp(name, kDefaultPrefixes[i], strlen(kDefaultPrefixes[i])) == 0) return YES;
    }
    return NO;
}

/// The replacement. Declares no arguments and returns nothing, on purpose: on
/// arm64 a callee that ignores its argument registers is well defined, so one
/// function serves a selector of any arity.
static void GNQuarantineNoop(id self, SEL _cmd) {
    // Deliberately empty. Nothing is logged here - a per-call line would be a
    // hot path - and nothing is returned, because a void method has nothing to
    // return.
}

/// v23: the answer for a method of a *named* class whose return type is a value
/// the caller can hold: nil where an object is expected, zero where a scalar is.
/// Returning through x0 covers objects, BOOL, integers and pointers; a struct or
/// a floating point return is deliberately not in scope below, because those come
/// back in other registers and this function would leave them undefined.
static id GNQuarantineNilReturn(id self, SEL _cmd) {
    return nil;
}

/// Return types this stub can answer honestly, by the first character of the
/// method's ABI encoding.
static BOOL GNQuarantineReturnIsRepresentable(const char *types) {
    if (!types || !types[0]) return NO;
    switch (types[0]) {
        case 'v':   // void
        case '@':   // object
        case 'B':   // BOOL
        case 'c':   // char / BOOL on older encodings
        case 'C':
        case 's':
        case 'S':
        case 'i':
        case 'I':
        case 'l':
        case 'L':
        case 'q':
        case 'Q':
        case '#':   // Class
        case ':':   // SEL
        case '*':   // C string
        case '^':   // pointer
            return YES;
        default:
            // struct ('{'), union ('('), array ('['), float / double ('f','d'),
            // long double ('D'), bitfield ('b'), and anything new Apple adds.
            return NO;
    }
}

#pragma mark - One class

static int32_t GNQuarantineClass(Class cls, NSArray<NSString *> *prefixes, BOOL neutralise) {
    if (!cls || GNQuarantineSeen(cls)) return 0;
    GNQuarantineMark(cls);
    __sync_add_and_fetch(&gQuarantineClasses, 1);

    int32_t replaced = 0;

    for (int isClassMethod = 0; isClassMethod < 2; isClassMethod++) {
        Class target = isClassMethod ? object_getClass(cls) : cls;
        if (!target) continue;

        unsigned int count = 0;
        Method *methods = class_copyMethodList(target, &count);
        if (!methods) continue;

        for (unsigned int i = 0; i < count; i++) {
            Method method = methods[i];

            // Shape check first: only a void-returning method is a candidate.
            const char *types = method_getTypeEncoding(method);
            if (!types || types[0] != 'v') continue;

            const char *name = sel_getName(method_getName(method));
            if (!GNQuarantineSelectorMatches(name, prefixes)) continue;

            replaced++;
            if (!neutralise) continue;

            // The ABI string is the existing method's, never the replacement's:
            // a caller compiled against CloudKit's header is what has to be
            // satisfied.
            class_replaceMethod(target, method_getName(method), (IMP)GNQuarantineNoop, types);

            if (replaced <= gQuarantineNames) {
                GNBeaconLine("quarantine: %c[%s %s] -> empty body (void return, work dropped)",
                             isClassMethod ? '+' : '-', class_getName(cls), name);
            }
        }
        free(methods);
    }

    __sync_add_and_fetch(&gQuarantineReplaced, replaced);
    return replaced;
}

#pragma mark - One named class (v23)

/// A class the caller named explicitly, as opposed to one matched by shape.
///
/// The v22 crash named `CKPersona`, and the sweep above cannot reach it for two
/// reasons: it is a Swift class, so `launch` is a static property getter and not
/// an Objective-C method at all, and its remaining members do not begin with any
/// of the work prefixes. So this pass ignores both filters for a named class -
/// every representable method is answered - and reports what it found, including
/// the case that matters most: a Swift class whose members are not ObjC visible
/// has *nothing* here, and the log has to say that instead of leaving "replaced
/// 0 methods" to be read as a success.
static int32_t GNQuarantineNamedClass(Class cls, BOOL neutralise) {
    if (!cls) return 0;

    int32_t replaced = 0;
    int32_t skipped = 0;
    int32_t instanceMethods = 0;
    int32_t classMethods = 0;

    for (int isClassMethod = 0; isClassMethod < 2; isClassMethod++) {
        Class target = isClassMethod ? object_getClass(cls) : cls;
        if (!target) continue;

        unsigned int count = 0;
        Method *methods = class_copyMethodList(target, &count);
        if (!methods) continue;

        for (unsigned int i = 0; i < count; i++) {
            Method method = methods[i];
            const char *types = method_getTypeEncoding(method);
            const char *name = sel_getName(method_getName(method));

            if (isClassMethod) classMethods++; else instanceMethods++;

            if (!GNQuarantineReturnIsRepresentable(types)) {
                skipped++;
                if (skipped <= 4) {
                    GNBeaconLine("quarantine: %c[%s %s] left alone - return type '%s' does not "
                                 "come back through x0, so a stub would leave it undefined",
                                 isClassMethod ? '+' : '-', class_getName(cls), name,
                                 types && types[0] ? types : "?");
                }
                continue;
            }

            replaced++;
            if (!neutralise) continue;

            IMP stub = (types[0] == 'v') ? (IMP)GNQuarantineNoop : (IMP)GNQuarantineNilReturn;
            class_replaceMethod(target, method_getName(method), stub, types);
        }
        free(methods);
    }

    GNBeaconLine("quarantine: named class %s - %d instance / %d class method(s) ObjC-visible, "
                 "%d %s, %d left alone%s",
                 class_getName(cls), instanceMethods, classMethods, replaced,
                 neutralise ? "replaced" : "would be replaced", skipped,
                 (instanceMethods + classMethods) == 0
                     ? " (none at all: a Swift-only class has no method list to walk, which is "
                       "why GNCloudKitSymbolQuarantine exists)" : "");

    __sync_add_and_fetch(&gQuarantineReplaced, replaced);
    return replaced;
}

#pragma mark - Public

int32_t GNCloudKitQuarantineReplacedCount(void) {
    return gQuarantineReplaced;
}

int32_t GNCloudKitQuarantineClassCount(void) {
    return gQuarantineClasses;
}

BOOL GNInstallCloudKitQuarantine(NSDictionary *cfg) {
    if (!GNCFG(@"CloudKitQuarantine", YES)) {
        GNBeaconLine("quarantine: disabled by config - only the named entry points in "
                     "GNCloudKitStub.m are covered");
        return NO;
    }

    NSString *mode = [cfg isKindOfClass:[NSDictionary class]] ? cfg[@"CloudKitQuarantineMode"] : nil;
    gQuarantineArmed = !([mode isKindOfClass:[NSString class]]
                         && [mode caseInsensitiveCompare:@"assert"] == NSOrderedSame);

    NSArray *prefixes = GNCFGArray(@"CloudKitQuarantinePrefixes");
    if (![prefixes isKindOfClass:[NSArray class]] || prefixes.count == 0) prefixes = nil;

    NSInteger budget = GNCGI(@"CloudKitQuarantineLogBudget", 12);
    gQuarantineNames = (int32_t)(budget > 0 ? budget : 0);

    // Every loaded class, filtered by image inside GNQuarantineClassIsCloudKit.
    int total = objc_getClassList(NULL, 0);
    if (total <= 0) {
        GNBeaconLine("quarantine: no classes in this process yet - nothing to do");
        return NO;
    }

    Class *classes = (Class *)calloc((size_t)total, sizeof(Class));
    if (!classes) {
        GNBeaconLine("quarantine: class table allocation failed - not installed");
        return NO;
    }
    total = objc_getClassList(classes, total);

    int32_t before = gQuarantineReplaced;
    int32_t cloudkitClasses = 0;

    for (int i = 0; i < total; i++) {
        Class cls = classes[i];
        if (!GNQuarantineClassIsCloudKit(cls)) continue;
        cloudkitClasses++;
        GNQuarantineClass(cls, prefixes, gQuarantineArmed);
    }
    free(classes);

    // -- v23: the classes the caller named ---------------------------------
    // After the shape sweep, never before it: a named class may also match the
    // shape rule, and the named answer (every representable method) is the wider
    // one, so it has to be the last word on that class.
    //
    // This runs before the "no CloudKit classes" early return on purpose. A named
    // class is a direct question - did CKPersona register? - and the answer is
    // useful even on the pass where the shape sweep found nothing to do.
    BOOL namedFound = NO;
    NSArray *named = GNCFGArray(@"CloudKitQuarantineClasses");
    if ([named isKindOfClass:[NSArray class]] && named.count > 0) {
        for (id entry in named) {
            if (![entry isKindOfClass:[NSString class]] || [entry length] == 0) continue;

            Class cls = objc_getClass([(NSString *)entry UTF8String]);
            if (!cls) {
                GNBeaconLine("quarantine: named class %s is not registered in this process "
                             "(not loaded yet, or the runtime name differs from the Swift name)",
                             [(NSString *)entry UTF8String]);
                continue;
            }
            namedFound = YES;
            GNQuarantineNamedClass(cls, gQuarantineArmed);
        }
    }

    int32_t did = gQuarantineReplaced - before;
    if (cloudkitClasses == 0 && !namedFound) {
        GNBeaconLine("quarantine: no CloudKit classes loaded yet - CloudKit is not in this "
                     "process or not loaded; the launcher retries");
        return NO;
    }

    GNBeaconLine("quarantine: %s - %d CloudKit class(es) inspected, %d method(s) this pass, "
                 "%d total this launch",
                 gQuarantineArmed ? "neutralised" : "assert only (nothing replaced)",
                 cloudkitClasses, (int)did, (int)gQuarantineReplaced);
    if (!gQuarantineArmed) {
        GNBeaconLine("quarantine: mode=assert - the names above are what *would* be dropped; "
                     "no implementation was changed");
    }
    return did > 0 || !gQuarantineArmed;
}
