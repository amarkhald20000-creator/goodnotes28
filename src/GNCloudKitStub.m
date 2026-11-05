//
//  GNCloudKitStub.m
//  Answer for CloudKit at the Objective-C boundary, and never enter it.
//
//  Read GNCloudKitStub.h first: it explains why five versions of "repair the
//  value" were the wrong shape of fix. This file is the replacement.
//
//  ===================== why the stub is a subclass, not a proxy =====================
//
//  A proxy is a different class that forwards, and anything that type checks it
//  sees a different class. A runtime subclass of the real CKContainer is a
//  CKContainer as far as ObjC and Swift are concerned - isKindOfClass:, the
//  Swift dynamic cast, everything - and it costs one class pair and one zeroed
//  instance.
//
//  Its ivars are zeroed by class_createInstance, which is the safest possible
//  starting state: no half-built container, no pointer into a cache that was
//  never populated, nothing a superclass method could walk off the end of.
//
//  ===================== why the original is never called =====================
//
//  Every containing design in v14-v19 called the real method inside an @try. The
//  exception then came out of a dispatch_once block, the gate stayed owned by
//  this thread, and the next call to the same once from this thread is a
//  libdispatch fault - a later, quieter, nameless crash than the one being
//  survived. Replacing the entry point instead never enters the block, so the
//  gate is never touched and there is nothing to re-enter.
//
//  ===================== what a caller sees =====================
//
//  The same thing an app sees when the user is not signed in to iCloud, which
//  is a state GoodNotes already ships UI for:
//
//      +[CKContainer defaultContainer]      -> a container object (not nil)
//      -privateCloudDatabase                -> a database object (not nil)
//      -accountStatusWithCompletionHandler: -> CKAccountStatusNoAccount
//      everything else                      -> zeroed / nil / empty
//
//  Nil is returned only when CloudKitStubMode says "nil" on purpose, because
//  several of these are non-optional in Swift: nil there is a trap, and a trap
//  is a worse log than an exception.
//

#import "GNCloudKitStub.h"
#import "GNUnlock.h"
#import "GNBeacon.h"

#import <objc/runtime.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>

/// CKAccountStatus. Spelled out as numbers on purpose: this file links no
/// CloudKit header, so the dylib still loads in a process that never loads
/// CloudKit at all.
enum {
    GNStubAccountCouldNotDetermine = 0,
    GNStubAccountAvailable = 1,
    GNStubAccountNoAccount = 2,          ///< the one every app handles gracefully
    GNStubAccountRestricted = 3,
    GNStubAccountTemporarilyUnavailable = 4,
};

/// CKApplicationPermissionStatus.
enum {
    GNStubPermissionNotDetermined = 0,
    GNStubPermissionDenied = 2,
};

/// CKErrorNotAuthenticated. An error accompanies every completion handler that
/// has an error parameter, because "no result, no error" makes a caller retry
/// forever; "no result, not authenticated" makes it show the sign-in banner it
/// already has.
enum { GNStubErrorNotAuthenticated = 9 };

static NSString *const kGNStubErrorDomain = @"CKErrorDomain";

#pragma mark - State

static Class   gStubContainerClass = Nil;
static Class   gStubDatabaseClass  = Nil;
static void   *gStubContainerRaw   = NULL;
static void   *gStubDatabaseRaw    = NULL;

static BOOL    gStubInstalled      = NO;
static int32_t gStubServed         = 0;
static int32_t gStubLogBudget      = 12;

/// "noAccount" (default), "nil", "observe".
static char    gStubMode[16]       = "noAccount";

#pragma mark - Reporting

static void GNStubSay(const char *fmt, ...) __attribute__((format(__printf__, 1, 2)));

static void GNStubSay(const char *fmt, ...) {
    int32_t count = __sync_add_and_fetch(&gStubServed, 1);
    if (count > gStubLogBudget) return;

    va_list args;
    va_start(args, fmt);
    char text[512];
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);

    GNBeaconLine("cloudkit-stub: %s", text);
}

#pragma mark - The substitute objects

/// The container every CKContainer entry point answers with. One instance for
/// the launch: CloudKit's own container is a singleton and code in the wild
/// compares containers by identity.
static id GNStubContainerObject(void) {
    if (!gStubContainerRaw) return nil;
    // __bridge: the +1 from class_createInstance is deliberately never released.
    // One object for the lifetime of the process, and a bridge cast keeps ARC
    // from turning this return into a second ownership claim on it.
    return (__bridge id)gStubContainerRaw;
}

static id GNStubDatabaseObject(void) {
    if (!gStubDatabaseRaw) return nil;
    return (__bridge id)gStubDatabaseRaw;
}

static NSError *GNStubNotAuthenticated(void) {
    @try {
        return [NSError errorWithDomain:kGNStubErrorDomain
                                   code:GNStubErrorNotAuthenticated
                               userInfo:nil];
    } @catch (__unused NSException *ignored) {
        return nil;
    }
}

/// Runs a completion handler with the "not available" answer.
///
/// Asynchronously, on the main queue, because that is what CloudKit does: a
/// caller is entitled to assume its handler is not re-entered on the stack of
/// the call it just made, and several of them take locks before making it.
typedef void (^GNStubObjectHandler)(id result, NSError *error);
typedef void (^GNStubStatusHandler)(NSInteger status, NSError *error);

static void GNStubDeliverObject(id handler, id result, NSError *error) {
    if (!handler) return;
    GNStubObjectHandler block = (GNStubObjectHandler)handler;
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            block(result, error);
        } @catch (__unused NSException *ignored) {
            GNBeaconLine("cloudkit-stub: a completion handler threw - swallowed, it is the "
                         "caller's code and the launch outranks it");
        }
    });
}

static void GNStubDeliverStatus(id handler, NSInteger status, NSError *error) {
    if (!handler) return;
    GNStubStatusHandler block = (GNStubStatusHandler)handler;
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            block(status, error);
        } @catch (__unused NSException *ignored) {
            GNBeaconLine("cloudkit-stub: a status handler threw - swallowed");
        }
    });
}

#pragma mark - The answers

/// +[CKContainer defaultContainer]
static id GNServeContainer(id self, SEL _cmd) {
    GNStubSay("+[CKContainer %s] -> the substitute container, CloudKit never sees the call",
              sel_getName(_cmd));
    if (strcmp(gStubMode, "nil") == 0) return nil;
    return GNStubContainerObject();
}

/// +[CKContainer containerWithIdentifier:]
static id GNServeContainerWithIdentifier(id self, SEL _cmd, id identifier) {
    GNStubSay("+[CKContainer containerWithIdentifier:] -> the substitute container "
              "(identifier ignored on purpose)");
    if (strcmp(gStubMode, "nil") == 0) return nil;
    return GNStubContainerObject();
}

static id GNServeDatabase(id self, SEL _cmd) {
    GNStubSay("-[CKContainer %s] -> the substitute database", sel_getName(_cmd));
    if (strcmp(gStubMode, "nil") == 0) return nil;
    return GNStubDatabaseObject();
}

/// -[CKContainer initWithContainerIdentifier:] and -initWithContainerID:
///
/// v20 replaced the class methods and the accessors and left the initialisers
/// alone, which is the hole a caller reaches with
///
///     [[CKContainer alloc] initWithContainerIdentifier:@"iCloud..."]
///
/// Everything that initialiser does, it does to a real CKContainer with real
/// ivars: container setup, the ubiquity token, and - on the evidence of every
/// version since v15 - the entitlement check that raises. Replacing it means the
/// check is never asked, and the caller gets the same substitute the class
/// methods hand out.
///
/// The +1 is real: this function stands in an init method, so the caller consumes
/// a retained reference. `ns_returns_retained` is not decoration - without it ARC
/// would treat the return as +0 and the caller would over-release a singleton.
static id GNServeContainerInit(id self, SEL _cmd, id argument) __attribute__((ns_returns_retained));

static id GNServeContainerInit(id self, SEL _cmd, id argument) {
    GNStubSay("-[CKContainer %s] -> the substitute container (the real initialiser never runs)",
              sel_getName(_cmd));
    if (strcmp(gStubMode, "nil") == 0) return nil;
    return (__bridge_transfer id)CFRetain((__bridge CFTypeRef)GNStubContainerObject());
}

/// -[CKContainer init]
static id GNServeContainerInitNoArgs(id self, SEL _cmd) __attribute__((ns_returns_retained));

static id GNServeContainerInitNoArgs(id self, SEL _cmd) {
    GNStubSay("-[CKContainer init] -> the substitute container");
    if (strcmp(gStubMode, "nil") == 0) return nil;
    return (__bridge_transfer id)CFRetain((__bridge CFTypeRef)GNStubContainerObject());
}

static id GNServeContainerIdentifier(id self, SEL _cmd) {
    // A string, not nil: callers compare it, log it and use it as a dictionary
    // key, and every one of those is a crash on nil.
    return @"iCloud.unavailable";
}

static void GNServeAccountStatus(id self, SEL _cmd, id handler) {
    GNStubSay("-[CKContainer accountStatusWithCompletionHandler:] -> CKAccountStatusNoAccount (%d)",
              (int)GNStubAccountNoAccount);
    GNStubDeliverStatus(handler, GNStubAccountNoAccount, nil);
}

static void GNServeAccountInfo(id self, SEL _cmd, id handler) {
    GNStubSay("-[CKContainer accountInfoWithCompletionHandler:] -> nil info, not authenticated");
    GNStubDeliverObject(handler, nil, GNStubNotAuthenticated());
}

static void GNServePermissionStatus(id self, SEL _cmd, NSInteger permission, id handler) {
    GNStubSay("-[CKContainer statusForApplicationPermission:completionHandler:] -> Denied");
    GNStubDeliverStatus(handler, GNStubPermissionDenied, nil);
}

static void GNServePermissionRequest(id self, SEL _cmd, NSInteger permission, id handler) {
    GNStubSay("-[CKContainer requestApplicationPermission:completionHandler:] -> Denied, "
              "nothing is requested from a real account");
    GNStubDeliverStatus(handler, GNStubPermissionDenied, nil);
}

static void GNServeUserRecordID(id self, SEL _cmd, id handler) {
    GNStubSay("-[CKContainer fetchUserRecordIDWithCompletionHandler:] -> not authenticated");
    GNStubDeliverObject(handler, nil, GNStubNotAuthenticated());
}

static void GNServeLongLivedIDs(id self, SEL _cmd, id handler) {
    GNStubSay("-[CKContainer fetchAllLongLivedOperationIDsWithCompletionHandler:] -> empty");
    GNStubDeliverObject(handler, @[], nil);
}

static void GNServeLongLivedOperation(id self, SEL _cmd, id identifier, id handler) {
    GNStubSay("-[CKContainer fetchLongLivedOperationWithID:completionHandler:] -> not authenticated");
    GNStubDeliverObject(handler, nil, GNStubNotAuthenticated());
}

/// `-[CKDatabase addOperation:]` and anything else whose only effect is work
/// that will never happen.
static void GNServeIgnoreOne(id self, SEL _cmd, id argument) {
    GNStubSay("-[%s %s] -> ignored, there is no database behind this object",
              class_getName(object_getClass(self)), sel_getName(_cmd));
}

/// `-[CKDatabase saveRecord:completionHandler:]` and the other two-argument
/// writes: the work is dropped and the handler is told it failed, which is the
/// answer a caller can act on.
static void GNServeWriteWithHandler(id self, SEL _cmd, id object, id handler) {
    GNStubSay("-[%s %s] -> not authenticated", class_getName(object_getClass(self)),
              sel_getName(_cmd));
    GNStubDeliverObject(handler, nil, GNStubNotAuthenticated());
}

static NSInteger GNServeDatabaseScope(id self, SEL _cmd) {
    return 2;   // CKDatabaseScopePrivate
}

#pragma mark - Identity and the unknown-selector net

/// One skeleton class whose methods are copied onto the runtime subclass. The
/// compiler generates the type encodings, so class_addMethod receives honest ABI
/// strings instead of ones written by hand.
@interface GNSkeletonContainer : NSObject
- (NSString *)containerIdentifier;
- (NSString *)description;
- (NSMethodSignature *)methodSignatureForSelector:(SEL)selector;
- (void)forwardInvocation:(NSInvocation *)invocation;
@end

@implementation GNSkeletonContainer

- (NSString *)containerIdentifier {
    return GNServeContainerIdentifier(self, _cmd);
}

- (NSString *)description {
    return @"<GNUnlock CKContainer substitute: iCloud unavailable, the entitlement was "
           "rejected by the signer and not by this app>";
}

/// Unknown selectors are answered, not crashed. CloudKit's surface is large and
/// includes Swift-synthesised shims whose names change between OS versions, so an
/// explicit list would only ever be the list of ones that existed when it was
/// written.
///
/// A signature is invented for anything the skeleton does not implement, and
/// -forwardInvocation: hands back a zeroed return value of that signature's
/// length: nil for an object, NO for a BOOL, 0 for an integer. That is the same
/// answer a real container gives for "nothing here".
- (NSMethodSignature *)methodSignatureForSelector:(SEL)selector {
    NSMethodSignature *signature = [super methodSignatureForSelector:selector];
    if (signature) return signature;
    // "@@:" is (object, self, _cmd) - the shape of every zero-argument getter,
    // which is what the unknown selectors on this class almost always are.
    return [NSMethodSignature signatureWithObjCTypes:"@@:"];
}

- (void)forwardInvocation:(NSInvocation *)invocation {
    NSUInteger length = [invocation.methodSignature methodReturnLength];
    if (length > 0) {
        void *zeroed = calloc(1, length);
        if (zeroed) {
            [invocation setReturnValue:zeroed];
            free(zeroed);
        }
    }
    GNStubSay("-[CKContainer substitute %s] -> zeroed return, %lu byte(s)",
              sel_getName([invocation selector]), (unsigned long)length);
}

@end

#pragma mark - Building the runtime classes

/// Copies every method declared by `skeleton` - not the ones it inherits - onto
/// `target`, keeping the compiler's type encoding.
static void GNCopySkeletonMethods(Class skeleton, Class target) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(skeleton, &count);
    if (!methods) return;

    for (unsigned int i = 0; i < count; i++) {
        SEL selector = method_getName(methods[i]);
        IMP implementation = method_getImplementation(methods[i]);
        const char *types = method_getTypeEncoding(methods[i]);
        if (!selector || !implementation || !types) continue;
        if (!class_addMethod(target, selector, implementation, types)) {
            GNBeaconLine("cloudkit-stub: %s already exists on %s - kept the existing one",
                         sel_getName(selector), class_getName(target));
        }
    }
    free(methods);
}

static Class GNMakeSubclass(Class base, const char *name, Class skeleton) {
    Class existing = objc_getClass(name);
    if (existing) return existing;

    Class made = objc_allocateClassPair(base, name, 0);
    if (!made) {
        GNBeaconLine("cloudkit-stub: objc_allocateClassPair(%s over %s) failed",
                     name, class_getName(base));
        return Nil;
    }
    GNCopySkeletonMethods(skeleton, made);
    objc_registerClassPair(made);
    return made;
}

#pragma mark - Installing over the real class

/// Replaces one method on `cls`. Deliberately does not store the old
/// implementation: this design never calls it, and keeping the pointer would be
/// an invitation to.
static BOOL GNReplace(Class cls, const char *name, IMP replacement, BOOL classMethod) {
    if (!cls || !name || !replacement) return NO;

    Class target = classMethod ? object_getClass(cls) : cls;
    SEL selector = sel_registerName(name);
    Method existing = class_getInstanceMethod(target, selector);

    if (existing) {
        // The ABI comes from the method that is already there, never from the
        // replacement's own signature: a caller compiled against CloudKit's
        // header is what the registers have to satisfy.
        class_replaceMethod(target, selector, replacement, method_getTypeEncoding(existing));
        GNBeaconLine("cloudkit-stub: %c[%s %s] replaced - the original is never called",
                     classMethod ? '+' : '-', class_getName(cls), name);
        return YES;
    }

    if (!class_addMethod(target, selector, replacement, "@@:")) {
        GNBeaconLine("cloudkit-stub: %c[%s %s] could not be added - a caller will reach "
                     "whatever CloudKit does instead",
                     classMethod ? '+' : '-', class_getName(cls), name);
        return NO;
    }
    GNBeaconLine("cloudkit-stub: %c[%s %s] added (CloudKit does not declare it here)",
                 classMethod ? '+' : '-', class_getName(cls), name);
    return YES;
}

#pragma mark - Install

int32_t GNCloudKitStubServeCount(void) {
    return gStubServed;
}

Class GNCloudKitStubContainerClass(void) {
    return gStubContainerClass;
}

BOOL GNCloudKitStubIsInstalled(void) {
    return gStubInstalled;
}

BOOL GNInstallCloudKitStub(NSDictionary *cfg) {
    if (gStubInstalled) return YES;

    if (![cfg isKindOfClass:[NSDictionary class]]) {
        GNBeaconLine("cloudkit-stub: no config - nothing installed");
        return NO;
    }
    if (!GNCFG(@"CloudKitStub", YES)) {
        GNBeaconLine("cloudkit-stub: disabled by config - CloudKit does its own entitlement "
                     "check again and the CKException is unmitigated");
        return NO;
    }

    NSString *mode = cfg[@"CloudKitStubMode"];
    if ([mode isKindOfClass:[NSString class]] && mode.length > 0) {
        snprintf(gStubMode, sizeof(gStubMode), "%s", mode.UTF8String ?: "noAccount");
    }

    id budget = cfg[@"CloudKitStubLogBudget"];
    if ([budget isKindOfClass:[NSNumber class]]) gStubLogBudget = [budget intValue];

    Class container = objc_getClass("CKContainer");
    if (!container) {
        // Not an error: CloudKit is loaded lazily in some processes, and the
        // constructor runs before a dlopen. The caller retries.
        GNBeaconLine("cloudkit-stub: CKContainer is not loaded yet - installation deferred");
        return NO;
    }

    if (strcmp(gStubMode, "observe") == 0) {
        GNBeaconLine("cloudkit-stub: mode=observe - the entry points are left alone, this "
                     "launch changes nothing");
        gStubInstalled = YES;
        return YES;
    }

    // ---- the substitute instances ----------------------------------------
    gStubContainerClass = GNMakeSubclass(container, "GNStubCKContainer",
                                         [GNSkeletonContainer class]);
    if (!gStubContainerClass) {
        GNBeaconLine("cloudkit-stub: could not build the container subclass - not installed");
        return NO;
    }
    gStubContainerRaw = (__bridge_retained void *)class_createInstance(gStubContainerClass, 0);
    if (!gStubContainerRaw) {
        GNBeaconLine("cloudkit-stub: the container instance could not be created - not installed");
        return NO;
    }

    Class database = objc_getClass("CKDatabase");
    if (database) {
        gStubDatabaseClass = GNMakeSubclass(database, "GNStubCKDatabase",
                                            [GNSkeletonContainer class]);
        if (gStubDatabaseClass) {
            gStubDatabaseRaw = (__bridge_retained void *)class_createInstance(gStubDatabaseClass, 0);
        }
    } else {
        GNBeaconLine("cloudkit-stub: CKDatabase is not loaded - the container still answers, "
                     "database entry points are not replaced");
    }

    // ---- the entry points -------------------------------------------------
    BOOL any = NO;

    any |= GNReplace(container, "defaultContainer", (IMP)GNServeContainer, YES);
    any |= GNReplace(container, "containerWithIdentifier:", (IMP)GNServeContainerWithIdentifier, YES);
    any |= GNReplace(container, "initWithContainerIdentifier:", (IMP)GNServeContainerInit, NO);
    any |= GNReplace(container, "initWithContainerID:", (IMP)GNServeContainerInit, NO);
    any |= GNReplace(container, "init", (IMP)GNServeContainerInitNoArgs, NO);
    any |= GNReplace(container, "containerIdentifier", (IMP)GNServeContainerIdentifier, NO);
    any |= GNReplace(container, "privateCloudDatabase", (IMP)GNServeDatabase, NO);
    any |= GNReplace(container, "publicCloudDatabase", (IMP)GNServeDatabase, NO);
    any |= GNReplace(container, "sharedCloudDatabase", (IMP)GNServeDatabase, NO);
    any |= GNReplace(container, "accountStatusWithCompletionHandler:", (IMP)GNServeAccountStatus, NO);
    any |= GNReplace(container, "accountInfoWithCompletionHandler:", (IMP)GNServeAccountInfo, NO);
    any |= GNReplace(container, "statusForApplicationPermission:completionHandler:",
                     (IMP)GNServePermissionStatus, NO);
    any |= GNReplace(container, "requestApplicationPermission:completionHandler:",
                     (IMP)GNServePermissionRequest, NO);
    any |= GNReplace(container, "fetchUserRecordIDWithCompletionHandler:", (IMP)GNServeUserRecordID, NO);
    any |= GNReplace(container, "fetchAllLongLivedOperationIDsWithCompletionHandler:",
                     (IMP)GNServeLongLivedIDs, NO);
    any |= GNReplace(container, "fetchLongLivedOperationWithID:completionHandler:",
                     (IMP)GNServeLongLivedOperation, NO);

    if (gStubDatabaseClass) {
        any |= GNReplace(gStubDatabaseClass, "addOperation:", (IMP)GNServeIgnoreOne, NO);
        any |= GNReplace(gStubDatabaseClass, "databaseScope", (IMP)GNServeDatabaseScope, NO);
        any |= GNReplace(gStubDatabaseClass, "saveRecord:completionHandler:",
                         (IMP)GNServeWriteWithHandler, NO);
        any |= GNReplace(gStubDatabaseClass, "deleteRecordWithID:completionHandler:",
                         (IMP)GNServeWriteWithHandler, NO);
        any |= GNReplace(gStubDatabaseClass, "fetchRecordWithID:completionHandler:",
                         (IMP)GNServeWriteWithHandler, NO);
        any |= GNReplace(gStubDatabaseClass, "fetchAllRecordZonesWithCompletionHandler:",
                         (IMP)GNServeWriteWithHandler, NO);
    }

    if (!any) {
        GNBeaconLine("cloudkit-stub: not one entry point could be replaced - CloudKit will "
                     "validate its entitlements exactly as before");
        return NO;
    }

    gStubInstalled = YES;
    GNBeaconLine("cloudkit-stub: installed (mode=%s) - iCloud now answers %s, the same answer "
                 "an app gets on a device with no iCloud account",
                 gStubMode,
                 strcmp(gStubMode, "nil") == 0 ? "nil" : "CKAccountStatusNoAccount");
    GNBeaconLine("cloudkit-stub: CloudKit's own dispatch_once is never entered, so there is no "
                 "half-initialised singleton behind this and nothing to re-enter");
    return YES;
}
