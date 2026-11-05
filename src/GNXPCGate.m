//
//  GNXPCGate.m
//  Redirect CloudKit's mach services to a name with nothing behind it. (v21, v22)
//
//  Read GNXPCGate.h first: it states the two hypotheses this is built for, and
//  why both of them collapse into the same fix.
//
//  ===================== v22: what CI rejected, and what changed =====================
//
//  v21 declared both libxpc entry points with this file's own spelling of the ABI:
//
//      extern void *xpc_connection_create_mach_service(const char *, dispatch_queue_t, uint64_t);
//      extern void *xpc_connection_create(const char *, dispatch_queue_t);
//
//  and named both in the table. On the real iOS SDK that is two errors in the same
//  file:
//
//      error: conflicting types for 'xpc_connection_create_mach_service'
//      error: 'xpc_connection_create_mach_service' is unavailable: not available on iOS
//
//  The first is the second's fault. <xpc/connection.h> is in scope on iOS (it
//  arrives through the platform headers), so Apple's declaration of the function
//  is already visible, and Apple marks the mach-service variant
//  __attribute__((unavailable)) on this platform. A second declaration of that
//  identifier cannot agree with a declaration that says "this does not exist
//  here", and naming it in an initialiser is a front-end error before the link
//  step is reached.
//
//  v22 therefore:
//
//    * removes xpc_connection_create_mach_service from this file entirely - the
//      declaration, the replacement, the table entry and the dlsym name. There is
//      no honest way to interpose a function the SDK says is not there, and a
//      runtime dlsym + inline hook is exactly what this project cannot do on a
//      Distribution signature (see GNCapability.m: codePatching BLOCKED);
//
//    * declares the one entry point it keeps under an identifier of its own,
//      bound to the runtime symbol by an asm label:
//
//          extern void *GNXPCCreateReplacee(const char *, dispatch_queue_t)
//              __asm__("_xpc_connection_create");
//
//      This is the same shape src/GNThrowInterpose.m and
//      src/GNEntitlementRepairInterpose.m already use, and for the same reason:
//      a distinct identifier has no SDK declaration to conflict with and no
//      identifier for an availability attribute to attach to, whatever headers
//      happen to be in scope. It is weak_import, so a process without libxpc
//      binds it to 0 and dyld ignores the tuple (dyld's interpose() opens with
//      "ignore interposing on a weak function that does not exist") instead of
//      failing the load.
//
//  What is lost: if CloudKit reaches the daemon through the mach-service variant
//  specifically, this file no longer sees that call. That is a real gap and the
//  log states it rather than implying coverage; the NSXPCConnection route and the
//  quarantine (empty bodies on every void work method a CloudKit image defines)
//  are the parts that still sit above it.
//
//  ===================== why a redirect and not a fake reply =====================
//
//  The tempting version of this module fabricates the reply: intercept
//  xpc_connection_send_message_with_reply, call the handler with an error object,
//  and never touch libxpc. It is tempting because it looks like a smaller change.
//  It is not, for two reasons:
//
//    * the error object has to be a real xpc_object_t of type XPC_TYPE_ERROR, and
//      the cleanest way to obtain one is to fail a real connection. At that point
//      the redirect already exists, and the interception is dead weight;
//
//    * a handler invoked synchronously from inside the send that CloudKit just
//      made breaks an assumption CloudKit is entitled to (its completion is not
//      re-entered on the stack of the call), which is the same class of mistake
//      that v8's delegate wrappers made.
//
//  So: keep libxpc's own machinery, and change only the destination. A
//  connection to a mach service that does not exist fails on resume with
//  XPC_ERROR_CONNECTION_INVALID, asynchronously, on the queue the caller asked
//  for - the exact shape a caller already handles because it is what happens when
//  a daemon is not running.
//
//  ===================== why a name and not a different service =====================
//
//  The substitute name is deliberately one this platform will never have. That is
//  the whole safety property: there is no daemon on the other end to misinterpret
//  a message, no protocol to speak, and no way for the redirect to accidentally
//  reach something that would answer.
//

#import "GNXPCGate.h"
#import "GNInterposeReal.h"
#import "GNUnlock.h"
#import "GNBeacon.h"

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>

#pragma mark - The C entry point

/// The one libxpc symbol this module names, named the way this tree names every
/// interposed symbol: a private C identifier with an asm label. See the header
/// comment above for why a plain extern is not an option on the iOS SDK.
///
/// weak_import matters twice: the load does not fail in a process that has no
/// libxpc, and the table half reads back as 0 so the log can say "not exported"
/// instead of claiming a gate that cannot be reached.
extern void *GNXPCCreateReplacee(const char *name, dispatch_queue_t targetq)
    __asm__("_xpc_connection_create") __attribute__((weak_import));

#pragma mark - State

/// A mach service name that has no service behind it on any Apple platform.
static const char *const kGNBlackholeService = "com.zaka.gnunlock.blackhole";

static NSArray<NSString *> *gGateServices = nil;
static volatile int32_t gGateRedirects = 0;
static volatile int32_t gGateLogBudget = 8;
static volatile int32_t gGateLogs = 0;
static volatile int32_t gGateInstalled = 0;

static void GNXPCGateSay(const char *fmt, ...) __attribute__((format(__printf__, 1, 2)));

static void GNXPCGateSay(const char *fmt, ...) {
    int32_t slot = __sync_add_and_fetch(&gGateLogs, 1);
    if (slot > gGateLogBudget) return;

    va_list args;
    va_start(args, fmt);
    char text[512];
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);
    GNBeaconLine("xpc-gate: %s", text);
}

#pragma mark - Which services count

static NSArray<NSString *> *GNXPCGateNeedles(void) {
    if (gGateServices) return gGateServices;
    return @[ @"cloudd", @"cloudkit", @"com.apple.ck." ];
}

/// Case-insensitive substring match against the needles. The default set is
/// deliberately narrow: cloudd and cloudkit are CloudKit's own services, and
/// "com.apple.ck." is the prefix its XPC endpoints use. Nothing else in this
/// process is redirected, so a failure here cannot become a failure in, say,
/// notifications or the keyboard.
static BOOL GNXPCGateMatches(const char *name) {
    if (!name || !*name) return NO;

    NSArray<NSString *> *needles = GNXPCGateNeedles();
    NSString *text = [NSString stringWithUTF8String:name];
    if (!text) return NO;
    NSString *lower = [text lowercaseString];

    for (NSString *needle in needles) {
        if (![needle isKindOfClass:[NSString class]] || needle.length == 0) continue;
        if ([lower containsString:[needle lowercaseString]]) return YES;
    }
    return NO;
}

#pragma mark - The table

typedef struct {
    const void *replacement;
    const void *replacee;
} GNXPCGateTuple;

static void *GNXPCGateCreate(const char *name, dispatch_queue_t targetq);

/// One entry, because one entry point can be named on this platform.
///
/// `used` because nothing in this image refers to the table - the consumer is
/// dyld, and without the attribute the linker is entitled to drop it, which would
/// leave this file as a quiet no-op with a log line claiming otherwise.
__attribute__((used))
static GNXPCGateTuple GNXPCGateTable[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)&GNXPCGateCreate, (const void *)&GNXPCCreateReplacee },
};

#pragma mark - The replacement

/// The address to call *through*, never by name: a call by name from this image
/// is a binding, and dyld has already redirected every binding to the replacement
/// above. v21 asked dlsym and trusted the answer; v22 goes through
/// GNInterposeReal(), which also refuses an answer that is this replacement and
/// falls back to the tuple half.
static void *GNXPCCreateOriginal(void) {
    static void *real = NULL;
    if (!real) {
        real = GNInterposeReal("xpc_connection_create",
                               GNXPCGateTable[0].replacee,
                               (const void *)&GNXPCGateCreate,
                               "xpc-gate");
    }
    return real;
}

static void *GNXPCGateCreate(const char *name, dispatch_queue_t targetq) {
    void *real = GNXPCCreateOriginal();
    if (!real) {
        // Nothing trustworthy to call. Handing back a connection we cannot create
        // would be inventing one; the log already names what was seen.
        GNXPCGateSay("xpc_connection_create could not be called through - answering NULL "
                     "instead of a fabricated connection");
        return NULL;
    }

    typedef void *(*GNXPCCreateFn)(const char *, dispatch_queue_t);
    GNXPCCreateFn create = (GNXPCCreateFn)real;

    if (!GNCFG(@"XPCGate", YES) || !GNXPCGateMatches(name)) {
        return create(name, targetq);
    }

    __sync_add_and_fetch(&gGateRedirects, 1);
    GNXPCGateSay("CloudKit connection '%s' -> '%s' (nothing is listening; libxpc will answer "
                 "connection-invalid on resume)", name ?: "(null)", kGNBlackholeService);
    return create(kGNBlackholeService, targetq);
}

#pragma mark - The Foundation flavour

typedef id (*GNInitMachServiceFn)(id, SEL, NSString *, NSUInteger) __attribute__((ns_returns_retained));

static GNInitMachServiceFn gOrigInitWithMachService = NULL;

static id GNXPCGateInitWithMachService(id self, SEL _cmd, NSString *name, NSUInteger options)
    __attribute__((ns_returns_retained));

static id GNXPCGateInitWithMachService(id self, SEL _cmd, NSString *name, NSUInteger options) {
    if (!gOrigInitWithMachService) return nil;

    if (GNCFG(@"XPCGate", YES) && [name isKindOfClass:[NSString class]]
        && GNXPCGateMatches(name.UTF8String)) {
        __sync_add_and_fetch(&gGateRedirects, 1);
        GNXPCGateSay("NSXPCConnection '%s' -> '%s'", name.UTF8String ?: "(null)",
                     kGNBlackholeService);
        name = [NSString stringWithUTF8String:kGNBlackholeService];
    }
    return gOrigInitWithMachService(self, _cmd, name, options);
}

#pragma mark - Public

int32_t GNXPCGateRedirectCount(void) {
    return gGateRedirects;
}

const char *GNXPCGateBlackholeName(void) {
    return kGNBlackholeService;
}

void GNInstallXPCGate(NSDictionary *cfg) {
    if (gGateInstalled) {
        GNBeaconLine("xpc-gate: already installed");
        return;
    }
    if (![cfg isKindOfClass:[NSDictionary class]]) {
        GNBeaconLine("xpc-gate: no config - the table is link time and only the service filter "
                     "defaults apply");
    }

    if (!GNCFG(@"XPCGate", YES)) {
        GNBeaconLine("xpc-gate: disabled by config - CloudKit connections reach the daemon "
                     "again and no C entry point is redirected");
        // The table cannot be removed; the flag is read per call, which is what
        // makes "off" mean pass-through here as well.
    }

    NSArray *services = GNCFGArray(@"XPCGateServices");
    if ([services isKindOfClass:[NSArray class]] && services.count > 0) {
        gGateServices = services;
    }
    gGateLogBudget = (int32_t)GNCGI(@"XPCGateLogBudget", 8);

    // The bound value is read from the tuple, not from the identifier: reading
    // the identifier goes through a binding, and this dylib's bindings are the
    // ones dyld just redirected. The tuple half is the raw stored pointer.
    const void *bound = GNXPCGateTable[0].replacee;
    if (!bound || bound == (const void *)&GNXPCGateCreate) {
        GNXPCGateSay("xpc_connection_create is not usable in this process (tuple half %p) - the "
                     "C route cannot be gated here; only NSXPCConnection is", bound);
    } else {
        GNXPCGateSay("xpc_connection_create bound at %p; every binding of it now reaches this "
                     "file", bound);
    }

    if (GNCFG(@"XPCGateNSXPC", YES)) {
        Class connection = objc_getClass("NSXPCConnection");
        SEL selector = connection ? sel_registerName("initWithMachServiceName:options:") : NULL;
        Method method = (connection && selector)
            ? class_getInstanceMethod(connection, selector) : NULL;
        if (method) {
            gOrigInitWithMachService = (GNInitMachServiceFn)method_getImplementation(method);
            method_setImplementation(method, (IMP)GNXPCGateInitWithMachService);
            GNXPCGateSay("NSXPCConnection -initWithMachServiceName:options: replaced");
        } else {
            GNXPCGateSay("NSXPCConnection is not loaded - the C entry point is the only route");
        }
    }

    gGateInstalled = 1;

    GNXPCGateSay("installed - %d entr(y|ies) in __DATA,__interpose, filter: %s",
                 (int)(sizeof(GNXPCGateTable) / sizeof(GNXPCGateTable[0])),
                 [[GNXPCGateNeedles() componentsJoinedByString:@", "] UTF8String]);
    GNXPCGateSay("substitute service: %s (no daemon, by construction)", kGNBlackholeService);
    GNXPCGateSay("the mach-service variant of xpc_connection_create is unavailable on iOS and "
                 "is not named anywhere in this dylib - a CloudKit call that uses that variant "
                 "specifically is not covered, and this line is here so the log never implies "
                 "it is");
    GNXPCGateSay("what CloudKit receives is libxpc's own XPC_ERROR_CONNECTION_INVALID for a "
                 "dead endpoint - the same answer it gets when a daemon is not running");
}
