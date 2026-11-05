//
//  GNPrivateSecTask.m
//  dlsym, not extern. See the header for why both halves of that sentence
//  matter: an extern prototype compiles and then fails at link time, and a
//  private typedef fails at the front end.
//
//  This translation unit is deliberately Foundation-free. It is called from the
//  dylib constructor, during dyld init, where the beacon already taught the
//  lesson: send no Objective-C message there. dlopen/dlsym are plain libc calls.
//

#include "GNPrivateSecTask.h"
#include "GNEntitlementRepair.h"
#include "GNBeacon.h"

#include <dlfcn.h>
#include <stddef.h>

typedef GNSecTaskHandle (*GNCreateFromSelfFn)(CFAllocatorRef allocator);
typedef CFTypeRef (*GNCopyValueForEntitlementFn)(GNSecTaskHandle task,
                                                 CFStringRef entitlement,
                                                 CFErrorRef *error);
typedef CFTypeRef (*GNCopyValuesForEntitlementsFn)(GNSecTaskHandle task,
                                                   CFArrayRef entitlements,
                                                   CFErrorRef *error);

static GNCreateFromSelfFn gCreateFromSelf;
static GNCopyValueForEntitlementFn gCopyValueForEntitlement;
static GNCopyValuesForEntitlementsFn gCopyValuesForEntitlements;

/// 0 = not attempted, 1 = both resolved, 2 = unavailable. A tri-state on
/// purpose: "not tried" and "tried and absent" produce different log lines, and
/// conflating them is how a silent no-op looks like a working probe.
static int gResolveState;

/// Security is linked by the app, so RTLD_DEFAULT answers on the first try and
/// this is never reached. It exists for the case where it is not loaded, and it
/// is written so that its worst outcome is a log line: no retry loop, no
/// recursive dlopen, no failure that can propagate.
static void GNPrivateSecTaskLoadFramework(void) {
    static int tried;
    if (tried) return;
    tried = 1;

    if (!dlopen("/System/Library/Frameworks/Security.framework/Security",
                RTLD_NOW | RTLD_GLOBAL)) {
        (void)dlopen("/usr/lib/libsecurity.dylib", RTLD_NOW | RTLD_GLOBAL);
    }
}

static void *GNPrivateSecTaskLookup(const char *name, bool *needFramework) {
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (symbol) return symbol;

    if (needFramework && !*needFramework) {
        *needFramework = true;
        GNPrivateSecTaskLoadFramework();
    }
    return dlsym(RTLD_DEFAULT, name);
}

void GNPrivateSecTaskResolve(void) {
    if (gResolveState != 0) return;

    bool loaded = false;
    void *createSymbol = GNPrivateSecTaskLookup("SecTaskCreateFromSelf", &loaded);
    void *copySymbol = GNPrivateSecTaskLookup("SecTaskCopyValueForEntitlement", &loaded);

    // The plural form is optional: it exists on modern systems and is absent on
    // older ones, and its absence is not a failure - the singular read is what
    // the repair is built on. It is resolved so the launch-time self-test can
    // measure the plural path too (v18).
    void *valuesSymbol = GNPrivateSecTaskLookup("SecTaskCopyValuesForEntitlements", &loaded);

    // v18 guard: the dlsym tap answers these three names with this dylib's
    // repair. If a resolution ever happens *after* that tap is installed, dlsym
    // hands back a replacement instead of the real function, and calling it from
    // here would recurse - the probe reading its own repair, forever. Refuse it:
    // the honest answer is "the real function is not reachable from this path",
    // which is a log line, not a crash.
    if (copySymbol == (void *)&GNRepairCopyValueForEntitlement) copySymbol = NULL;
    if (valuesSymbol == (void *)&GNRepairCopyValuesForEntitlements) valuesSymbol = NULL;

    gCreateFromSelf = (GNCreateFromSelfFn)createSymbol;
    gCopyValueForEntitlement = (GNCopyValueForEntitlementFn)copySymbol;
    gCopyValuesForEntitlements = (GNCopyValuesForEntitlementsFn)valuesSymbol;

    if (gCreateFromSelf && gCopyValueForEntitlement) {
        gResolveState = 1;
        GNBeaconLine("probe: SecTask API resolved by dlsym - no private header, no extern");
        return;
    }

    gCreateFromSelf = NULL;
    gCopyValueForEntitlement = NULL;
    gResolveState = 2;

    GNBeaconLine("probe: SecTask API not exported in this process (create=%s copy=%s)",
                 createSymbol ? "yes" : "no", copySymbol ? "yes" : "no");
    GNBeaconLine("probe: -> entitlements cannot be read from inside this process;");
    GNBeaconLine("probe:    check the signed .mobileprovision instead of trusting a log");
}

bool GNPrivateSecTaskAvailable(void) {
    if (gResolveState == 0) GNPrivateSecTaskResolve();
    return gResolveState == 1;
}

GNSecTaskHandle GNPrivateSecTaskCreateFromSelf(void) {
    if (gResolveState == 0) GNPrivateSecTaskResolve();
    if (!gCreateFromSelf) return NULL;
    return gCreateFromSelf(kCFAllocatorDefault);
}

CFTypeRef GNPrivateSecTaskCopyEntitlement(GNSecTaskHandle task, CFStringRef entitlement) {
    if (!task) return NULL;
    if (gResolveState == 0) GNPrivateSecTaskResolve();
    if (!gCopyValueForEntitlement) return NULL;
    return gCopyValueForEntitlement(task, entitlement, NULL);
}

CFTypeRef GNPrivateSecTaskCopyValues(GNSecTaskHandle task, CFArrayRef entitlements) {
    if (!task || !entitlements) return NULL;
    if (gResolveState == 0) GNPrivateSecTaskResolve();
    if (!gCopyValuesForEntitlements) return NULL;
    return gCopyValuesForEntitlements(task, entitlements, NULL);
}
