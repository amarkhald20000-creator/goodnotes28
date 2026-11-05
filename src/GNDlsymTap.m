//
//  GNDlsymTap.m
//  Interpose the lookup, not the function.
//
//  ======================= what the v17 log measured =======================
//
//      slot: 'SecTaskCopyValueForEntitlement'   target 0x… 2622 image(s), 2526 slot
//                                               section(s), 1 slot(s) rewritten
//      slot: 'SecTaskCopyValuesForEntitlements' target 0x… 2622 image(s), 2526 slot
//                                               section(s), 0 slot(s) rewritten
//
//  Same walker, same process, same instant. One of the two functions is reachable
//  through an import slot and the other is not, which leaves exactly two ways a
//  caller can reach it:
//
//    direct branch   `bl` straight into the function. The instruction is on a
//                    code page, so nothing data-only can change it - and on a
//                    Distribution signature a write there is not a hook, it is
//                    the CODESIGNING / Invalid Page kill this project already
//                    paid for.
//
//    cached pointer  the caller resolves the symbol once - `dlsym`, or a weak
//                    import that dyld binds into a variable - and calls through
//                    the value it kept. No import slot for the call site, and
//                    the address itself is data.
//
//  The second case is reachable, and only from one place: the resolution. A
//  framework that soft-links a newer API (SecTaskCopyValuesForEntitlements is
//  several OS versions younger than the singular form) does exactly this, which
//  is why CloudKit can call it without a slot that holds its address.
//
//  ============================== what this does ==============================
//
//  It rewrites the import slots that hold dlsym() - the same address-matched,
//  byte-proven rewrite src/GNSlotScan.m does for the entitlement functions - to a
//  replacement that:
//
//      * answers the three entitlement symbols with this dylib's repair,
//      * defers every other name to the real dlsym,
//      * returns the real answer when the symbol is absent, so a caller that
//        probes for availability still sees "absent".
//
//  The real dlsym is resolved and stored *before* anything is rewritten, so the
//  tap can never call itself: it calls a pointer, not the slot.
//
//  What it does not do: it cannot help a caller that uses a direct branch. That
//  case remains unfixable in process, and the log says so with a zero rather than
//  a theory.
//

#import "GNUnlock.h"
#import "GNEntitlementRepair.h"

#include <dlfcn.h>
#include <string.h>

typedef void *(*GNDlsymFn)(void *, const char *);

/// Resolved before the first slot is rewritten. If this is NULL nothing is
/// installed: a tap that cannot reach the real function would break every
/// dlsym in the process.
static GNDlsymFn gRealDlsym;

static volatile int32_t gTapHits;
static int32_t gTapLogBudget = 8;
static bool gInstalled;

/// The three names CloudKit can use to read the entitlements, mapped to the
/// repair. Compared with strcmp on purpose: these are cold, called once per
/// framework initialiser at most.
static void *GNRepairForName(const char *symbol) {
    if (!symbol) return NULL;
    if (strcmp(symbol, "SecTaskCopyValueForEntitlement") == 0) {
        return (void *)&GNRepairCopyValueForEntitlement;
    }
    if (strcmp(symbol, "SecTaskCopyValuesForEntitlements") == 0) {
        return (void *)&GNRepairCopyValuesForEntitlements;
    }
    if (strcmp(symbol, "SecCodeCopySigningInformation") == 0) {
        return (void *)&GNRepairCopySigningInformation;
    }
    return NULL;
}

void *GNDlsymTap(void *handle, const char *symbol) {
    if (!gRealDlsym) return NULL;

    void *result = gRealDlsym(handle, symbol);

    // Only replace a symbol that the process actually has. A framework probing
    // for a newer API has to keep seeing "absent" where it is absent, or its
    // fallback path is skipped and the reason becomes our hook.
    if (!result || !symbol) return result;

    void *replacement = GNRepairForName(symbol);
    if (!replacement) return result;

    int32_t index = __atomic_add_fetch(&gTapHits, 1, __ATOMIC_SEQ_CST);
    if (index <= gTapLogBudget) {
        GNLogC("dlsym: '%s' resolved at %p - answered with this dylib's repair (%d)",
               symbol, result, (int)index);
        if (index == 1) {
            GNLogC("dlsym: this is the evidence that the read happened through a "
                   "lookup rather than an import slot - which is why v17 found zero "
                   "slots for the plural call");
        }
    }
    return replacement;
}

int32_t GNDlsymTapHitCount(void) {
    return gTapHits;
}

void GNInstallDlsymTap(NSDictionary *cfg) {
    (void)cfg;
    if (gInstalled) return;
    gInstalled = true;

    if (!GNCFG(@"DlsymTap", YES)) {
        GNLogC("dlsym: disabled by config - a lookup-resolved entitlement read stays "
               "unrepaired");
        return;
    }
    if (GNSafeModeActive()) {
        GNLogC("dlsym: safe mode (the previous launch died in our code) - not installed");
        return;
    }

    gTapLogBudget = (int32_t)GNCGI(@"DlsymTapLogBudget", 8);

    // Resolve *now*, through the real function, and keep the pointer. Every
    // rewrite below happens after this line, so the tap calls a stored address
    // and can never recurse into itself.
    gRealDlsym = (GNDlsymFn)dlsym(RTLD_DEFAULT, "dlsym");
    if (!gRealDlsym) {
        GNLogC("dlsym: dlsym itself is not resolvable - tap not installed");
        return;
    }

    void *original = NULL;
    int32_t sections = GNSlotRebindSymbol("dlsym", (void *)&GNDlsymTap, &original, true);
    int32_t written = GNSlotRewriteCount();

    if (sections <= 0) {
        GNLogC("dlsym: no import slot section in this process holds dlsym - the tap is "
               "not on any path");
        return;
    }
    if (written == 0) {
        GNLogC("dlsym: %d slot section(s) walked, none held dlsym", (int)sections);
        return;
    }
    GNLogC("dlsym: tap armed (%d slot section(s) walked, %d slot(s) rewritten so far "
           "across all watches)", (int)sections, (int)written);
}
