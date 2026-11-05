//
//  GNReadAudit.m
//  Who asked, and did the answer change.
//
//  ============================ the state v18 left ============================
//
//  v17/v18 established, by measurement, that the repair is reached on some paths:
//
//      repair: #1 com.apple.developer.icloud-services (schema wants array of
//              strings): string "*" -> array(1)
//      slot: self-test  VERDICT: interception is LIVE in this process
//
//  and the launch still died with the same CKException. Both statements are true
//  at the same time, and they are only compatible in one way: the self-test
//  proves the interposition works on a call that goes *through a binding we
//  control*. It does not prove that CloudKit's call site is one of those.
//
//  "interception is LIVE" and "CloudKit read our value" are two different claims
//  and this project had been treating the first as proof of the second. That is
//  the gap this file closes.
//
//  ============================== what it records ==============================
//
//  Every one of the three repaired doors, on every call:
//
//      the door          single / batch / signing information
//      the caller        the return address inside the door (see below)
//      whether the value was actually rewritten on that call
//
//  The numbers are counted only. The caller address is stored raw and resolved
//  to image + offset later, at +5s, on a background queue - resolving it inline
//  would run dladdr inside a call that CloudKit makes during dyld init, and this
//  project has already paid once for doing work on that path.
//
//  ================================ the three answers ================================
//
//  hits = 0
//      Nothing in this process reached a repaired door. The read happens between
//      two images inside the dyld shared cache, where the call is a direct branch
//      resolved when the cache was built: no import slot exists, no dyld binding
//      exists, and no data-only mechanism can change it. The value has to be
//      fixed where it is written - in the signature.
//
//  hits > 0, rewritten = 0
//      Callers arrived and the value was already correct. Whatever CloudKit is
//      objecting to, it is not the type of this key at these call sites.
//
//  rewritten > 0 and the launch still dies
//      The repair answered and the process still rejected the value. The caller
//      image names on the "audit:" lines are then the whole answer: if none of
//      them is a CloudKit image, CloudKit never asked here.
//
//  The point of printing a caller image is that it ends the guessing. §"try
//  hooking one more symbol" stops being a plan once the log says nobody called.
//

#import "GNUnlock.h"
#import "GNBeacon.h"

#include <dlfcn.h>
#include <string.h>

/// Distinct call sites kept. A process asks for the same three keys from the
/// same two or three places; 32 is comfortably above that and still a static
/// allocation, because this runs during dyld init.
#define GN_READ_AUDIT_SITES 32

typedef struct {
    uintptr_t caller;       ///< raw return address inside the door
    int32_t   hits;
    bool      changed;      ///< at least one call had its value rewritten
    bool      used;
} GNReadSite;

static GNReadSite gSites[GN_READ_AUDIT_SITES];
static int32_t    gSiteReserved;          ///< monotonic, may exceed the table

static volatile int32_t gDoorHits[GNReadDoorCount];
static volatile int32_t gDoorChanged[GNReadDoorCount];
static volatile int32_t gTotalHits;
static volatile int32_t gTotalChanged;
static volatile int32_t gTotalDropped;

/// Non-zero while something in this dylib is calling a door on purpose. The
/// slot self-test does exactly that - it calls the singular read through our own
/// binding to prove the binding is ours - and counting that as "CloudKit asked"
/// would turn the one number this file exists to produce into an artefact of the
/// measurement itself.
static volatile int32_t gQuiet;

/// One door can call another: the batch door falls back to the single one key by
/// key when the batch symbol is absent. Without this, one CloudKit question would
/// be counted twice and the totals would describe our own layering instead of the
/// caller.
static __thread int tDoorDepth;

static const char *GNReadDoorName(GNReadDoor door) {
    switch (door) {
        case GNReadDoorSingle:      return "SecTaskCopyValueForEntitlement";
        case GNReadDoorBatch:       return "SecTaskCopyValuesForEntitlements";
        case GNReadDoorSigningInfo: return "SecCodeCopySigningInformation";
        default:                    return "unknown";
    }
}

void GNReadAuditSuspend(void) {
    __atomic_add_fetch(&gQuiet, 1, __ATOMIC_SEQ_CST);
}

void GNReadAuditResume(void) {
    __atomic_sub_fetch(&gQuiet, 1, __ATOMIC_SEQ_CST);
}

static void GNReadAuditRecord(GNReadDoor door, const void *caller, bool changed);

/// `caller` is __builtin_return_address(0) taken inside the door, i.e. the
/// instruction the caller returns to - which is the call site, not our frame.
void GNReadAuditNote(GNReadDoor door, const void *caller, bool changed) {
    if (tDoorDepth > 0) return;
    tDoorDepth++;
    GNReadAuditRecord(door, caller, changed);
    tDoorDepth--;
}

static void GNReadAuditRecord(GNReadDoor door, const void *caller, bool changed) {
    if (door < 0 || door >= GNReadDoorCount) return;
    if (__atomic_load_n(&gQuiet, __ATOMIC_SEQ_CST) > 0) return;

    __atomic_add_fetch(&gDoorHits[door], 1, __ATOMIC_SEQ_CST);
    if (changed) __atomic_add_fetch(&gDoorChanged[door], 1, __ATOMIC_SEQ_CST);

    __atomic_add_fetch(&gTotalHits, 1, __ATOMIC_SEQ_CST);
    if (changed) __atomic_add_fetch(&gTotalChanged, 1, __ATOMIC_SEQ_CST);

    uintptr_t address = (uintptr_t)caller;
    if (!address) return;

    int32_t count = __atomic_load_n(&gSiteReserved, __ATOMIC_SEQ_CST);
    if (count > GN_READ_AUDIT_SITES) count = GN_READ_AUDIT_SITES;

    for (int32_t i = 0; i < count; i++) {
        if (gSites[i].used && gSites[i].caller == address) {
            __atomic_add_fetch(&gSites[i].hits, 1, __ATOMIC_SEQ_CST);
            if (changed) gSites[i].changed = true;
            return;
        }
    }

    int32_t slot = __atomic_add_fetch(&gSiteReserved, 1, __ATOMIC_SEQ_CST) - 1;
    if (slot >= GN_READ_AUDIT_SITES) {
        __atomic_add_fetch(&gTotalDropped, 1, __ATOMIC_SEQ_CST);
        return;
    }
    gSites[slot].caller = address;
    gSites[slot].hits = 1;
    gSites[slot].changed = changed;
    gSites[slot].used = true;
}

int32_t GNReadAuditHitCount(void) {
    return __atomic_load_n(&gTotalHits, __ATOMIC_SEQ_CST);
}

int32_t GNReadAuditChangedCount(void) {
    return __atomic_load_n(&gTotalChanged, __ATOMIC_SEQ_CST);
}

/// "CloudKitCore + 0x2f1a4" when dladdr can describe the address, otherwise the
/// bare number. Called from the delayed dump only - never from a door.
static NSString *GNReadSiteDescription(uintptr_t address) {
    Dl_info info;
    if (dladdr((const void *)address, &info) && info.dli_fname) {
        const char *base = strrchr(info.dli_fname, '/');
        const char *name = base ? base + 1 : info.dli_fname;
        unsigned long long offset = (unsigned long long)(address - (uintptr_t)info.dli_fbase);
        BOOL system = GNIsSystemImagePath(info.dli_fname);
        return [NSString stringWithFormat:@"%s + 0x%llx%s", name, offset,
                                          system ? " (shared cache)" : " (app)"];
    }
    return [NSString stringWithFormat:@"0x%llx (unresolved)", (unsigned long long)address];
}

NSString *GNReadAuditSummary(void) {
    NSMutableString *text = [NSMutableString string];
    int32_t total = __atomic_load_n(&gTotalHits, __ATOMIC_SEQ_CST);

    [text appendFormat:@"%d call(s) through a repaired door, %d with a rewritten value",
                       (int)total, (int)__atomic_load_n(&gTotalChanged, __ATOMIC_SEQ_CST)];

    for (int door = 0; door < GNReadDoorCount; door++) {
        int32_t hits = __atomic_load_n(&gDoorHits[door], __ATOMIC_SEQ_CST);
        if (hits == 0) continue;
        [text appendFormat:@"; %s x%d", GNReadDoorName((GNReadDoor)door), (int)hits];
    }
    int32_t dropped = __atomic_load_n(&gTotalDropped, __ATOMIC_SEQ_CST);
    if (dropped > 0) [text appendFormat:@"; %d call site(s) beyond the table", (int)dropped];
    return text;
}

NSString *GNReadAuditVerdict(void) {
    int32_t total = __atomic_load_n(&gTotalHits, __ATOMIC_SEQ_CST);
    int32_t changed = __atomic_load_n(&gTotalChanged, __ATOMIC_SEQ_CST);

    if (total == 0) {
        return @"VERDICT: nothing in this process reached a repaired door. The "
               @"entitlement read happens between two images inside the shared cache, "
               @"where the call is a direct branch - no import slot, no binding, and "
               @"no data-only hook can change it. Stop adding hooks: the value has to "
               @"be written correctly by the signer.";
    }
    if (changed == 0) {
        return @"VERDICT: callers arrived but the value was already well formed at "
               @"every one of them, so this key is not what CloudKit is objecting to "
               @"at those call sites.";
    }
    return @"VERDICT: the repair answered and the value was rewritten, and the launch "
           @"still died. Read the caller images below: if no CloudKit image is among "
           @"them, CloudKit never asked through this door.";
}

void GNReadAuditDump(void) {
    GNBeaconLine("audit: %s", GNReadAuditSummary().UTF8String);

    int32_t count = __atomic_load_n(&gSiteReserved, __ATOMIC_SEQ_CST);
    if (count > GN_READ_AUDIT_SITES) count = GN_READ_AUDIT_SITES;

    for (int32_t i = 0; i < count; i++) {
        if (!gSites[i].used) continue;
        GNBeaconLine("audit:   %2d hit(s)%s <- %s",
                     (int)gSites[i].hits,
                     gSites[i].changed ? " (rewritten)" : "",
                     GNReadSiteDescription(gSites[i].caller).UTF8String);
    }

    GNBeaconLine("audit: %s", GNReadAuditVerdict().UTF8String);
}
