//
//  GNSlotScan.m
//  Rewrite an import slot that happens to hold a given function address, in
//  every image in the process - shared cache included.
//
//  ===================== what went wrong in v15, exactly =====================
//
//  v15 put SecTaskCopyValueForEntitlement and SecTaskCopyValuesForEntitlements
//  in a __DATA,__interpose table and let dyld do the work. dyld applies an
//  interpose to *bindings*, i.e. to import slots, and only where an import slot
//  exists. Two ways that leaves a hole:
//
//    * a caller that reaches the function with a direct branch has no slot to
//      rewrite, so there is nothing for dyld to patch;
//    * our replacement is only ever reached through a slot dyld rewrote. If the
//      read happens in an image whose binding dyld does not touch, the repair is
//      dead code - and the log says "armed" while nothing is intercepted.
//
//  The remaining data-only option is to rewrite the slot ourselves. That is what
//  fishhook does, and it fails here for two structural reasons:
//
//    * fishhook looks a slot up by *name*, through the classic symbol table and
//      the indirect symbol table. The dyld shared cache strips both. Every
//      system image therefore reports zero symbols and nothing is ever found -
//      which is exactly the subclass of image this problem lives in;
//    * on arm64e the slot holds an authenticated pointer, signed over the
//      identity of that slot. A plain address written there does not fail at the
//      write, it fails at the next call, in a frame that looks nothing like the
//      hook.
//
//  Neither is fatal once you stop using names and stop guessing:
//
//    identify a slot by the address it holds, not by what it is called
//        walk __got / __auth_got / __la_symbol_ptr / __nl_symbol_ptr out of the
//        section table (which the cache keeps), read each entry, and compare it
//        with the resolved address of the function we are after. A slot that
//        points at it is, by definition, a call site for it.
//
//    prove the signature before writing it
//        the slot already contains a correctly signed pointer to `target`. Sign
//        `target` again with each candidate key/discriminator pair and require
//        the result to equal the bytes already in the slot. Only a pair that
//        reproduces the existing content byte for byte is used to sign the
//        replacement. Nothing is guessed, and a slot that cannot be reproduced
//        is left exactly as it was (GNSlotMoveTo in src/GNRebind.m).
//
//  ============================ what this is not ============================
//
//  It is not an inline hook: no code page is written, so the amfi check that
//  killed the v5 attempt (CODESIGNING / "Failed to fault in a page with execute
//  permissions") is not involved. Every byte touched here belongs to a data page.
//
//  It is also not a promise. If the caller uses a direct branch there is no slot,
//  the scan finds nothing in that image, and the log says so with a zero - which
//  is the measurement v15 did not have.
//
#import "GNUnlock.h"

#include "GNSlotWalk.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/vm_page_size.h>

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/// Upper bound on import slot sections per launch. A typical process has a few
/// thousand across the whole shared cache; this is high enough to be complete on
/// a normal device and low enough that a corrupt section table cannot stall dyld.
enum { GN_SLOT_SECTION_BUDGET = 8192 };

/// How many symbols may be watched at once, including the ones rescanned when a
/// new image is loaded. Two is what v16 needs; the spare room is for the next
/// caller without a rewrite of this file.
enum { GN_WATCH_LIMIT = 4 };

typedef struct {
    char  symbol[128];
    void *replacement;
    void *target;
    bool  used;
    int32_t written;
} GNWatch;

static GNWatch gWatch[GN_WATCH_LIMIT];
static bool gWatchingNewImages;
static int32_t gImagesScanned;
static int32_t gSlotSections;
static int32_t gRefusedSlots;
static int32_t gSlotWritten;
static bool gBudgetLogged;
/// Images that existed when the first sweep finished. dyld replays the add-image
/// callback for every image that is already loaded at registration time, and
/// rescanning those would spend the section budget on work that is already done -
/// producing a "budget reached" line that looks like a failure and starving the
/// scan of the image the callback was actually about.
static uint32_t gImagesCoveredByFirstSweep;
static int32_t gUnreadableSections;

/// v20: a count-only sweep. When this is set, the range walker still counts
/// every slot that holds the target, and the writer refuses every one of them.
/// It exists because "no slot holds this symbol" and "we never looked" are
/// different facts, and the read-surface table has to be able to say which
/// symbols are measured without arming a hook for them.
static bool gSlotDryRun = false;

/// Slots that held the target address, across every sweep this launch.
static int32_t gSlotMatched = 0;

#pragma mark - The ops the pure walker calls back into

typedef struct {
    const GNWatch *watch;
    const char    *imageName;
    int            imageIndex;
} GNScanContext;

/// Direct read. Only ever called for a section that already passed
/// GNRangeIsReadable() - a per-slot region walk would cost more than the whole
/// scan (each one asks the kernel for the region table).
static bool GNScanRead(void *ctx, uint64_t address, uint64_t *out) {
    (void)ctx;
    uint64_t value = 0;
    memcpy(&value, (const void *)(uintptr_t)address, sizeof(value));
    *out = value;
    return true;
}

static bool GNScanWrite(void *ctx, uint64_t address, uint64_t value) {
    (void)ctx;
    if (!GNWriteBytes((uintptr_t)address, &value, sizeof(value))) return false;

    // Read it back. A write that "succeeded" but did not land is the one failure
    // mode that would look like a working hook until the next call.
    uint64_t check = 0;
    memcpy(&check, (const void *)(uintptr_t)address, sizeof(check));
    if (check != value) {
        GNLogC("slot: write at %p read back as 0x%llx, expected 0x%llx",
               (void *)(uintptr_t)address, (unsigned long long)check,
               (unsigned long long)value);
        return false;
    }
    return true;
}

static bool GNScanRefersTo(void *ctx, uint64_t raw, uint64_t target) {
    (void)ctx;
    return GNSlotRefersTo((uintptr_t)raw, (uintptr_t)target);
}

static uint64_t GNScanMoveTo(void *ctx, uint64_t raw, uint64_t target,
                             uint64_t replacement, uint64_t slotAddress) {
    (void)ctx;
    // Dry run: counted by the walker already, never written. 0 means "refuse this
    // slot", which is the walker's normal signal for "do not touch it".
    if (gSlotDryRun) return 0;
    const char *why = NULL;
    uint64_t value = (uint64_t)GNSlotMoveTo((uintptr_t)raw, (uintptr_t)target,
                                            (uintptr_t)replacement,
                                            (uintptr_t)slotAddress, &why);
    if (value == 0 && why && gRefusedSlots < 4) {
        GNLogC("slot: refused %p (%s) - left untouched", (void *)(uintptr_t)slotAddress, why);
    }
    return value;
}

#pragma mark - One section, one image

static bool GNScanSection(void *ctx, const GNWSlotSection *section) {
    GNScanContext *scan = (GNScanContext *)ctx;

    if (!section || section->size < sizeof(uint64_t)) return true;

    // A budget, because this runs inside dyld initialisation: a few thousand
    // region lookups is milliseconds, an unbounded walk on a pathological cache
    // is a launch that looks hung. Hitting the cap is logged, never silent.
    if (gSlotSections >= GN_SLOT_SECTION_BUDGET) {
        if (!gBudgetLogged) {
            gBudgetLogged = true;
            GNLogC("slot: section budget (%d) reached - the rest of the image list is "
                   "not scanned this launch", GN_SLOT_SECTION_BUDGET);
        }
        return false;
    }
    gSlotSections++;

    if (!GNRangeIsReadable((uintptr_t)section->address, (size_t)section->size)) {
        gUnreadableSections++;
        if (gUnreadableSections <= 4) {
            GNLogC("slot: %s %s,__%s is not fully readable (%llu bytes) - skipped",
                   scan->imageName, section->segname, section->sectname,
                   (unsigned long long)section->size);
        }
        return true;
    }

    GNSlotOps ops;
    memset(&ops, 0, sizeof(ops));
    ops.read = GNScanRead;
    ops.write = GNScanWrite;
    ops.refersTo = GNScanRefersTo;
    ops.moveTo = GNScanMoveTo;
    ops.ctx = scan;

    GNSlotStats stats = GNWRebindSlotRange(section->address, section->size,
                                           (uint64_t)(uintptr_t)scan->watch->target,
                                           (uint64_t)(uintptr_t)scan->watch->replacement,
                                           &ops);

    // A dry run refuses every match by design; counting those as refusals would
    // make the real "a slot could not be proven" number meaningless.
    if (!gSlotDryRun) gRefusedSlots += (int32_t)stats.refused;
    gSlotWritten += (int32_t)stats.written;
    gSlotMatched += (int32_t)stats.matched;

    if (stats.written > 0) {
        GNLogC("slot: %s %s,__%s: %llu of %llu slot(s) held '%s' - rewritten",
               scan->imageName, section->segname, section->sectname,
               (unsigned long long)stats.written, (unsigned long long)stats.scanned,
               scan->watch->symbol);
    }
    return true;
}

static int32_t GNScanImage(uint32_t index, GNWatch *watch) {
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)_dyld_get_image_header(index);
    if (!header) return 0;

    intptr_t slide = _dyld_get_image_vmaddr_slide(index);
    const char *path = _dyld_get_image_name(index);
    const char *base = path ? strrchr(path, '/') : NULL;
    const char *name = base ? base + 1 : (path ? path : "?");

    // The load commands live in __TEXT, which is mapped readably; asking the
    // kernel how far that run goes is what makes the walk bounded. The cap
    // keeps a merged shared cache mapping from turning this into a 200 MB scan.
    uint64_t readable = (uint64_t)GNReadableRunLength((uintptr_t)header, 16u << 20);
    if (readable < sizeof(GNWImageHeader)) return 0;

    GNScanContext scan;
    memset(&scan, 0, sizeof(scan));
    scan.watch = watch;
    scan.imageName = name;
    scan.imageIndex = (int)index;

    GNWWalkStats stats;
    GNWWalkImage(header, readable, (uint64_t)slide, GNScanSection, &scan, &stats);

    gImagesScanned++;

    if (stats.truncated > 0 && stats.slotSections == 0) {
        GNLogC("slot: %s load commands look trimmed (%u truncated) - nothing to scan",
               name, stats.truncated);
    }
    return (int32_t)stats.slotSections;
}

#pragma mark - Late images

/// A framework loaded with dlopen after this constructor has no slots at the time
/// of the first scan. CloudKit is exactly such a framework on GoodNotes: the app
/// links it lazily, so the slots that matter are created after we have already
/// walked the image list. dyld calls this for every image it adds, before that
/// image's own initialisers run, which is early enough.
static void GNOnImageAdded(const struct mach_header *header, intptr_t slide) {
    (void)slide;
    if (!gWatchingNewImages) return;
    if (!header) return;

    uint32_t count = _dyld_image_count();
    if (count == 0) return;

    // Match on the header dyld handed us rather than assuming the new image is
    // last. dyld calls this for every already-loaded image at registration time,
    // so "last" would rescan the same image a few dozen times and never touch the
    // one that was actually added.
    uint32_t index = 0;
    bool found = false;
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) == header) {
            index = i;
            found = true;
            break;
        }
    }
    if (!found) return;
    if (index < gImagesCoveredByFirstSweep) return;   // already swept at install
    for (int i = 0; i < GN_WATCH_LIMIT; i++) {
        if (!gWatch[i].used || !gWatch[i].target) continue;
        int32_t sections = GNScanImage(index, &gWatch[i]);
        if (sections > 0) {
            const char *path = _dyld_get_image_name(index);
            const char *base = path ? strrchr(path, '/') : NULL;
            GNLogC("slot: late image %s scanned (%d slot section(s)) for '%s'",
                   base ? base + 1 : "?", (int)sections, gWatch[i].symbol);
        }
    }
}

#pragma mark - Entry point

/// The sweep itself, for an address that is already known.
///
/// v25 split this out of GNSlotRebindSymbol because the two names that matter
/// now are *not* exported: dlsym answers NULL for both, so a rebinder that begins
/// with dlsym can never be reached. The address comes from the resolver in
/// src/GNCloudKitSymbolQuarantine.m instead (a crash-log offset mapped onto an
/// LC_FUNCTION_STARTS entry), and this function does the part that only needs an
/// address: walk every import slot section, keep the ones that hold it, and
/// redirect them - refusing any slot whose signature cannot be reproduced.
static int32_t GNRunWatch(const char *label, uintptr_t target, void *replacement,
                          bool watchNewImages, int32_t *matchedOut) {
    if (matchedOut) *matchedOut = 0;
    if (!label || !label[0] || !replacement) return 0;
    if (!target || target == (uintptr_t)replacement) return 0;

    if (GNSafeModeActive()) {
        GNLogC("slot: safe mode (the previous launch died in our code) - '%s' not scanned",
               label);
        return 0;
    }

    GNWatch *watch = NULL;
    for (int i = 0; i < GN_WATCH_LIMIT; i++) {
        if (gWatch[i].used && strcmp(gWatch[i].symbol, label) == 0) {
            watch = &gWatch[i];
            break;
        }
    }
    if (!watch) {
        for (int i = 0; i < GN_WATCH_LIMIT; i++) {
            if (!gWatch[i].used) {
                watch = &gWatch[i];
                memset(watch, 0, sizeof(*watch));
                snprintf(watch->symbol, sizeof(watch->symbol), "%s", label);
                watch->used = true;
                break;
            }
        }
    }
    if (!watch) {
        GNLogC("slot: no watch slot left for '%s' - skipped", label);
        return 0;
    }
    watch->replacement = replacement;
    watch->target = (void *)target;

    uint32_t count = _dyld_image_count();
    int32_t totalSections = 0;
    int32_t writtenBefore = gSlotWritten;
    int32_t matchedBefore = gSlotMatched;

    for (uint32_t i = 0; i < count; i++) {
        totalSections += GNScanImage(i, watch);
    }

    if (watchNewImages && !gWatchingNewImages) {
        gImagesCoveredByFirstSweep = _dyld_image_count();
        gWatchingNewImages = true;
        _dyld_register_func_for_add_image(GNOnImageAdded);
        GNLogC("slot: watching for late images - a framework loaded later is scanned "
               "before its initialisers run");
    }

    int32_t matched = gSlotMatched - matchedBefore;
    int32_t written = gSlotWritten - writtenBefore;
    if (matchedOut) *matchedOut = matched;

    GNLogC("slot: '%s' target %p, %d image(s) walked, %d import slot section(s), "
           "%d slot(s) held it, %d rewritten",
           label, (void *)target, (int)gImagesScanned, (int)totalSections,
           (int)matched, (int)written);
    return totalSections;
}

int32_t GNSlotRebindAddress(const char *label, uintptr_t target, void *replacement,
                            bool watchNewImages, int32_t *matchedOut) {
    return GNRunWatch(label, target, replacement, watchNewImages, matchedOut);
}

int32_t GNSlotRebindSymbol(const char *symbol, void *replacement, void **original,
                           bool watchNewImages) {
    if (!symbol || !symbol[0] || !replacement) return 0;

    void *resolved = dlsym(RTLD_DEFAULT, symbol);
    if (!resolved) {
        GNLogC("slot: '%s' is not in this process - nothing to scan", symbol);
        return 0;
    }

    // dlsym may hand back an authenticated pointer on arm64e. Comparing slot
    // contents against a signed address would never match, so strip it once.
    uintptr_t target = GNSlotStripAddress((uintptr_t)resolved);
    if (original) *original = resolved;

    return GNRunWatch(symbol, target, replacement, watchNewImages, NULL);
}

/// The address-keyed dry run: how many import slots in this process hold
/// `target`, without writing one of them. Used for a target that was resolved
/// from an offset, where "no slot" and "never looked" have to be distinguishable
/// in the log.
int32_t GNSlotProbeAddress(uintptr_t target, int32_t *matchedOut) {
    if (matchedOut) *matchedOut = 0;
    if (!target) return 0;

    // A placeholder that is never reached: the writer refuses every slot while
    // the dry run flag is set. It only has to differ from the target.
    void *placeholder = (void *)&gSlotDryRun;

    int32_t before = gSlotMatched;
    gSlotDryRun = true;
    int32_t sections = GNRunWatch("probe", target, placeholder, false, NULL);
    gSlotDryRun = false;

    if (matchedOut) *matchedOut = gSlotMatched - before;
    return sections;
}

int32_t GNSlotRewriteCount(void) {
    return gSlotWritten;
}

int32_t GNSlotSectionCount(void) {
    return gSlotSections;
}

int32_t GNSlotRefusedCount(void) {
    return gRefusedSlots;
}

int32_t GNSlotMatchCount(void) {
    return gSlotMatched;
}

/// Counts the import slots that hold `symbol`'s address, in every image, without
/// rewriting one of them.
///
/// The v17-v19 logs answered "was it rewritten" per symbol, which conflates two
/// facts: a symbol with no slots may have no caller, or a caller that never goes
/// through a slot. This answers "how many callers go through a slot" for symbols
/// this dylib deliberately does not hook - SecCodeCopySelf, SecTaskCreateFromSelf,
/// the libxpc entitlement readers - so the log can say which doors exist in this
/// process instead of listing the ones someone thought of.
///
/// Returns the number of import slot sections walked; the match count is the
/// difference in GNSlotMatchCount() across the call.
int32_t GNSlotProbeSymbol(const char *symbol, void **resolvedOut) {
    if (!symbol || !symbol[0]) return 0;

    void *resolved = dlsym(RTLD_DEFAULT, symbol);
    if (resolvedOut) *resolvedOut = resolved;
    if (!resolved) return 0;

    // A placeholder replacement: never reached, because the writer refuses every
    // slot while the dry run flag is set. It only has to be an address that is
    // not the target, so GNSlotRebindSymbol gets past its early return.
    void *placeholder = (void *)&gSlotDryRun;

    gSlotDryRun = true;
    int32_t sections = GNSlotRebindSymbol(symbol, placeholder, NULL, false);
    gSlotDryRun = false;
    return sections;
}
