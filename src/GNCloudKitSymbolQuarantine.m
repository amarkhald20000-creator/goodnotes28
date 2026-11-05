//
//  GNCloudKitSymbolQuarantine.m
//  Resolve the two names at run time, then rewrite the slots that hold them.
//  (v25)
//
//  Read GNCloudKitSymbolQuarantine.h first: it states why v24 could not link
//  (neither name is in CloudKit's .tbd), why dlsym is expected to fail for the
//  same reason, and what the offset path does about that.
//
//  ===================== the shape of each replacement =====================
//
//  Both are ordinary C functions with the callee's own signature:
//
//      CKPersona.launch                      ()            -> Optional<CKPersona>
//      CKMainBundleIsAppleExecutable         ()            -> bool
//
//  Pointer-sized and one byte respectively. Neither is noreturn, so a return
//  here is a well defined event for the caller.
//
//  They reach the real function through the pointer this file resolved, never
//  through a name. That matters twice: an interpose table is gone, so there is no
//  tuple half to fall back on; and a call by name from inside a replacement is
//  how v22 recursed into itself.
//
//  ===================== what changed from v23/v24 =====================
//
//  v24 was an __DATA,__interpose table naming two symbols the linker cannot see.
//  A table that does not exist cannot be armed, so this file no longer has one:
//  there is no extern, no asm label, no section. The address comes from
//  dlsym-then-offset, and the redirection is done by GNSlotRebindAddress().
//
//  ===================== why the gate is read per call =====================
//
//  A rewritten slot cannot be un-rewritten. "Off" therefore means "call the real
//  function with the same arguments", i.e. the same behaviour plus one frame. A
//  switch that silently keeps working after being turned off is worse than no
//  switch.
//

#import "GNCloudKitSymbolQuarantine.h"
#import "GNUnlock.h"
#import "GNBeacon.h"
#import "GNFunctionStarts.h"

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// <mach-o/loader.h> has carried this since the 10.x SDKs; the fallback exists so
// a stub SDK without it cannot silently change which command is being looked for.
#ifndef LC_FUNCTION_STARTS
#define LC_FUNCTION_STARTS 0x26
#endif

#pragma mark - The two entries

enum { GN_SYMBOL_COUNT = 2 };

typedef struct {
    const char *label;        ///< the name the backtrace used, for the log
    const char *symbol;       ///< the C name to hand dlsym (no leading underscore)
    const char *configKey;    ///< the plist offset key, same spelling as label
    void       *replacement;

    void       *real;         ///< resolved entry point, or NULL
    uintptr_t   target;       ///< entry address with any PAC stripped, or 0
    BOOL        enabled;      ///< its own switch, read once
    BOOL        resolved;
    const char *via;          ///< "dlsym" / "offset(interior)" / "offset(entry)"
    int32_t     matched;      ///< slots that held the address
    int32_t     rewritten;    ///< slots actually redirected
} GNSymbolEntry;

static GNSymbolEntry gEntries[GN_SYMBOL_COUNT];

#pragma mark - State

static volatile int32_t gSymbolHits     = 0;
static volatile int32_t gSymbolLogs     = 0;
static int32_t          gSymbolLogBudget = 8;

/// Every switch starts closed: this file is reached from the constructor, and a
/// default of YES here would mean two rewrites nobody asked for if the config
/// ever failed to load.
static BOOL gGate              = NO;    // CloudKitSymbolQuarantine
static BOOL gRebind            = NO;    // CloudKitSymbolRebind
static bool gMainBundleAnswer  = true;  // what entry 2 answers

/// Set when the offset path had no usable image or command, so the log can say
/// which of the two things was missing instead of "unresolved".
static const char *gOffsetProblem = NULL;

#pragma mark - Logging

static void GNSymbolSay(const char *fmt, ...) __attribute__((format(__printf__, 1, 2)));

static void GNSymbolSay(const char *fmt, ...) {
    if (__sync_add_and_fetch(&gSymbolLogs, 1) > gSymbolLogBudget) return;

    va_list args;
    va_start(args, fmt);
    char text[640];
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);
    GNBeaconLine("symbol-quarantine: %s", text);
}

#pragma mark - Replacements (declared first: the entry table names them)

static void *GNCloudKitPersonaLaunchReplaced(void);
static bool GNCloudKitMainBundleIsAppleReplaced(void);

#pragma mark - Step 1: is it exported at all

/// dlsym, three ways. The two fallbacks exist because they fail differently:
///
///   RTLD_DEFAULT   the global scope - what an ordinary cross-image bind uses
///   RTLD_NEXT      this dylib's own predecessor in the search order, in case a
///                  framework re-exports the name
///   RTLD_NOLOAD    a handle on CloudKit itself. It does not load anything; if
///                  the image is not already resident the call answers NULL, and
///                  a framework that has not been loaded has nothing to intercept
///                  anyway.
///
/// A symbol that is absent from the framework's .tbd is normally absent from all
/// three, which is exactly what v24's link error said one stage earlier. Logging
/// the attempt is what keeps "not exported" from being confused with "we did not
/// look".
static void *GNLookupExported(const char *name, const char **viaOut) {
    if (viaOut) *viaOut = NULL;
    if (!name || !*name) return NULL;

    void *found = dlsym(RTLD_DEFAULT, name);
    if (found) {
        if (viaOut) *viaOut = "dlsym(RTLD_DEFAULT)";
        return found;
    }

    found = dlsym(RTLD_NEXT, name);
    if (found) {
        if (viaOut) *viaOut = "dlsym(RTLD_NEXT)";
        return found;
    }

    // Both spellings: dlopen accepts a leaf name for a framework already in the
    // process, and the path form covers the case where it does not.
    void *handle = dlopen("CloudKit", RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) {
        handle = dlopen("/System/Library/Frameworks/CloudKit.framework/CloudKit",
                        RTLD_LAZY | RTLD_NOLOAD);
    }
    if (handle) {
        found = dlsym(handle, name);
        if (found) {
            if (viaOut) *viaOut = "dlsym(CloudKit handle)";
            return found;
        }
    }

    return NULL;
}

#pragma mark - Step 2: the offset the crash log prints

/// Strict hex: optional 0x, hex digits only, no sign, no suffix, not zero.
///
/// A permissive parser here is a rewritten slot pointing at nothing. "592" with
/// a stray quote, "592 " with a trailing space from a copy-paste, "0" from an
/// empty field - all of them have to be refused, and refused loudly.
static BOOL GNParseHexOffset(NSString *text, uint64_t *out) {
    if (out) *out = 0;
    if (![text isKindOfClass:[NSString class]]) return NO;
    if (text.length == 0 || text.length > 18) return NO;

    const char *raw = [text UTF8String];
    if (!raw) return NO;

    const char *p = raw;
    while (*p == ' ' || *p == '\t') p++;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    if (!*p) return NO;

    for (const char *q = p; *q; q++) {
        if (!isxdigit((unsigned char)*q)) return NO;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(p, &end, 16);
    if (errno == ERANGE || !end || *end != '\0') return NO;
    if (value == 0) return NO;

    if (out) *out = (uint64_t)value;
    return YES;
}

/// Turns an image-relative offset into the entry address of the function that
/// contains it, using the image's own LC_FUNCTION_STARTS list.
///
/// `imageOffset` is what the crash log gives: frame address minus the binary's
/// load address. `*absoluteOut` comes back already slid, ready for the slot walk.
static BOOL GNImageFunctionStart(const struct mach_header_64 *header, intptr_t slide,
                                 uint64_t imageOffset, uint64_t *absoluteOut,
                                 const char **whyOut) {
    if (absoluteOut) *absoluteOut = 0;
    if (whyOut) *whyOut = NULL;

    if (!header || header->magic != MH_MAGIC_64) {
        if (whyOut) *whyOut = "the image is not a 64 bit Mach-O";
        return NO;
    }

    const uint8_t *base = (const uint8_t *)header;
    uint64_t commandsEnd = sizeof(*header) + (uint64_t)header->sizeofcmds;

    uint64_t textVMAddr = 0;
    BOOL haveText = NO;
    uint32_t startsFileOffset = 0;
    uint32_t startsSize = 0;
    BOOL haveStarts = NO;

    uint64_t offset = sizeof(*header);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (offset + sizeof(struct load_command) > commandsEnd) break;

        const struct load_command *command = (const struct load_command *)(base + offset);
        if (command->cmdsize < sizeof(struct load_command) ||
            offset + command->cmdsize > commandsEnd) break;

        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, "__TEXT", sizeof(segment->segname)) == 0) {
                textVMAddr = segment->vmaddr;
                haveText = YES;
            }
        } else if (command->cmd == LC_FUNCTION_STARTS &&
                   command->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *data =
                (const struct linkedit_data_command *)command;
            startsFileOffset = data->dataoff;
            startsSize = data->datasize;
            haveStarts = YES;
        }

        offset += command->cmdsize;
    }

    if (!haveText) {
        if (whyOut) *whyOut = "the image has no __TEXT segment";
        return NO;
    }
    if (!haveStarts || startsSize == 0) {
        if (whyOut) *whyOut = "the image has no LC_FUNCTION_STARTS, so an interior offset "
                              "cannot be turned into an entry - set "
                              "CloudKitSymbolOffsetKind to entry and give the entry offset";
        return NO;
    }

    // dataoff is a *file* offset. Map it through the segment table rather than
    // treating it as a memory offset: that shortcut is only valid when a segment
    // happens to have vmaddr == fileoff, and it is how the v9 walker read a
    // string table out of the wrong place. Each segment's content is contiguous
    // in both spaces, so "fileoff - segment.fileoff + segment.vmaddr" is right
    // for a standalone binary and for a shared-cache image alike.
    const uint8_t *starts = NULL;

    // Same walk again, now looking for the segment that contains dataoff.
    offset = sizeof(*header);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (offset + sizeof(struct load_command) > commandsEnd) break;

        const struct load_command *command = (const struct load_command *)(base + offset);
        if (command->cmdsize < sizeof(struct load_command) ||
            offset + command->cmdsize > commandsEnd) break;

        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            uint64_t end = segment->fileoff + segment->filesize;
            if ((uint64_t)startsFileOffset >= segment->fileoff &&
                (uint64_t)startsFileOffset < end) {
                uint64_t address = (uint64_t)slide + segment->vmaddr +
                                   ((uint64_t)startsFileOffset - segment->fileoff);
                if (!GNRangeIsReadable((uintptr_t)address, (size_t)startsSize)) {
                    if (whyOut) *whyOut = "LC_FUNCTION_STARTS points at memory that is not "
                                          "readable in this process";
                    return NO;
                }
                starts = (const uint8_t *)(uintptr_t)address;
                break;
            }
        }

        offset += command->cmdsize;
    }

    if (!starts) {
        if (whyOut) *whyOut = "LC_FUNCTION_STARTS is not inside any mapped segment";
        return NO;
    }

    uint64_t textAddress = (uint64_t)slide + textVMAddr;
    uint64_t target = textAddress + imageOffset;
    uint64_t start = 0;
    uint32_t walked = 0;

    if (!GNFSFindFunction(starts, (size_t)startsSize, textAddress, target, &start, &walked)) {
        if (whyOut) *whyOut = "no function start at or below that offset";
        return NO;
    }

    if (absoluteOut) *absoluteOut = start;
    return YES;
}

#pragma mark - Resolution state

/// The image an offset is relative to, as a C string: the deferred path runs
/// from a dyld callback, and an NSString captured there would be an object whose
/// pool nobody owns.
static char     gImageName[64];
static BOOL     gInteriorKind = YES;
static BOOL     gHavePending[GN_SYMBOL_COUNT];
static uint64_t gPendingOffset[GN_SYMBOL_COUNT];
static BOOL     gDeferredArmed = NO;

static void GNApplyEntry(GNSymbolEntry *entry);
static void GNOnImageLoaded(const struct mach_header *header, intptr_t slide);

#pragma mark - Resolution

/// Fills in `real`, `target` and `via` for one entry, or explains why it could
/// not. Nothing here writes memory.
///
/// The offset path needs the image loaded: a number relative to CloudKit's load
/// address is meaningless before CloudKit is in the process. GoodNotes links
/// CloudKit lazily, so at constructor time it usually is *not*, and the honest
/// answer is "not yet" rather than "unresolved" - the entry stays open and the
/// dyld add-image callback finishes the job.
static void GNResolveEntry(GNSymbolEntry *entry, int32_t index) {
    if (!entry) return;

    // -- 1. exported? ------------------------------------------------------
    const char *via = NULL;
    void *exported = GNLookupExported(entry->symbol, &via);
    if (exported && exported != entry->replacement) {
        entry->real = exported;
        entry->target = GNSlotStripAddress((uintptr_t)exported);
        entry->via = via;
        entry->resolved = YES;
        GNSymbolSay("%s: exported (%p via %s)", entry->label, exported, via);
        return;
    }
    if (exported && exported == entry->replacement) {
        // dyld applies interpose tables to dlsym results too, so a lookup can
        // answer with this file's own replacement. Accepting it would recurse.
        GNSymbolSay("%s: dlsym answered this dylib's own replacement - refused", entry->label);
    }

    GNSymbolSay("%s: is not exported by any image in this process (RTLD_DEFAULT, RTLD_NEXT "
                "and a CloudKit handle all answered NULL)", entry->label);

    // -- 2. the offset from the log ---------------------------------------
    if (index < 0 || index >= GN_SYMBOL_COUNT || !gHavePending[index]) {
        GNSymbolSay("%s: no CloudKitSymbolOffsets entry, so there is no address to rewrite. "
                    "Copy the number the crash log prints after this name (the '+ 592' part) "
                    "into that key to try the slot path", entry->label);
        return;
    }

    int imageIndex = GNImageIndexForName(gImageName);
    if (imageIndex < 0) {
        GNSymbolSay("%s: '%s' is not loaded yet, and the offset is relative to it. Resolution "
                    "moves to the add-image callback - the crash this targets happens inside "
                    "that framework's own initialisation, so being early is expected",
                    entry->label, gImageName);
        if (!gDeferredArmed) {
            gDeferredArmed = YES;
            _dyld_register_func_for_add_image(GNOnImageLoaded);
            GNSymbolSay("waiting for '%s' to load; %d slot walk(s) will run when it does",
                        gImageName, (int)GN_SYMBOL_COUNT);
        }
        return;
    }

    intptr_t slide = GNImageSlide(gImageName);
    uintptr_t base = GNImageBase(gImageName);
    if (!base) {
        GNSymbolSay("%s: '%s' has no load address", entry->label, gImageName);
        return;
    }

    uint64_t value = gPendingOffset[index];
    uint64_t absolute = 0;
    BOOL asEntry = !gInteriorKind;

    if (gInteriorKind) {
        const struct mach_header_64 *header =
            (const struct mach_header_64 *)_dyld_get_image_header((uint32_t)imageIndex);
        const char *why = NULL;
        if (GNImageFunctionStart(header, slide, value, &absolute, &why)) {
            entry->via = "offset(interior)";
            GNSymbolSay("%s: offset 0x%llx (interior) -> entry %p, %llu byte(s) into the function "
                        "per LC_FUNCTION_STARTS", entry->label, (unsigned long long)value,
                        (void *)(uintptr_t)absolute,
                        (unsigned long long)((uint64_t)base + value - absolute));
        } else {
            // v27: a number relative to an image base has exactly two readings, and
            // the crash log does not say which one it printed. Rather than spend a
            // launch on "the kind was wrong", use the other reading: a number that
            // already is an entry survives this unchanged, and a number that is not
            // an entry resolves to an address the slot walk simply does not match,
            // which writes nothing. The line names which reading answered.
            gOffsetProblem = why;
            asEntry = YES;
            GNSymbolSay("%s: offset 0x%llx is interior, and the entry it belongs to could not "
                        "be found (%s) - reading the same number as an entry instead",
                        entry->label, (unsigned long long)value, why ? why : "unknown");
        }
    }

    if (asEntry) {
        absolute = (uint64_t)base + value;
        entry->via = gInteriorKind ? "offset(entry-fallback)" : "offset(entry)";
        GNSymbolSay("%s: offset 0x%llx (%s) -> %p in '%s'", entry->label,
                    (unsigned long long)value,
                    gInteriorKind ? "entry, fallback" : "entry",
                    (void *)(uintptr_t)absolute, gImageName);
    }

    entry->target = GNSlotStripAddress((uintptr_t)absolute);
    entry->resolved = YES;
}

/// dyld's add-image callback: the image an offset is relative to just arrived.
///
/// dyld replays this for every image already in the process at registration, so
/// the body has to be cheap for the ones that do not match. It resolves only for
/// the configured image, only once, and only the entries that are still open.
static void GNOnImageLoaded(const struct mach_header *header, intptr_t slide) {
    if (!gDeferredArmed || !header) return;

    const char *path = NULL;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) == header) {
            path = _dyld_get_image_name(i);
            break;
        }
    }
    if (!path) return;

    const char *base = strrchr(path, '/');
    const char *leaf = base ? base + 1 : path;
    if (strncmp(leaf, gImageName, sizeof(gImageName)) != 0) return;

    GNSymbolSay("%s loaded (%s) - resolving the entries that were waiting for it",
                gImageName, path);

    (void)slide;
    for (int32_t i = 0; i < GN_SYMBOL_COUNT; i++) {
        GNSymbolEntry *entry = &gEntries[i];
        if (entry->resolved) continue;
        GNResolveEntry(entry, i);
        if (entry->resolved) GNApplyEntry(entry);
    }
}

#pragma mark - Acting on a resolved address

/// Probe, then rewrite. Called once per entry: at install for the entries that
/// resolved immediately, from the add-image callback for the ones that had to
/// wait for the framework.
static void GNApplyEntry(GNSymbolEntry *entry) {
    if (!entry) return;

    if (!entry->resolved || !entry->target) {
        GNSymbolSay("%s: no address, so no slot can be matched. A call made inside the "
                    "CloudKit image to its own function is a direct branch either way - the "
                    "throw-level swallow is the layer that can still act on it", entry->label);
        return;
    }

    if (!entry->enabled) {
        GNSymbolSay("%s: resolved to %p but this entry is switched off - it passes through to "
                    "the real function", entry->label, (void *)entry->target);
        return;
    }

    // Measure first, always: the count is the difference between "no caller goes
    // through a slot" and "we never looked", and it is reported even when
    // rewriting is off.
    int32_t matched = 0;
    int32_t sections = GNSlotProbeAddress(entry->target, &matched);
    entry->matched = matched;

    if (!gRebind) {
        GNSymbolSay("%s: %d slot(s) in %d import slot section(s) hold %p; rewriting is off, so "
                    "nothing was written", entry->label, (int)matched, (int)sections,
                    (void *)entry->target);
        return;
    }

    int32_t written = 0;
    GNSlotRebindAddress(entry->label, entry->target, entry->replacement, YES, &written);
    entry->rewritten = written;

    if (written > 0) {
        GNSymbolSay("%s: %d slot(s) redirected to this dylib's replacement - a call that went "
                    "through one of them now answers here", entry->label, (int)written);
    } else {
        GNSymbolSay("%s: %d slot(s) hold the address and none could be redirected - every "
                    "caller reaches it by direct branch inside its own image, which no "
                    "data-only mechanism can rewrite. The throw-level swallow is the remaining "
                    "layer", entry->label, (int)matched);
    }
}

#pragma mark - Replacements

/// CKPersona.launch: the getter answers nil.
///
/// nil is the value that says "there is no persona", which is the state a device
/// with no iCloud account is in - the same state the CloudKit substitute answers
/// with. It is not a fabricated object: it is the absence of one.
static void *GNCloudKitPersonaLaunchReplaced(void) {
    GNSymbolEntry *entry = &gEntries[0];

    if (!gGate || !entry->enabled) {
        if (!entry->real) {
            GNSymbolSay("pass-through requested for CKPersona.launch but no address was "
                        "resolved - answering nil, which is what a device with no account "
                        "answers");
            return NULL;
        }
        return ((void *(*)(void))entry->real)();
    }

    __sync_add_and_fetch(&gSymbolHits, 1);
    GNSymbolSay("reached: CKPersona.launch -> nil (the getter body, and whatever it throws "
                "from inside its dispatch_once, does not run)");
    return NULL;
}

/// CKMainBundleIsAppleExecutable: answers the configured bool.
///
/// This function decides whether CloudKit treats the main bundle as Apple's own
/// executable; Apple's binaries do not go through the provisioning entitlement
/// path, so answering true is what skips that path for this bundle. It is a bool,
/// one byte, and the caller compares it - there is no object to hand back and no
/// lifetime to get wrong.
static bool GNCloudKitMainBundleIsAppleReplaced(void) {
    GNSymbolEntry *entry = &gEntries[1];

    if (!gGate || !entry->enabled) {
        if (!entry->real) {
            GNSymbolSay("pass-through requested for CKMainBundleIsAppleExecutable but no "
                        "address was resolved - answering the configured value (%s)",
                        gMainBundleAnswer ? "true" : "false");
            return gMainBundleAnswer;
        }
        return ((bool (*)(void))entry->real)();
    }

    __sync_add_and_fetch(&gSymbolHits, 1);
    GNSymbolSay("reached: CKMainBundleIsAppleExecutable -> %s",
                gMainBundleAnswer ? "true" : "false");
    return gMainBundleAnswer;
}

#pragma mark - Public

int32_t GNCloudKitSymbolQuarantineCount(void) {
    return GN_SYMBOL_COUNT;
}

const char *GNCloudKitSymbolQuarantineName(int32_t index) {
    if (index < 0 || index >= GN_SYMBOL_COUNT) return "?";
    return gEntries[index].label ? gEntries[index].label : "?";
}

BOOL GNCloudKitSymbolQuarantineIsResolved(int32_t index) {
    if (index < 0 || index >= GN_SYMBOL_COUNT) return NO;
    return gEntries[index].resolved;
}

uintptr_t GNCloudKitSymbolQuarantineTarget(int32_t index) {
    if (index < 0 || index >= GN_SYMBOL_COUNT) return 0;
    return gEntries[index].target;
}

int32_t GNCloudKitSymbolQuarantineMatchCount(int32_t index) {
    if (index < 0 || index >= GN_SYMBOL_COUNT) return 0;
    return gEntries[index].matched;
}

int32_t GNCloudKitSymbolQuarantineRewriteCount(int32_t index) {
    if (index < 0 || index >= GN_SYMBOL_COUNT) return 0;
    return gEntries[index].rewritten;
}

int32_t GNCloudKitSymbolQuarantineHitCount(void) {
    return gSymbolHits;
}

void GNInstallCloudKitSymbolQuarantine(NSDictionary *cfg) {
    (void)cfg;

    gGate             = GNCFG(@"CloudKitSymbolQuarantine", YES);
    gRebind           = GNCFG(@"CloudKitSymbolRebind", YES);
    gMainBundleAnswer = GNCFG(@"CloudKitSymbolQuarantineMainBundleAnswer", YES) ? true : false;

    NSInteger budget = GNCGI(@"CloudKitSymbolQuarantineLogBudget", 16);
    gSymbolLogBudget = (int32_t)(budget > 0 ? budget : 0);

    NSString *imageName = GNCGS(@"CloudKitSymbolImage");
    if (![imageName isKindOfClass:[NSString class]] || imageName.length == 0) {
        imageName = @"CloudKit";
    }
    const char *imageLeaf = [imageName UTF8String];
    memset(gImageName, 0, sizeof(gImageName));
    if (imageLeaf) snprintf(gImageName, sizeof(gImageName), "%s", imageLeaf);

    NSString *kind = GNCGS(@"CloudKitSymbolOffsetKind");
    gInteriorKind = YES;
    if ([kind isKindOfClass:[NSString class]] && kind.length > 0) {
        gInteriorKind = ([kind caseInsensitiveCompare:@"entry"] != NSOrderedSame);
        if (gInteriorKind && [kind caseInsensitiveCompare:@"interior"] != NSOrderedSame) {
            GNSymbolSay("CloudKitSymbolOffsetKind='%s' is not interior/entry - reading it as "
                        "interior, which is what a crash log gives", [kind UTF8String]);
        }
    }

    NSDictionary *offsets = GNCFGDict(@"CloudKitSymbolOffsets");
    if (![offsets isKindOfClass:[NSDictionary class]]) offsets = nil;

    memset(gEntries, 0, sizeof(gEntries));
    memset(gHavePending, 0, sizeof(gHavePending));
    memset(gPendingOffset, 0, sizeof(gPendingOffset));

    gEntries[0] = (GNSymbolEntry){
        .label = "CKPersona.launch",
        .symbol = "$sSo9CKPersonaC8CloudKitE6launchABSgvgZ",
        .configKey = "CKPersona.launch",
        .replacement = (void *)&GNCloudKitPersonaLaunchReplaced,
        .enabled = GNCFG(@"CloudKitSymbolQuarantinePersonaLaunch", YES),
    };
    gEntries[1] = (GNSymbolEntry){
        .label = "CKMainBundleIsAppleExecutable",
        .symbol = "CKMainBundleIsAppleExecutable",
        .configKey = "CKMainBundleIsAppleExecutable",
        .replacement = (void *)&GNCloudKitMainBundleIsAppleReplaced,
        .enabled = GNCFG(@"CloudKitSymbolQuarantineMainBundleIsApple", YES),
    };

    // Parse every configured offset once, up front: a value that is not strictly
    // hex is refused here, with the key named, instead of at the moment a slot is
    // about to be written.
    for (int32_t i = 0; i < GN_SYMBOL_COUNT; i++) {
        NSString *key = [NSString stringWithUTF8String:gEntries[i].configKey];
        id raw = key ? [offsets objectForKey:key] : nil;
        if (!raw) continue;

        uint64_t value = 0;
        if (!GNParseHexOffset(raw, &value)) {
            GNSymbolSay("%s: CloudKitSymbolOffsets['%s'] is not a hex offset - refused, nothing "
                        "will be written for this entry", gEntries[i].label,
                        gEntries[i].configKey);
            continue;
        }
        gHavePending[i] = YES;
        gPendingOffset[i] = value;
    }

    GNSymbolSay("gate %s, slot rewriting %s, %d entr(y|ies), image '%s', offsets %s",
                gGate ? "ON" : "OFF (pass-through)",
                gRebind ? "ON" : "OFF (measure only)",
                (int)GNCloudKitSymbolQuarantineCount(), gImageName,
                gInteriorKind ? "interior" : "entry");

    if (!gGate) {
        GNSymbolSay("gate OFF - both replacements call the real functions with the same "
                    "arguments and no slot is rewritten");
        return;
    }

    for (int32_t i = 0; i < GN_SYMBOL_COUNT; i++) {
        GNResolveEntry(&gEntries[i], i);
        GNApplyEntry(&gEntries[i]);
    }

    if (gOffsetProblem) {
        GNSymbolSay("offset note: %s", gOffsetProblem);
    }
}
