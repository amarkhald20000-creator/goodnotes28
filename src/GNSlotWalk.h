//
//  GNSlotWalk.h
//  The import-slot rebinder, with every Apple header removed.
//
//  Why this is a header and not part of a .m
//  -----------------------------------------
//  This is the only new mechanism in v16 that can be *executed* before it is
//  trusted: the decision "does this 8 byte slot hold the symbol I am after, and
//  what may I store instead" is pure arithmetic over a memory range. Keeping it
//  free of Foundation, of <mach-o/loader.h> and of Darwin-only calls means
//  scripts/slotwalk_test.c can compile this exact source for the host and run it
//  against synthetic images - the same trick scripts/experiment_ladder_test.c
//  uses for the experiment ladder. Everything Darwin specific (vm_protect,
//  pointer authentication, dyld) stays in src/GNSlotScan.m and src/GNRebind.m.
//
//  The problem this solves
//  -----------------------
//  v15 asked dyld to interpose SecTaskCopyValueForEntitlement for the whole
//  process. The interpose table is applied to *bindings*, and a binding is a
//  data slot. If the caller reaches the function through a direct branch there
//  is no binding to rewrite and the interpose cannot fire. The remaining
//  data-only option - the one fishhook implements - is to rewrite the slot
//  itself. fishhook cannot do it here for two reasons that are structural rather
//  than bugs:
//
//    * it finds a slot by *name*, from the classic symbol table and the indirect
//      symbol table. The dyld shared cache strips both, so every system image
//      reports zero symbols and nothing is ever found;
//    * on arm64e the slot holds an authenticated pointer, signed over the
//      identity of that slot. Storing a plain address there does not fail at
//      the write, it fails at the next call - EXC_BAD_ACCESS in a place that
//      looks nothing like the hook.
//
//  Both are solvable without a symbol name and without guessing: walk the
//  section table (which the cache does keep), and identify a slot by *what it
//  points at* rather than by what it is called. Then prove the signature by
//  reproducing the bytes already in the slot before writing anything - see
//  GNSlotMoveTo in src/GNRebind.m. A slot that cannot be reproduced byte for
//  byte is left exactly as it was.
//
//  Hardware-neutral by construction: the structs below are the on-disk Mach-O
//  layouts, spelled out here so this file compiles on Linux, on Windows and on
//  Darwin alike, and so a test can build a synthetic image without a parser.
//
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma mark - The three structures this walk needs

enum {
    GNW_MH_MAGIC_64   = 0xfeedfacf,
    GNW_LC_SEGMENT_64 = 0x00000019,
    /// A section table wider than this is not a section table. The number is
    /// the same order as the largest real __TEXT (a few hundred sections) and
    /// it exists so a corrupt nsects cannot make this walk read a gigabyte.
    GNW_MAX_SECTIONS  = 4096,
    /// Import tables are small. 8 MB of slots is more than any real image has,
    /// and the cap means a bogus section size cannot turn into a long loop
    /// during dyld initialisation.
    GNW_MAX_SLOT_BYTES = 8u << 20,
};

typedef struct {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} GNWImageHeader;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
} GNWSegmentCommand;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} GNWSection;

#pragma mark - Which sections hold import slots

/// The four section kinds that hold a resolved function address, nothing else.
///
///   __got             non-lazy symbol pointer, plain
///   __auth_got        non-lazy symbol pointer, arm64e authenticated
///   __la_symbol_ptr   lazy symbol pointer, plain
///   __nl_symbol_ptr   non-lazy symbol pointer, plain
///
/// Deliberately NOT included: __const / __auth_const / __objc_* / __cfstring.
/// Those can contain a function pointer too, but they are not call sites: the
/// value there is data the program reads, and rewriting it would change what the
/// app *sees* rather than where a call goes.
static inline bool GNWIsImportSlotSection(const char *name) {
    static const char *const kinds[] = {
        "__got", "__auth_got", "__la_symbol_ptr", "__nl_symbol_ptr",
    };
    if (!name) return false;
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        const char *kind = kinds[i];
        size_t length = strlen(kind);
        if (memcmp(name, kind, length) == 0 && name[length] == '\0') return true;
    }
    return false;
}

#pragma mark - Walking one image

typedef struct {
    uint64_t address;        ///< already slid
    uint64_t size;
    char     sectname[17];   ///< NUL terminated copy, for the log
    char     segname[17];
} GNWSlotSection;

/// Return false to stop the walk (the caller hit its own budget).
typedef bool (*GNWSectionVisitor)(void *ctx, const GNWSlotSection *section);

typedef struct {
    uint32_t segments;
    uint32_t sections;
    uint32_t slotSections;
    uint32_t truncated;      ///< a load command or section table ran past `readable`
} GNWWalkStats;

/// Walks the section table of one already-slid Mach-O image and hands every
/// import-slot section to `visit`.
///
/// `readable` is how many bytes starting at `image` are known to be mapped and
/// readable. Everything is checked against it: this runs during dyld
/// initialisation, where a bad read is a launch failure with no log line, and a
/// system image whose load commands have been trimmed is exactly the case that
/// makes `hdr + 1` unsafe.
///
/// The walk never reads a slot - it only reports ranges. Reading, matching and
/// writing belong to GNWRebindSlotRange, so that the two can be tested
/// separately.
static inline uint32_t GNWWalkImage(const void *image, uint64_t readable, uint64_t slide,
                                    GNWSectionVisitor visit, void *ctx,
                                    GNWWalkStats *stats) {
    if (stats) {
        stats->segments = 0;
        stats->sections = 0;
        stats->slotSections = 0;
        stats->truncated = 0;
    }
    if (!image || readable < sizeof(GNWImageHeader)) {
        if (stats) stats->truncated++;
        return 0;
    }

    const GNWImageHeader *header = (const GNWImageHeader *)image;
    if (header->magic != GNW_MH_MAGIC_64) return 0;

    const uint8_t *base = (const uint8_t *)image;
    uint64_t commandsEnd = sizeof(GNWImageHeader) + (uint64_t)header->sizeofcmds;
    if (commandsEnd > readable) {
        if (stats) stats->truncated++;
        commandsEnd = readable;
    }

    uint64_t offset = sizeof(GNWImageHeader);
    for (uint32_t index = 0; index < header->ncmds; index++) {
        // cmd + cmdsize are the only fields that can be read before the size is
        // known, so they are the only fields read before the bounds check.
        if (offset + sizeof(uint32_t) * 2 > commandsEnd) {
            if (stats) stats->truncated++;
            break;
        }

        const GNWSegmentCommand *command = (const GNWSegmentCommand *)(base + offset);
        uint32_t commandSize = command->cmdsize;
        if (commandSize < sizeof(uint32_t) * 2 || offset + commandSize > commandsEnd) {
            if (stats) stats->truncated++;
            break;
        }

        if (command->cmd == GNW_LC_SEGMENT_64) {
            if (stats) stats->segments++;

            uint32_t count = command->nsects;
            if (commandSize < sizeof(GNWSegmentCommand)) {
                if (stats) stats->truncated++;
            } else if (count > GNW_MAX_SECTIONS ||
                       sizeof(GNWSegmentCommand) + (uint64_t)count * sizeof(GNWSection) > commandSize) {
                // nsects disagrees with cmdsize. Trust cmdsize, not nsects.
                if (stats) stats->truncated++;
            } else {
                for (uint32_t i = 0; i < count; i++) {
                    const GNWSection *section =
                        (const GNWSection *)((const uint8_t *)command + sizeof(GNWSegmentCommand) +
                                             (size_t)i * sizeof(GNWSection));
                    if (stats) stats->sections++;

                    if (!GNWIsImportSlotSection(section->sectname)) continue;

                    GNWSlotSection found;
                    found.address = slide + section->addr;
                    found.size = section->size;
                    memset(found.sectname, 0, sizeof(found.sectname));
                    memset(found.segname, 0, sizeof(found.segname));
                    memcpy(found.sectname, section->sectname, sizeof(section->sectname));
                    memcpy(found.segname, section->segname, sizeof(section->segname));

                    if (stats) stats->slotSections++;
                    if (visit && !visit(ctx, &found)) return stats ? stats->slotSections : 0;
                }
            }
        }

        offset += commandSize;
    }

    return stats ? stats->slotSections : 0;
}

#pragma mark - Rewriting one range

/// Everything the range walker is not allowed to know: how to touch memory, how
/// to recognise the target, and how to produce the value that replaces it.
///
/// `moveTo` returning 0 means "refuse this slot". That is the single most
/// important property of this design: a slot whose existing contents cannot be
/// reproduced byte for byte is never written, because a wrong guess there is not
/// a missed hook, it is the next call into that slot faulting.
typedef struct {
    bool     (*read)(void *ctx, uint64_t address, uint64_t *out);
    bool     (*write)(void *ctx, uint64_t address, uint64_t value);
    bool     (*refersTo)(void *ctx, uint64_t raw, uint64_t target);
    uint64_t (*moveTo)(void *ctx, uint64_t raw, uint64_t target,
                       uint64_t replacement, uint64_t slotAddress);
    void     *ctx;
} GNSlotOps;

typedef struct {
    uint64_t scanned;
    uint64_t matched;       ///< slots that hold `target`
    uint64_t written;
    uint64_t refused;       ///< matched, but the signature could not be proven
    uint64_t unreadable;
    uint64_t irrelevant;    ///< slots holding something else
} GNSlotStats;

/// Visits every 8 byte entry in [address, address+size) and rewrites the ones
/// that refer to `target`. Everything else is left untouched, including a
/// matched slot whose replacement value cannot be produced.
static inline GNSlotStats GNWRebindSlotRange(uint64_t address, uint64_t size,
                                             uint64_t target, uint64_t replacement,
                                             const GNSlotOps *ops) {
    GNSlotStats stats;
    memset(&stats, 0, sizeof(stats));

    if (!ops || !ops->read || !ops->write || !ops->refersTo || !ops->moveTo) return stats;
    if (!address || size < sizeof(uint64_t)) return stats;

    uint64_t bytes = size;
    if (bytes > (uint64_t)GNW_MAX_SLOT_BYTES) bytes = (uint64_t)GNW_MAX_SLOT_BYTES;
    uint64_t count = bytes / sizeof(uint64_t);
    if (count == 0) return stats;

    for (uint64_t i = 0; i < count; i++) {
        uint64_t slot = address + i * sizeof(uint64_t);
        uint64_t raw = 0;

        if (!ops->read(ops->ctx, slot, &raw)) {
            stats.unreadable++;
            continue;
        }
        stats.scanned++;

        if (!ops->refersTo(ops->ctx, raw, target)) {
            stats.irrelevant++;
            continue;
        }
        stats.matched++;

        uint64_t value = ops->moveTo(ops->ctx, raw, target, replacement, slot);
        if (value == 0) {
            stats.refused++;
            continue;
        }
        if (value == raw) continue;             // already the replacement

        if (ops->write(ops->ctx, slot, value)) stats.written++;
        else stats.refused++;
    }

    return stats;
}

#ifdef __cplusplus
}
#endif
