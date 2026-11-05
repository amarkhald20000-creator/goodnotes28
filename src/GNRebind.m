//
//  GNRebind.m
//  Intercept a C function without writing a single executable byte.
//
//  The problem
//  -----------
//  `dlsym(RTLD_DEFAULT, "SecItemCopyMatching")` hands back the address of the
//  function inside Security.framework, which lives in a code signed image (the
//  dyld shared cache). Overwriting the first instruction there - the classic
//  inline hook - makes the kernel copy that page, and the next instruction
//  fetch from the copy kills the process. On a Distribution certificate this is
//  not a maybe, it is a certainty.
//
//  The fix
//  -------
//  Don't touch the framework. Touch the caller.
//
//  Every call from the app into a framework goes through an import slot: an
//  8 byte pointer in the app's own __got / __auth_got / __la_symbol_ptr. Those
//  slots live in __DATA_CONST / __DATA - data pages, checked by the kernel for
//  write permission but never for a code signature. Rewriting one is a plain
//  memory write, and it redirects exactly the calls we care about: the app's.
//
//  Two formats have to be handled:
//
//    * images built with chained fixups (LC_DYLD_CHAINED_FIXUPS, everything
//      modern): the slots are encoded as a linked list, each pointer carrying
//      the offset of the next one. We walk the chains, decode the bind entries,
//      map the ordinal to a symbol name, and rewrite the ones that match.
//
//    * images built the old way (LC_DYSYMTAB indirect symbol table): the slot
//      index maps straight into the symbol table. Much simpler.
//
//  Safety
//  ------
//  Nothing is written unless the slot currently holds the address that dlsym()
//  returned for that symbol. If our decode is off by a bit, the value will not
//  match, we skip, we log, and the app keeps running. Worst case is a no-op -
//  never a corrupted table.
//
//  What v10 fixed, and why it crashed
//  ---------------------------------
//  v9 died with SIGBUS / KERN_PROTECTION_FAILURE inside strcmp, called from
//  GNRebindSymbolInAppImages during dyld initialisation. Reading the decoder
//  against Apple's <mach-o/fixup-chains.h> turned up four separate defects:
//
//    1. Import table stride. The three dyld_chained_import* formats do not
//       share an entry size (4, 4 and 8 bytes). v9 advanced by 8 and 16 for
//       formats 2 and 3, so it read the *addend array* - or the neighbouring
//       entry - as if it were an import. Whatever came back was used as a
//       string offset, so `symbols + offset` pointed outside the string pool
//       and strcmp walked off the end of the mapping. That is the SIGBUS.
//
//    2. Classic symbol table base. `hdr + symtab->stroff` treats a *file
//       offset* as a memory offset. That is only true when __LINKEDIT happens
//       to be laid out with vmaddr == fileoff, and `n_un.n_strx` was never
//       checked against strsize at all, so a single bad index was enough.
//
//    3. No bounds checking before a comparison. Every name went straight into
//       strcmp. Unbounded by construction: strcmp stops at a NUL that may not
//       be in this mapping.
//
//    4. It ran when it was not supposed to. GNInstallLaunchGuard() called this
//       directly for the abort()/exit() tracer, bypassing EnableGOTRebinding -
//       so the "off by default" switch never applied to the one caller that
//       runs in the dylib's constructor.
//
//  v10 answers each of those with structure rather than a guard clause:
//
//    * GNImportEntrySize() is the single source of truth for the stride, and
//      GNImportSymbolName() refuses any offset that does not fit inside the
//      blob it came from.
//    * Every base pointer comes from GNFileOffsetToAddress(), which maps a file
//      offset through the segment table and verifies the result is actually
//      mapped and readable.
//    * Every string comparison goes through GNReadableCStringEquals(), which
//      finds the terminator inside the readable run before comparing a byte.
//    * This function refuses to walk anything unless EnableGOTRebinding is on,
//      and the launch guard no longer calls it from the constructor.
//

#import "GNUnlock.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/vm_map.h>
#import <dlfcn.h>
#import <string.h>
#import <stdio.h>
#import <stdlib.h>

#if __has_include(<ptrauth.h>)
#import <ptrauth.h>
#define GN_HAVE_PTRAUTH 1
#endif

// Only clang has __has_feature. The guards further down test it directly, and
// a preprocessor expression has to be evaluable on every front end, so give
// anything that is not clang a zero.
#ifndef __has_feature
#define __has_feature(x) 0
#endif

// Apple's own layout for the chained fixup pointers, when the SDK ships it
// (Xcode 13 and later). Where the header exists, every field offset below comes
// from it rather than from memory; that is the whole point of including it.
#if __has_include(<mach-o/fixup-chains.h>)
#include <mach-o/fixup-chains.h>
#define GN_HAVE_FIXUP_CHAIN_STRUCTS 1
#endif

// Apple declares every dyld type as a bare struct tag - there is no typedef
// behind `dyld_chained_ptr_arm64e_auth_bind`, only `struct ...`. Naming it
// without the keyword is a hard front-end error, and it is one that only
// appears once the iOS SDK is on the include path, so no check that runs
// without a real SDK catches it:
//
//     error: must use 'struct' tag to refer to type
//            'dyld_chained_ptr_arm64e_auth_bind'
//
// The tag is therefore spelled exactly once, in the typedef below, and the
// decoder names GNAuthBindPtr. If a tag ever comes back at a call site the
// build and CI now fail on purpose (see the dyld tag guard in build.sh).
#ifdef GN_HAVE_FIXUP_CHAIN_STRUCTS
typedef struct dyld_chained_ptr_arm64e_auth_bind GNAuthBindPtr;
#else
// The same declaration, field for field, for SDKs that predate the header -
// transcribed from <mach-o/fixup-chains.h>:
//
//   dyld_chained_ptr_arm64e_auth_bind:
//     ordinal:16  zero:16  diversity:16  addrDiv:1  key:2  next:11
//     bind:1  auth:1
typedef struct {
    uint64_t ordinal   : 16;
    uint64_t zero      : 16;
    uint64_t diversity : 16;
    uint64_t addrDiv   : 1;
    uint64_t key       : 2;
    uint64_t next      : 11;
    uint64_t bind      : 1;
    uint64_t auth      : 1;
} GNAuthBindPtr;
#endif

// 64 bits either way. If a future SDK grows this struct the memcpy in
// GNDecodeChainedBind() would read past `raw`, so make that a compile error
// here rather than a stack read in the walker.
typedef char GNAuthBindPtrIsOneWord[(sizeof(GNAuthBindPtr) == sizeof(uint64_t)) ? 1 : -1];

#pragma mark - Chained fixups, declared locally

// The fixup headers are used where the SDK ships them; these local mirrors
// keep the file building against any SDK, and make the layout visible while
// reading the decoder.

#define GN_LC_DYLD_CHAINED_FIXUPS 0x80000034u

// Values from dyld_chained_starts_in_segment.pointer_format in
// <mach-o/fixup-chains.h>. The numbering has to match Apple's enum exactly:
// a segment that says 10 is ARM64E_FIRMWARE, which is laid out and strided
// differently from the userland chains, and walking it with the userland
// assumptions rewrites slots that belong to something else.
#define GN_PTR_ARM64E             1
#define GN_PTR_64                 2
#define GN_PTR_32                 3
#define GN_PTR_64_OFFSET          6
#define GN_PTR_ARM64E_KERNEL      7    // stride 4, unauth target is vm offset
#define GN_PTR_64_KERNEL_CACHE    8
#define GN_PTR_ARM64E_USERLAND    9    // stride 8, unauth target is vm offset
#define GN_PTR_ARM64E_FIRMWARE   10    // stride 4, unauth target is vmaddr
#define GN_X86_64_KERNEL_CACHE   11
#define GN_PTR_ARM64E_USERLAND24 12    // stride 8, 24 bit bind ordinals

#define GN_IMPORT              1
#define GN_IMPORT_ADDEND       2
#define GN_IMPORT_ADDEND64     3

#define GN_SYMBOLS_UNCOMPRESSED 0

#define GN_CHAINED_PTR_START_NONE  0xFFFF
#define GN_CHAINED_PTR_START_MULTI 0x8000

// Defined in <mach-o/loader.h> on every SDK we care about; repeated here so an
// older header cannot break the build.
#ifndef INDIRECT_SYMBOL_LOCAL
#define INDIRECT_SYMBOL_LOCAL 0x80000000u
#endif
#ifndef INDIRECT_SYMBOL_ABS
#define INDIRECT_SYMBOL_ABS   0x40000000u
#endif

// Import names are shorter than this everywhere; the cap exists so a corrupt
// offset cannot turn a comparison into a scan of an entire segment.
#define GN_MAX_SYMBOL_NAME 4096u

typedef struct {
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;
    uint32_t symbols_format;
} GNFixupsHeader;

typedef struct {
    uint32_t seg_count;
    /* uint32_t seg_info_offset[seg_count]; */
} GNStartsInImage;

typedef struct {
    uint32_t size;
    uint16_t page_size;
    uint16_t pointer_format;
    uint64_t segment_offset;
    uint16_t max_valid_pointer;
    uint16_t page_count;
    /* uint16_t page_start[page_count]; */
} GNStartsInSegment;

typedef enum {
    GNFamilyUnknown = 0,
    GNFamilyARM64E,
    GNFamily64,
} GNFamily;

typedef struct {
    uint32_t ordinal;
    uint32_t next;
    BOOL     auth;
    uint16_t key;
    uint16_t diversity;
    BOOL     addrDiv;
} GNBindEntry;

static GNFamily GNFamilyForFormat(uint16_t format) {
    switch (format) {
        case GN_PTR_ARM64E:
        case GN_PTR_ARM64E_KERNEL:
        case GN_PTR_ARM64E_USERLAND:
        case GN_PTR_ARM64E_FIRMWARE:
        case GN_PTR_ARM64E_USERLAND24:
            return GNFamilyARM64E;
        case GN_PTR_64:
        case GN_PTR_64_OFFSET:
        case GN_PTR_64_KERNEL_CACHE:
            return GNFamily64;
        default:
            return GNFamilyUnknown;
    }
}

/// Size of one step of the `next` field, in bytes. The field counts units of
/// the pointer size: 8 for arm64e userland chains, 4 for the 64 bit formats.
///
/// 0 means "this walker cannot vouch for that format". The arm64e kernel and
/// firmware formats are not laid out the way the code below assumes, and a
/// wrong stride does not fail loudly - it walks into whatever happens to sit
/// next and rewrites a slot that holds an unrelated pointer. Skipping is the
/// only honest answer for a format nobody here can test.
static uint32_t GNChainStride(uint16_t format) {
    switch (format) {
        case GN_PTR_ARM64E:
        case GN_PTR_ARM64E_USERLAND:
        case GN_PTR_ARM64E_USERLAND24:
            return 8;
        case GN_PTR_64:
        case GN_PTR_64_OFFSET:
            return 4;
        default:
            return 0;
    }
}

/// Bytes per entry in the imports table. The three formats do not share a
/// stride, which is defect 1 in the header of this file:
///
///   1  dyld_chained_import           4 bytes  (lib_ordinal:8  weak:1  name:23)
///   2  dyld_chained_import_addend    4 bytes  (64 addend array follows the table)
///   3  dyld_chained_import_addend64  8 bytes  (lib_ordinal:16 weak:1
///                                              reserved:15 name:32;
///                                              64 bit addend array follows)
///
/// The addend arrays are separate and only matter when the slot needs an
/// addend, which nothing here does - but they are why the entry size is not
/// "16 for the 64 bit format".
static uint32_t GNImportEntrySize(uint32_t format) {
    switch (format) {
        case GN_IMPORT:
        case GN_IMPORT_ADDEND:
            return 4;
        case GN_IMPORT_ADDEND64:
            return 8;
        default:
            return 0;
    }
}

/// Decodes one chained pointer. Returns NO for rebase entries, unsupported
/// formats and anything that does not carry the bind bit.
static BOOL GNDecodeChainedBind(uint64_t raw, uint16_t format, GNBindEntry *out) {
    GNFamily family = GNFamilyForFormat(format);
    if (family == GNFamilyUnknown) return NO;

    GNBindEntry entry;
    memset(&entry, 0, sizeof(entry));

    if (family == GNFamilyARM64E) {
        // bit 62: bind, bit 63: auth
        if (((raw >> 62) & 1u) == 0) return NO;
        entry.auth = ((raw >> 63) & 1u) != 0;

        uint32_t ordinalMask = (format == GN_PTR_ARM64E_USERLAND24) ? 0xFFFFFFu : 0xFFFFu;
        entry.ordinal = (uint32_t)(raw & ordinalMask);

        if (entry.auth) {
            // An auth bind reuses the bits a plain bind spends on `zero` and
            // `addend` for the signature parameters:
            //
            //   dyld_chained_ptr_arm64e_auth_bind:
            //     ordinal:16  zero:16  diversity:16  addrDiv:1  key:2
            //     next:11  bind:1  auth:1
            //   dyld_chained_ptr_arm64e_auth_bind24 (format 12):
            //     ordinal:24  zero:8   diversity:16  addrDiv:1  key:2
            //     next:11  bind:1  auth:1
            //
            // So the ordinal is 16 or 24 bits wide depending on the format, and
            // everything from bit 32 up is identical in both: diversity at 32,
            // addrDiv at 48, key at 49, next at 51. One declaration therefore
            // decodes both formats; only the ordinal mask outside this block
            // depends on the format, and it already does.
            //
            // Decoded through the struct on every SDK, not by shifting: the
            // layout is Apple's where the header exists, and GNAuthBindPtr is
            // the same declaration field for field where it does not. Little
            // endian is the only arm64 ABI, so the memcpy is the decode.
            GNAuthBindPtr decoded;
            memset(&decoded, 0, sizeof(decoded));
            memcpy(&decoded, &raw, sizeof(decoded));
            entry.diversity = (uint16_t)decoded.diversity;
            entry.addrDiv = decoded.addrDiv ? YES : NO;
            entry.key = (uint16_t)decoded.key;
            entry.next = (uint32_t)decoded.next;
        } else {
            entry.next = (uint32_t)((raw >> 51) & 0x7FFu);
        }
    } else {
        // 64 bit family: bit 63 bind, bits 51..62 next (12 bits), 24 bit ordinal
        if (((raw >> 63) & 1u) == 0) return NO;
        entry.auth = NO;
        entry.next = (uint32_t)((raw >> 51) & 0xFFFu);
        entry.ordinal = (uint32_t)(raw & 0xFFFFFFu);
    }

    if (out) *out = entry;
    return YES;
}

#pragma mark - Pointer authenticity

// Rewriting a slot in __auth_got means writing a *signed* pointer: the callee
// loads it and authenticates it with autIA / autIB / autDA / autDB before the
// call. A bare address in such a slot is not "unverified", it is a crash.
//
// ptrauth.h cannot do this for us. ptrauth_sign_unauthenticated lowers to
// __builtin_ptrauth_sign_unauthenticated, and that builtin requires its
// discriminator operand to be an integer constant expression. The
// discriminator here is the 16 bit diversity field of a chained fixup - a run
// time value - so the front end rejects the call on arm64e:
//
//     error: expression is not an integer constant expression
//
// That restriction belongs to the front end, not to the hardware: a PAC
// instruction takes its modifier from a general purpose register
// (pacIA Xd, Xn), which is exactly how dyld signs these same slots while
// fixing up an arm64e image. GNSignPointer() is that instruction sequence
// written out, one variant per key, with the discriminator coming from the
// chain instead of from a literal.

#define GN_KEY_IA 0u   // pacia / autia
#define GN_KEY_IB 1u   // pacib / autib
#define GN_KEY_DA 2u   // pacda / autda
#define GN_KEY_DB 3u   // pacdb / autdb

/// 1 when this slice can sign with a run time discriminator (arm64e only).
#if defined(__arm64e__) && defined(__has_feature)
#if __has_feature(ptrauth_calls)
#define GN_RUNTIME_PTRAUTH 1
#endif
#endif

/// Signs `value` with `key` and `discriminator`, the way dyld signs a chained
/// fixup slot: the 16 bit diversity, or the slot address when addrDiv is set.
/// On a slice without PAC this is the identity.
static uintptr_t GNSignPointer(uintptr_t value, unsigned key, uintptr_t discriminator) {
#if defined(GN_RUNTIME_PTRAUTH) && GN_RUNTIME_PTRAUTH
    uintptr_t result = value;
    // x9 carries the modifier. It is declared as a clobber so the allocator
    // cannot park `result` there and hand us pacia x9, x9.
    switch (key & 3u) {
        case GN_KEY_IA:
            __asm__ volatile("mov x9, %1\n\tpacia %0, x9"
                             : "+r"(result) : "r"(discriminator) : "x9");
            break;
        case GN_KEY_IB:
            __asm__ volatile("mov x9, %1\n\tpacib %0, x9"
                             : "+r"(result) : "r"(discriminator) : "x9");
            break;
        case GN_KEY_DA:
            __asm__ volatile("mov x9, %1\n\tpacda %0, x9"
                             : "+r"(result) : "r"(discriminator) : "x9");
            break;
        default:
            __asm__ volatile("mov x9, %1\n\tpacdb %0, x9"
                             : "+r"(result) : "r"(discriminator) : "x9");
            break;
    }
    return result;
#else
    (void)key;
    (void)discriminator;
    return value;
#endif
}

/// Drops the PAC field without authenticating, so two pointers can be
/// compared. Strip does not depend on the discriminator, only on the key.
static uintptr_t GNStripPointer(uintptr_t value, unsigned key) {
#if defined(GN_HAVE_PTRAUTH) && __has_feature(ptrauth_calls)
    switch (key & 3u) {
        case GN_KEY_IA: return (uintptr_t)ptrauth_strip((void *)value, ptrauth_key_asia);
        case GN_KEY_IB: return (uintptr_t)ptrauth_strip((void *)value, ptrauth_key_asib);
        case GN_KEY_DA: return (uintptr_t)ptrauth_strip((void *)value, ptrauth_key_asda);
        default:        return (uintptr_t)ptrauth_strip((void *)value, ptrauth_key_asdb);
    }
#else
    (void)key;
    return value;
#endif
}

/// YES when `raw`, read out of an import slot, currently holds `expected`.
/// Auth signed slots are compared after the signature is stripped.
static BOOL GNSlotHoldsAddress(uintptr_t raw, uintptr_t expected, const GNBindEntry *entry) {
    if (raw == expected) return YES;

    if (entry && entry->auth && GNStripPointer(raw, entry->key) == expected) return YES;

    // Fall back to every key. If a linker encodes the key field differently
    // from what we decoded, the slot is still recognisable - and we still
    // refuse to write a foreign pointer into it.
    for (unsigned key = 0; key < 4u; key++) {
        if (GNStripPointer(raw, key) == expected) return YES;
    }
    return NO;
}

/// The value to store in a slot: the replacement itself for a plain slot, a
/// signed pointer for an auth slot.
///
/// Returns 0 when a signed pointer is required but this slice cannot produce
/// one (an arm64 build looking at an arm64e image, for instance). The caller
/// treats 0 as "leave the slot alone": writing an unsigned pointer into an
/// auth slot would turn a working call site into a crashed one.
static uintptr_t GNSignSlotValue(uintptr_t target, const GNBindEntry *entry,
                                 uintptr_t slotAddress) {
    if (!target) return 0;
    if (!entry || !entry->auth) return target;

#if defined(GN_RUNTIME_PTRAUTH) && GN_RUNTIME_PTRAUTH
    uintptr_t discriminator = entry->addrDiv ? slotAddress : (uintptr_t)entry->diversity;
    uintptr_t signedValue = GNSignPointer(target, entry->key, discriminator);

    // A pac instruction only replaces the top bits: the address itself has to
    // come back unchanged. If it does not, the sequence above is wrong for
    // this ABI and storing it would produce a slot the callee cannot
    // authenticate - so don't.
    if (signedValue == 0 || GNStripPointer(signedValue, entry->key) != target) {
        GNLogC("rebind: signing produced a mangled pointer for key %u - skipped",
               (unsigned)entry->key);
        return 0;
    }
    return signedValue;
#else
    (void)slotAddress;
    GNLogC("rebind: slot is auth signed and this slice has no PAC - skipped");
    return 0;
#endif
}

#pragma mark - Moving a slot without a symbol name (v16)

//  These three are the whole of v16's "find the call site" problem, and they are
//  public (declared in GNUnlock.h) because src/GNSlotScan.m is the caller and
//  src/GNRebind.m is the only file allowed to know how a pointer is signed.
//
//  fishhook identifies a slot by name. That cannot work in the dyld shared
//  cache, which keeps neither the symbol table nor the indirect symbol table -
//  the same image this whole problem lives in. Identifying a slot by the address
//  it already holds needs neither.

/// The plain address inside `value`, whether or not it carries a PAC.
///
/// A dlsym result on arm64e can be an authenticated pointer. Comparing that with
/// the *unsigned* address stored in a slot would never match, so the target is
/// stripped once, up front, and everything downstream deals in plain addresses.
uintptr_t GNSlotStripAddress(uintptr_t value) {
    if (!value) return 0;

    for (unsigned key = 0; key < 4u; key++) {
        uintptr_t candidate = GNStripPointer(value, key) & 0x0000FFFFFFFFFFFFULL;
        if (candidate && GNIsExecutableAddress(candidate)) return candidate;
    }
    return value & 0x0000FFFFFFFFFFFFULL;
}

/// true when the 8 bytes in a slot refer to `target`: either plainly, or through
/// a signature this slice knows how to look through.
bool GNSlotRefersTo(uintptr_t raw, uintptr_t target) {
    if (!raw || !target) return false;
    if (raw == target) return true;

    for (unsigned key = 0; key < 4u; key++) {
        if (GNStripPointer(raw, key) == target) return true;
    }
    return false;
}

/// The value to store in `slotAddress` so that it points at `replacement`
/// instead of at `target`. Returns 0 - and the caller leaves the slot alone -
/// when the signature cannot be reproduced exactly.
///
/// The proof, and why it is a proof
/// --------------------------------
/// A plain slot holds `target` verbatim; storing `replacement` verbatim is the
/// same operation that put the original value there, so it is correct by
/// construction.
///
/// An authenticated slot holds `pacia(target, modifier)`. We do not know the
/// modifier - it may be the slot address, a constant baked in by dyld, or
/// something this process cannot observe. So we do not guess it: we re-sign
/// `target` with each candidate and require the result to equal the bytes already
/// in the slot, bit for bit. A candidate that reproduces the existing content is
/// the exact key and modifier dyld used; anything else is rejected. That means a
/// wrong-modifier write - a fault on the next call into that slot - is not
/// possible, only a refusal.
uintptr_t GNSlotMoveTo(uintptr_t raw, uintptr_t target, uintptr_t replacement,
                       uintptr_t slotAddress, const char **why) {
    if (why) *why = NULL;
    if (!raw || !target || !replacement) return 0;

    if (raw == target) return replacement;    // plain slot, proven by equality

    for (unsigned key = 0; key < 4u; key++) {
        uintptr_t modifiers[2];
        modifiers[0] = slotAddress;           // addrDiv: diversity is the slot
        modifiers[1] = 0;                     // diversity 0 / plain

        for (int index = 0; index < 2; index++) {
            if (GNSignPointer(target, key, modifiers[index]) != raw) continue;

            uintptr_t moved = GNSignPointer(replacement, key, modifiers[index]);
            if (!moved || GNStripPointer(moved, key) != replacement) {
                if (why) *why = "re-signing the replacement mangled the address";
                return 0;
            }
            return moved;
        }
    }

    if (why) {
        *why = "the slot's signature could not be reproduced byte for byte";
    }
    return 0;
}

#pragma mark - Bounds-checked decoding

/// Maps a file offset onto the address it is loaded at, and refuses unless the
/// whole [offset, offset+length) range is inside one segment's file range *and*
/// currently readable.
///
/// This replaces `hdr + offset`, which is only correct while every segment is
/// laid out with vmaddr == fileoff. __LINKEDIT is not always, the dyld shared
/// cache never is, and a base computed that way turns a table read into a read
/// of whatever else lives at that address - or of nothing mapped at all.
static const uint8_t *GNFileOffsetToAddress(const struct mach_header_64 *hdr,
                                            intptr_t slide,
                                            const struct segment_command_64 *const *segments,
                                            uint32_t segmentCount,
                                            uint64_t fileOffset,
                                            uint64_t length) {
    if (!hdr || !segments || length == 0) return NULL;

    uint64_t end = fileOffset + length;
    if (end < fileOffset) return NULL;      // overflow

    for (uint32_t i = 0; i < segmentCount; i++) {
        const struct segment_command_64 *seg = segments[i];
        if (!seg || seg->filesize == 0) continue;

        uint64_t segmentEnd = seg->fileoff + seg->filesize;
        if (segmentEnd < seg->fileoff) continue;
        if (fileOffset < seg->fileoff || end > segmentEnd) continue;
        if (length > seg->vmsize) continue;

        uintptr_t address = (uintptr_t)(slide + (intptr_t)seg->vmaddr) +
                            (uintptr_t)(fileOffset - seg->fileoff);
        if (!GNRangeIsReadable(address, (size_t)length)) return NULL;
        return (const uint8_t *)address;
    }
    return NULL;
}

/// Compares a decoded C string against `a` / `b` without ever reading a byte
/// that has not been shown to be readable.
///
/// The shape matters: find the run of readable memory first, then look for the
/// terminator *inside* it, and only then compare. A plain strcmp assumes the
/// terminator exists in the mapping it was given, which is exactly the
/// assumption that produced the v9 SIGBUS.
static BOOL GNReadableCStringEquals(const char *candidate, size_t limit,
                                    const char *a, const char *b) {
    if (!candidate) return NO;
    if (limit == 0 || limit > GN_MAX_SYMBOL_NAME) limit = GN_MAX_SYMBOL_NAME;

    size_t run = GNReadableRunLength((uintptr_t)candidate, limit);
    if (run == 0) return NO;

    const char *terminator = (const char *)memchr(candidate, 0, run);
    if (!terminator) return NO;

    size_t length = (size_t)(terminator - candidate);
    if (a && strlen(a) == length && memcmp(candidate, a, length) == 0) return YES;
    if (b && strlen(b) == length && memcmp(candidate, b, length) == 0) return YES;
    return NO;
}

/// Reads the symbol name for one import ordinal, or NULL when anything about
/// that ordinal does not fit the blob it came from.
static const char *GNImportSymbolName(const GNFixupsHeader *header,
                                      const uint8_t *blob,
                                      size_t blobSize,
                                      uint32_t ordinal) {
    if (!header || !blob) return NULL;
    if (blobSize < sizeof(GNFixupsHeader)) return NULL;
    if (header->symbols_format != GN_SYMBOLS_UNCOMPRESSED) return NULL;
    if (ordinal >= header->imports_count) return NULL;

    uint32_t entrySize = GNImportEntrySize(header->imports_format);
    if (entrySize == 0) return NULL;

    uint64_t importsOffset = header->imports_offset;
    uint64_t symbolsOffset = header->symbols_offset;
    if (importsOffset > blobSize || symbolsOffset >= (uint64_t)blobSize) return NULL;

    // The whole table has to fit, not just the entry we want: a truncated blob
    // means the header and the data disagree, and no entry of it is trustworthy.
    uint64_t tableSpan = (uint64_t)header->imports_count * (uint64_t)entrySize;
    if (tableSpan / entrySize != (uint64_t)header->imports_count) return NULL;
    if (importsOffset + tableSpan > (uint64_t)blobSize) return NULL;

    const uint8_t *entry = blob + importsOffset + (uint64_t)ordinal * entrySize;
    uint32_t nameOffset = 0;

    if (header->imports_format == GN_IMPORT_ADDEND64) {
        uint64_t raw = 0;
        memcpy(&raw, entry, sizeof(raw));
        nameOffset = (uint32_t)((raw >> 32) & 0xFFFFFFFFu);
    } else {
        // Formats 1 and 2: lib_ordinal:8, weak:1, name_offset:23.
        uint32_t raw = 0;
        memcpy(&raw, entry, sizeof(raw));
        nameOffset = (raw >> 9) & 0x7FFFFFu;
    }

    uint64_t nameAddress = symbolsOffset + (uint64_t)nameOffset;
    if (nameAddress < symbolsOffset) return NULL;              // overflow
    if (nameAddress >= (uint64_t)blobSize) return NULL;

    // In range is not enough: the name has to be terminated *inside* the blob.
    // Otherwise the pointer is valid, the string is not, and whoever reads it
    // runs past the end of the table looking for a NUL - which is the shape of
    // the v9 crash. The whole blob was proven readable by the caller, so this
    // scan cannot fault.
    uint64_t remaining = (uint64_t)blobSize - nameAddress;
    if (remaining == 0) return NULL;
    if (!memchr(blob + nameAddress, 0, (size_t)remaining)) return NULL;

    return (const char *)(blob + nameAddress);
}

/// Name match for one decoded import. Keeps the "how long may this string be"
/// arithmetic in one place, so no caller can hand strcmp an unbounded pointer.
static BOOL GNImportNameMatches(const GNFixupsHeader *header,
                                const uint8_t *blob,
                                size_t blobSize,
                                uint32_t ordinal,
                                const char *symbol,
                                const char *underscored) {
    const char *name = GNImportSymbolName(header, blob, blobSize, ordinal);
    if (!name) return NO;

    size_t offset = (size_t)(name - (const char *)blob);
    if (offset >= blobSize) return NO;
    return GNReadableCStringEquals(name, blobSize - offset, symbol, underscored);
}

#pragma mark - Chain walking

static NSInteger GNRebindChainedFixes(const struct mach_header_64 *hdr,
                                      intptr_t slide,
                                      int imageIndex,
                                      const char *symbol,
                                      void *replacement,
                                      uintptr_t expected,
                                      int *writeFailures) {
    const struct linkedit_data_command *fixupsCommand = NULL;
    const struct segment_command_64 *segments[64];
    uint32_t segmentCount = 0;

    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(struct load_command)) break;
        if (lc->cmd == GN_LC_DYLD_CHAINED_FIXUPS) {
            fixupsCommand = (const struct linkedit_data_command *)lc;
        } else if (lc->cmd == LC_SEGMENT_64 && segmentCount < 64) {
            segments[segmentCount++] = (const struct segment_command_64 *)lc;
        }
        cursor += lc->cmdsize;
    }

    if (!fixupsCommand) return 0;
    if (segmentCount == 0) return 0;
    if (fixupsCommand->datasize < sizeof(GNFixupsHeader)) return 0;

    const uint8_t *blob = GNFileOffsetToAddress(hdr, slide, segments, segmentCount,
                                                fixupsCommand->dataoff,
                                                sizeof(GNFixupsHeader));
    if (!blob) {
        GNLogC("rebind[%d]: chained fixups header is not a readable mapped range - skipped",
               imageIndex);
        return 0;
    }

    const size_t blobSize = fixupsCommand->datasize;
    if (!GNRangeIsReadable((uintptr_t)blob, blobSize)) {
        GNLogC("rebind[%d]: chained fixups blob (%lu bytes) is not fully readable - skipped",
               imageIndex, (unsigned long)blobSize);
        return 0;
    }

    const GNFixupsHeader *header = (const GNFixupsHeader *)blob;
    if (header->symbols_format != GN_SYMBOLS_UNCOMPRESSED) {
        GNLogC("rebind[%d]: compressed symbol table - skipped", imageIndex);
        return 0;
    }
    if (GNImportEntrySize(header->imports_format) == 0) {
        GNLogC("rebind[%d]: imports format %u unknown - skipped",
               imageIndex, (unsigned)header->imports_format);
        return 0;
    }
    if (header->starts_offset >= blobSize) {
        GNLogC("rebind[%d]: starts_offset past the blob - skipped", imageIndex);
        return 0;
    }

    const GNStartsInImage *starts = (const GNStartsInImage *)(blob + header->starts_offset);
    uint32_t segCount = starts->seg_count;
    if (segCount == 0 || segCount > segmentCount) {
        GNLogC("rebind[%d]: seg_count %u does not match %u segments - skipped",
               imageIndex, (unsigned)segCount, (unsigned)segmentCount);
        return 0;
    }

    // starts + seg_count + offsets must be inside the blob.
    uint64_t startsSpan = sizeof(GNStartsInImage) + (uint64_t)segCount * sizeof(uint32_t);
    if (header->starts_offset + startsSpan > (uint64_t)blobSize) {
        GNLogC("rebind[%d]: segment offset table past the blob - skipped", imageIndex);
        return 0;
    }

    const uint32_t *segInfoOffsets = (const uint32_t *)(starts + 1);
    NSInteger rebound = 0;
    NSInteger signSkips = 0;

    // Imports are named with a leading underscore; accept both spellings.
    char symbolWithUnderscore[260];
    snprintf(symbolWithUnderscore, sizeof(symbolWithUnderscore), "_%s", symbol);

    for (uint32_t segIndex = 0; segIndex < segCount; segIndex++) {
        uint32_t infoOffset = segInfoOffsets[segIndex];
        if (infoOffset == 0) continue;

        // The per-segment record plus its page table has to be inside the blob
        // before we trust page_count enough to index it.
        uint64_t infoAddress = (uint64_t)header->starts_offset + infoOffset;
        if (infoAddress + sizeof(GNStartsInSegment) > (uint64_t)blobSize) {
            GNLogC("rebind[%d]: segment %u starts record past the blob - skipped",
                   imageIndex, (unsigned)segIndex);
            continue;
        }

        const GNStartsInSegment *info = (const GNStartsInSegment *)(blob + infoAddress);
        if (info->size < sizeof(GNStartsInSegment)) continue;

        uint64_t pageTableSpan = sizeof(GNStartsInSegment) +
                                 (uint64_t)info->page_count * sizeof(uint16_t);
        if (pageTableSpan > info->size) {
            GNLogC("rebind[%d]: segment %u page table exceeds its record - skipped",
                   imageIndex, (unsigned)segIndex);
            continue;
        }
        if (infoAddress + pageTableSpan > (uint64_t)blobSize) continue;

        GNFamily family = GNFamilyForFormat(info->pointer_format);
        if (family == GNFamilyUnknown) {
            GNLogC("rebind[%d]: pointer format %u unsupported - segment skipped",
                   imageIndex, (unsigned)info->pointer_format);
            continue;
        }

        uint32_t stride = GNChainStride(info->pointer_format);
        if (stride == 0) {
            GNLogC("rebind[%d]: pointer format %u is not walked by this code - segment skipped",
                   imageIndex, (unsigned)info->pointer_format);
            continue;
        }
        if (info->page_size == 0) continue;

        const struct segment_command_64 *seg = segments[segIndex];
        if (!seg || seg->vmsize == 0) continue;

        uintptr_t segmentAddress = (uintptr_t)(slide + (intptr_t)seg->vmaddr);
        uint64_t segmentSize = seg->vmsize;
        if (!GNRangeIsReadable(segmentAddress, (size_t)segmentSize)) {
            GNLogC("rebind[%d]: segment %u is not readable - skipped",
                   imageIndex, (unsigned)segIndex);
            continue;
        }

        const uint16_t *pageStarts = (const uint16_t *)(info + 1);

        for (uint32_t page = 0; page < info->page_count; page++) {
            uint16_t start = pageStarts[page];
            if (start == GN_CHAINED_PTR_START_NONE) continue;
            if (start & GN_CHAINED_PTR_START_MULTI) continue;   // rare, not needed here
            if ((uint32_t)start >= info->page_size) continue;

            // The chain is relative to the page it starts on, not to the
            // segment. v9 compared `page * page_size + start` against
            // page_size, so every page except the first broke out immediately
            // and most slots were never looked at - which is also why the
            // decoder bugs below stayed hidden.
            uint64_t pageOffset = (uint64_t)page * (uint64_t)info->page_size;
            if (pageOffset >= segmentSize) break;

            uint64_t room = segmentSize - pageOffset;
            size_t pageSpan = (size_t)(room < (uint64_t)info->page_size
                                       ? room : (uint64_t)info->page_size);
            if (pageSpan <= sizeof(uint64_t)) continue;

            uintptr_t pageAddress = segmentAddress + (uintptr_t)pageOffset;
            uintptr_t offset = (uintptr_t)start;
            size_t guard = 0;

            while (guard++ < 100000) {
                if (offset + sizeof(uint64_t) > (uintptr_t)pageSpan) break;

                uintptr_t slotAddress = pageAddress + offset;
                uint64_t raw = 0;
                memcpy(&raw, (const void *)slotAddress, sizeof(raw));

                uint32_t next = 0;
                GNBindEntry entry;

                if (GNDecodeChainedBind(raw, info->pointer_format, &entry)) {
                    next = entry.next;

                    if (GNImportNameMatches(header, blob, blobSize, entry.ordinal,
                                            symbol, symbolWithUnderscore)) {
                        if (GNSlotHoldsAddress((uintptr_t)raw, expected, &entry)) {
                            uintptr_t newValue = GNSignSlotValue((uintptr_t)replacement,
                                                                 &entry, slotAddress);
                            if (newValue == 0) {
                                signSkips++;
                            } else if (GNWriteBytes(slotAddress, &newValue, sizeof(newValue))) {
                                rebound++;
                            } else if (writeFailures) {
                                (*writeFailures)++;
                            }
                        } else {
                            GNLogC("rebind[%d]: slot for '%s' at %p does not hold the symbol "
                                   "address (0x%llx) - left alone",
                                   imageIndex, symbol, (void *)slotAddress,
                                   (unsigned long long)raw);
                        }
                    }
                } else {
                    // A rebase entry: next is still valid for the 64 bit family,
                    // but the arm64e rebase layout puts it in the same bits, so
                    // the same stride applies.
                    if (family == GNFamilyARM64E) {
                        next = (uint32_t)((raw >> 51) & 0x7FFu);
                    } else {
                        next = (uint32_t)((raw >> 51) & 0xFFFu);
                    }
                }

                if (next == 0) break;
                uintptr_t step = (uintptr_t)next * stride;
                if (step == 0) break;
                if (offset + step <= offset) break;      // overflow
                offset += step;
            }
        }
    }

    if (signSkips > 0) {
        GNLogC("rebind[%d]: %ld auth slot(s) needed a signed pointer and were left alone",
               imageIndex, (long)signSkips);
    }

    return rebound;
}

#pragma mark - Classic indirect symbol table

static NSInteger GNRebindClassic(const struct mach_header_64 *hdr,
                                 intptr_t slide,
                                 int imageIndex,
                                 const char *symbol,
                                 void *replacement,
                                 uintptr_t expected,
                                 int *writeFailures) {
    const struct symtab_command *symtab = NULL;
    const struct dysymtab_command *dysymtab = NULL;
    const struct segment_command_64 *segments[64];
    uint32_t segmentCount = 0;
    BOOL hasChainedFixups = NO;

    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(struct load_command)) break;
        if (lc->cmd == LC_SYMTAB) {
            symtab = (const struct symtab_command *)lc;
        } else if (lc->cmd == LC_DYSYMTAB) {
            dysymtab = (const struct dysymtab_command *)lc;
        } else if (lc->cmd == GN_LC_DYLD_CHAINED_FIXUPS) {
            hasChainedFixups = YES;
        } else if (lc->cmd == LC_SEGMENT_64 && segmentCount < 64) {
            segments[segmentCount++] = (const struct segment_command_64 *)lc;
        }
        cursor += lc->cmdsize;
    }

    // One image, one mechanism. In a chained-fixups binary the indirect table
    // is either absent or describes something the linker no longer uses, and
    // treating it as live is how you walk garbage indices.
    if (hasChainedFixups) return 0;
    if (!symtab || !dysymtab) return 0;
    if (segmentCount == 0) return 0;
    if (dysymtab->nindirectsyms == 0 || symtab->nsyms == 0 || symtab->strsize == 0) return 0;

    const uint32_t *indirect = (const uint32_t *)GNFileOffsetToAddress(
        hdr, slide, segments, segmentCount, dysymtab->indirectsymoff,
        (uint64_t)dysymtab->nindirectsyms * sizeof(uint32_t));
    if (!indirect) {
        GNLogC("rebind[%d]: indirect symbol table out of range - skipped", imageIndex);
        return 0;
    }

    const struct nlist_64 *symbols = (const struct nlist_64 *)GNFileOffsetToAddress(
        hdr, slide, segments, segmentCount, symtab->symoff,
        (uint64_t)symtab->nsyms * sizeof(struct nlist_64));
    if (!symbols) {
        GNLogC("rebind[%d]: symbol table out of range - skipped", imageIndex);
        return 0;
    }

    // v9 computed this as `hdr + stroff`, i.e. it treated a file offset as a
    // memory offset, and never checked n_strx against strsize. Both are fixed
    // here: the base comes from the segment table, and every index is bounded.
    const char *strings = (const char *)GNFileOffsetToAddress(
        hdr, slide, segments, segmentCount, symtab->stroff, symtab->strsize);
    if (!strings) {
        GNLogC("rebind[%d]: string table out of range - skipped", imageIndex);
        return 0;
    }

    char symbolWithUnderscore[260];
    snprintf(symbolWithUnderscore, sizeof(symbolWithUnderscore), "_%s", symbol);

    NSInteger rebound = 0;

    for (uint32_t s = 0; s < segmentCount; s++) {
        const struct segment_command_64 *seg = segments[s];
        const struct section_64 *sections = (const struct section_64 *)(seg + 1);

        for (uint32_t i = 0; i < seg->nsects; i++) {
            const struct section_64 *sect = &sections[i];
            uint8_t type = sect->flags & SECTION_TYPE;
            BOOL isPointerSection = (type == S_NON_LAZY_SYMBOL_POINTERS ||
                                     type == S_LAZY_SYMBOL_POINTERS ||
                                     type == S_LAZY_DYLIB_SYMBOL_POINTERS);
            if (!isPointerSection || sect->size < 8) continue;

            uint64_t count = sect->size / 8;
            for (uint64_t k = 0; k < count; k++) {
                uint64_t tableIndex = (uint64_t)sect->reserved1 + k;
                if (tableIndex >= dysymtab->nindirectsyms) continue;

                uint32_t symbolIndex = indirect[tableIndex];
                if ((symbolIndex & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) != 0) continue;
                if (symbolIndex >= symtab->nsyms) continue;

                uint32_t strx = symbols[symbolIndex].n_un.n_strx;
                if (strx == 0 || strx >= symtab->strsize) continue;

                const char *name = strings + strx;
                if (!GNReadableCStringEquals(name, (size_t)(symtab->strsize - strx),
                                             symbol, symbolWithUnderscore)) {
                    continue;
                }

                uintptr_t slotAddress = (uintptr_t)(slide + (intptr_t)sect->addr) + (uintptr_t)(k * 8);
                if (!GNRangeIsReadable(slotAddress, sizeof(uint64_t))) continue;

                uintptr_t raw = 0;
                memcpy(&raw, (const void *)slotAddress, sizeof(raw));

                // Classic slots are never auth signed, so an exact match is the
                // only thing we accept here.
                if (raw != expected) {
                    GNLogC("rebind[%d]: classic slot for '%s' at %p holds 0x%llx - left alone",
                           imageIndex, symbol, (void *)slotAddress, (unsigned long long)raw);
                    continue;
                }

                uintptr_t newValue = (uintptr_t)replacement;
                if (GNWriteBytes(slotAddress, &newValue, sizeof(newValue))) {
                    rebound++;
                } else if (writeFailures) {
                    (*writeFailures)++;
                }
            }
        }
    }

    return rebound;
}

#pragma mark - Public entry points

NSInteger GNRebindSymbolInAppImages(const char *symbol, void *replacement, void **original) {
    if (!symbol || !symbol[0] || !replacement) return 0;

    void *target = dlsym(RTLD_DEFAULT, symbol);
    if (!target) {
        GNLogC("rebind '%s': symbol not found", symbol);
        return 0;
    }
    if (original) *original = target;

    if ((uintptr_t)target == (uintptr_t)replacement) return 0;

    // Two gates, both new in v10.
    //
    // The config gate belongs here and not only in GNInterposeSymbol(): the
    // launch guard used to call this function directly, so the switch that was
    // supposed to keep rebinding off never saw that call. That is how a
    // feature documented as "off by default" ran inside the dylib constructor.
    //
    // v11 adds a second, narrower key: AllowDiagnosticRebinding. It exists for
    // exactly one caller - GNInstallThrowTracer(), which rewrites the
    // objc_exception_throw slot to *observe* an exception and then calls the
    // real function. It changes no behaviour, so it does not need the switch
    // that also enables keychain / SecCode / SecTask interposition, and keeping
    // those two decisions separate is the difference between "the app behaves
    // differently" and "the app behaves identically but we can see".
    if (!GNCFG(@"EnableGOTRebinding", NO) && !GNCFG(@"AllowDiagnosticRebinding", NO)) {
        GNLogC("rebind '%s': EnableGOTRebinding and AllowDiagnosticRebinding are both off "
               "- no image walked", symbol);
        return 0;
    }
    if (GNSafeModeActive()) {
        GNLogC("rebind '%s': safe mode (previous launch died here) - skipped", symbol);
        return 0;
    }

    uint32_t count = _dyld_image_count();
    NSInteger total = 0;
    int writeFailures = 0;

    for (uint32_t i = 0; i < count; i++) {
        if (!GNIsAppOwnedImage(i)) continue;

        const struct mach_header_64 *hdr =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;

        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        NSInteger chained = GNRebindChainedFixes(hdr, slide, (int)i, symbol,
                                                 replacement, (uintptr_t)target, &writeFailures);
        NSInteger classic = GNRebindClassic(hdr, slide, (int)i, symbol,
                                            replacement, (uintptr_t)target, &writeFailures);
        NSInteger here = chained + classic;

        if (here > 0) {
            const char *path = _dyld_get_image_name(i);
            const char *base = path ? strrchr(path, '/') : NULL;
            GNLogC("rebind '%s': %ld slot(s) in %s", symbol, (long)here, base ? base + 1 : "?");
        }
        total += here;
    }

    if (writeFailures > 0) {
        GNLogC("rebind '%s': %d slot(s) could not be written", symbol, writeFailures);
    }

    return total;
}

BOOL GNInterposeSymbol(const char *symbol, void *replacement, void **original) {
    if (!symbol || !replacement) return NO;

    void *target = dlsym(RTLD_DEFAULT, symbol);
    if (!target) {
        GNLogC("interpose '%s': symbol not found", symbol);
        return NO;
    }
    if (original) *original = target;

    if (GNCodePatchingAllowed()) {
        if (GNInlineHookSymbol(symbol, replacement, NULL)) return YES;
        GNLogC("interpose '%s': inline hook failed, falling back to rebinding", symbol);
    }

    if (!GNCFG(@"EnableGOTRebinding", NO)) {
        GNLogC("interpose '%s': no code patching on a %s signature and "
               "EnableGOTRebinding is off - skipped, app keeps working",
               symbol, GNSignatureMode());
        return NO;
    }

    NSInteger sites = GNRebindSymbolInAppImages(symbol, replacement, NULL);
    if (sites == 0) {
        GNLogC("interpose '%s': no import slot to rebind - skipped", symbol);
        return NO;
    }
    GNLogC("interpose '%s': %ld call site(s) redirected (data only)", symbol, (long)sites);
    return YES;
}
