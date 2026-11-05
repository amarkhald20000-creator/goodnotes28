//
//  GNFunctionStarts.h
//  "Which function contains this address?" - answered from LC_FUNCTION_STARTS.
//
//  Why this file exists (v25)
//  --------------------------
//  v24 could not link. The two names the device backtrace produced are not in
//  CloudKit's .tbd, so an __DATA,__interpose tuple that names them is an
//  undefined symbol at link time, weak_import or not:
//
//      Undefined symbols for architecture arm64:
//        "static (extension in CloudKit):__C.CKPersona.launch.getter : __C.CKPersona?"
//        "_CKMainBundleIsAppleExecutable"
//
//  v25 therefore stops naming them at link time entirely and resolves an
//  address at run time instead. The obvious first attempt - dlsym - is expected
//  to fail for exactly the reason the link failed: a symbol that is not in the
//  stub is not exported either. So there has to be a second source, and the one
//  piece of information the crash log always gives is an *interior* offset:
//
//      13  CloudKit  $sSo9CKPersonaC8CloudKitE6launchABSgvgZ + 592
//
//  592 is inside the function, not its entry, and a slot cannot be matched
//  against an interior address - the address a caller binds is the entry. The
//  image does carry the entry points, without names, in LC_FUNCTION_STARTS: a
//  ULEB128 delta list, each non-zero value the distance to the next function
//  start, terminated by a zero.
//
//  So: walk the deltas, keep the last start that is <= the interior offset. That
//  is the function the frame belongs to, by construction rather than by guess.
//
//  This header is deliberately free of <mach-o/*>, of Foundation and of any
//  Darwin call, so scripts/functionstarts_test.c can execute it on the host with
//  synthetic streams - including the malformed ones. Reading the command out of
//  a real image, and every kernel call, stay in src/GNCloudKitSymbolQuarantine.m.
//
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// A stream longer than this many entries is not a function-start list. The cap
/// is for the same reason GNW_MAX_SECTIONS has one: a corrupt datasize must not
/// turn into an unbounded loop during dyld initialisation.
enum { GNFS_MAX_ENTRIES = 1 << 20 };

/// Reads one ULEB128 from `data` at *cursor, advancing it.
///
/// Returns false on a truncated or overlong encoding, and leaves *cursor where it
/// was. Overlong means more than 10 groups or a value that would not fit in 64
/// bits; both are "this is not the list I think it is", and the caller's answer
/// is to stop, not to guess.
static inline bool GNFSReadULEB(const uint8_t *data, size_t size, size_t *cursor,
                                uint64_t *out) {
    if (!data || !cursor || !out) return false;

    size_t at = *cursor;
    uint64_t value = 0;
    unsigned shift = 0;
    unsigned groups = 0;

    while (at < size) {
        uint8_t byte = data[at++];
        groups++;
        if (groups > 10) return false;
        if (shift < 64) {
            value |= (uint64_t)(byte & 0x7f) << shift;
        } else if ((byte & 0x7f) != 0) {
            return false;   // bits that do not fit in 64
        }
        if ((byte & 0x80) == 0) {
            *cursor = at;
            *out = value;
            return true;
        }
        shift += 7;
        if (shift > 70) return false;
    }
    return false;   // ran out mid-encoding
}

/// The start of the function that contains `target`.
///
/// `textAddress` is the __TEXT vmaddr the delta list is relative to, in the same
/// address space as `target`. `target` may be a function entry or any address
/// inside one; an address below `textAddress`, or past the end of the list,
/// answers false rather than clamping - a wrong start is worse than no start,
/// because the caller would rewrite a slot to point at the wrong function.
///
/// `indexOut` (optional) receives how many starts at or below `target` the list
/// held, which is what the log reports when the answer is "no": it separates an
/// empty list from "this image declares no function there".
static inline bool GNFSFindFunction(const uint8_t *starts, size_t size,
                                    uint64_t textAddress, uint64_t target,
                                    uint64_t *startOut, uint32_t *indexOut) {
    if (startOut) *startOut = 0;
    if (indexOut) *indexOut = 0;
    if (!starts || size == 0) return false;
    if (target < textAddress) return false;

    uint64_t address = textAddress;
    uint64_t best = 0;
    bool found = false;
    bool malformed = false;
    uint32_t index = 0;
    size_t cursor = 0;

    while (cursor < size && index < GNFS_MAX_ENTRIES) {
        uint64_t delta = 0;
        if (!GNFSReadULEB(starts, size, &cursor, &delta)) { malformed = true; break; }
        if (delta == 0) break;                                     // terminator

        if (address > UINT64_MAX - delta) { malformed = true; break; }
        address += delta;

        // Past the address we were asked about: the previous start is the answer.
        if (address > target) break;

        best = address;
        found = true;
        index++;
    }
    if (index >= GNFS_MAX_ENTRIES) malformed = true;

    if (indexOut) *indexOut = index;
    if (!found) return false;

    // A list that stopped early (truncated, overlong, overflowing) cannot vouch
    // for an address past the last start it managed to read: the function that
    // contains `target` may be one of the entries it never decoded. Answering
    // with the last good start there would rewrite a slot to point at the wrong
    // function, so the answer is "no" instead. An exact hit is still exact.
    if (malformed && target != best) return false;

    if (startOut) *startOut = best;
    return true;
}

#ifdef __cplusplus
}
#endif
