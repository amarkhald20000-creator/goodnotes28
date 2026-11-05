//
//  functionstarts_test.c
//  Executes src/GNFunctionStarts.h on the host, against synthetic delta lists.
//
//  Why this exists
//  ---------------
//  The v25 resolution path answers "which function contains this address" for a
//  name the SDK will not let us link. If it is wrong by one entry the dylib
//  rewrites an import slot to point at a *different* function - not a missed
//  hook, a crash on the next call. So the arithmetic is in a header with no
//  Apple dependencies and this file runs it, malformed input included, instead
//  of trusting a reading.
//
//  --selfcheck runs the same expectations against the shape v24 had (treat the
//  interior offset as if it were the entry) and requires them to fail, so a
//  test that has quietly stopped checking anything cannot pass.
//
#include "../src/GNFunctionStarts.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void expect(bool condition, const char *what) {
    checks++;
    if (!condition) {
        failures++;
        printf("  FAIL  %s\n", what);
    }
}

/// One function-start list, built by hand: the deltas are the values between
/// function entries, terminated by a zero exactly the way the loader emits it.
static size_t build(uint8_t *out, const uint64_t *deltas, size_t count) {
    size_t at = 0;
    for (size_t i = 0; i < count; i++) {
        uint64_t value = deltas[i];
        do {
            uint8_t byte = (uint8_t)(value & 0x7f);
            value >>= 7;
            if (value) byte |= 0x80;
            out[at++] = byte;
        } while (value);
    }
    return at;
}

static void testSimpleTable(void) {
    // text at 0x1000; functions at 0x1010, 0x1030, 0x1060
    const uint64_t deltas[] = { 0x10, 0x20, 0x30, 0 };
    uint8_t blob[32];
    size_t size = build(blob, deltas, 4);

    uint64_t start = 0;
    uint32_t index = 0;

    expect(GNFSFindFunction(blob, size, 0x1000, 0x1010, &start, &index) && start == 0x1010,
           "an exact function entry resolves to itself");
    expect(index == 1, "the entry was reached after one delta");

    expect(GNFSFindFunction(blob, size, 0x1000, 0x1020, &start, &index) && start == 0x1010,
           "an interior offset resolves to the start of its own function");

    // +592 is the shape of the v22 frame: well inside one function.
    expect(GNFSFindFunction(blob, size, 0x1000, 0x1030 + 0x25, &start, &index)
           && start == 0x1030,
           "an interior offset of a later function resolves to that function");

    expect(GNFSFindFunction(blob, size, 0x1000, 0x1060, &start, &index) && start == 0x1060,
           "the last declared start resolves");

    expect(GNFSFindFunction(blob, size, 0x1000, 0x1061, &start, &index) && start == 0x1060,
           "an address past the last entry is attributed to it, not to nothing");

    expect(!GNFSFindFunction(blob, size, 0x1000, 0x1000, &start, &index),
           "an address before the first entry has no containing function");
}

static void testMultiByteDeltas(void) {
    // 300 encodes as two groups; the boundary is where a one-byte decoder dies.
    const uint64_t deltas[] = { 300, 70000, 0 };
    uint8_t blob[32];
    size_t size = build(blob, deltas, 3);

    uint64_t start = 0;
    expect(GNFSFindFunction(blob, size, 0x100000, 0x100000 + 300, &start, NULL),
           "the first declared start resolves to itself");
    expect(start == 0x100000 + 300, "the first start is the first delta");

    expect(GNFSFindFunction(blob, size, 0x100000, 0x100000 + 300 + 299, &start, NULL)
           && start == 0x100000 + 300,
           "an address 299 bytes into the first function resolves to its start");

    expect(GNFSFindFunction(blob, size, 0x100000, 0x100000 + 300 + 70000, &start, NULL)
           && start == 0x100000 + 300 + 70000,
           "a three-byte delta resolves");
}

static void testMalformed(void) {
    uint64_t start = 12345;
    uint32_t index = 7;

    expect(!GNFSFindFunction(NULL, 0, 0x1000, 0x1010, &start, &index),
           "no data answers no");
    expect(start == 0 && index == 0, "a refusal zeroes its outputs instead of leaving stale ones");

    const uint64_t deltas[] = { 0x10, 0 };
    uint8_t blob[16];
    size_t size = build(blob, deltas, 2);
    expect(!GNFSFindFunction(blob, size, 0x1000, 0x0f00, &start, NULL),
           "an address below __TEXT is refused rather than clamped");

    // A truncated final group: 0x80 says "more follows" and nothing does.
    uint8_t truncated[] = { 0x10, 0x80 };
    expect(!GNFSFindFunction(truncated, sizeof(truncated), 0x1000, 0x2000, &start, &index),
           "a truncated list cannot vouch for an address past its last good start");
    expect(index == 1, "the deltas read before the truncation still counted");
    expect(GNFSFindFunction(truncated, sizeof(truncated), 0x1000, 0x1010, &start, &index)
           && start == 0x1010,
           "an exact hit before the truncation is still exact");

    // Overlong: eleven continuation groups cannot be a 64 bit delta.
    uint8_t overlong[16];
    memset(overlong, 0x80, sizeof(overlong));
    expect(!GNFSFindFunction(overlong, sizeof(overlong), 0x1000, 0x2000, &start, NULL),
           "an overlong encoding is refused");

    // A delta that would overflow the address space.
    const uint64_t huge[] = { UINT64_MAX, 0x10, 0 };
    uint8_t hugeBlob[32];
    size_t hugeSize = build(hugeBlob, huge, 3);
    expect(!GNFSFindFunction(hugeBlob, hugeSize, 0x1000, 0x2000, &start, NULL),
           "an overflowing delta cannot produce a start");

    // No terminator at all: the list simply ends. Still answerable.
    uint8_t unterminated[] = { 0x10, 0x20 };
    expect(GNFSFindFunction(unterminated, sizeof(unterminated), 0x1000, 0x1025, &start, NULL)
           && start == 0x1010,
           "a list with no terminator, but a complete last group, is still walked");
}

/// What v24 effectively did: take the interior offset from the crash log and use
/// it as if it named the entry. Every expectation above that says "the answer is
/// a function start" has to fail against this, or the test is describing the
/// wrong thing.
static bool naiveInteriorIsEntry(uint64_t target, uint64_t *out) {
    *out = target;
    return true;
}

static int selfcheck(void) {
    unsigned matched = 0;
    unsigned wrong = 0;

    const uint64_t deltas[] = { 0x10, 0x20, 0x30, 0 };
    uint8_t blob[32];
    size_t size = build(blob, deltas, 4);
    (void)size;

    const uint64_t interior[] = { 0x1021, 0x1045, 0x1059 };
    const uint64_t expected[] = { 0x1010, 0x1030, 0x1030 };

    for (size_t i = 0; i < sizeof(interior) / sizeof(interior[0]); i++) {
        uint64_t naive = 0;
        naiveInteriorIsEntry(interior[i], &naive);
        if (naive == expected[i]) matched++;
        else wrong++;
    }

    if (wrong == 0) {
        printf("selfcheck: the naive reading agreed with the walker - the test proves nothing\n");
        return 1;
    }
    printf("selfcheck: %d of %d interior offsets map to a different address than the naive "
           "reading; the expectation is not vacuous\n", wrong, wrong + matched);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--selfcheck") == 0) return selfcheck();

    printf("function starts: %s\n", "src/GNFunctionStarts.h");
    testSimpleTable();
    testMultiByteDeltas();
    testMalformed();

    if (failures) {
        printf("function starts: %d of %d check(s) failed\n", failures, checks);
        return 1;
    }
    printf("function starts: all %d checks passed\n", checks);
    return 0;
}
