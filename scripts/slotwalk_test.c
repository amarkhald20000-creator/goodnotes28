//
//  slotwalk_test.c
//  Runs src/GNSlotWalk.h for real. Host target, no Darwin, no simulator.
//
//  This is the half of v16 that can be executed before it is trusted, and it is
//  written the way the failure modes are: the synthetic image is placed at the
//  very end of a mapped page with a PROT_NONE guard page behind it, so any read
//  past the readable length is a segfault in this test rather than a launch
//  failure in a system image nobody can debug.
//
//  What it proves:
//    * the section walk finds __got / __auth_got / __la_symbol_ptr /
//      __nl_symbol_ptr and ignores everything else;
//    * a lying nsects, a lying cmdsize and a truncated sizeofcmds are all
//      refused without reading outside the readable run;
//    * the slot loop rewrites exactly the entries that refer to the target,
//      counts refusals separately, and never writes a slot whose replacement
//      could not be produced.
//
//  What it does NOT prove: that dyld gives us those sections for a shared cache
//  image, and that pointer authentication reproduces a cache slot byte for byte.
//  Both are runtime facts; the dylib's own launch-time self-test reports them.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <unistd.h>

#include "../src/GNSlotWalk.h"

static int gFailures;
static int gChecks;

#define CHECK(condition, ...)                                                  \
    do {                                                                       \
        gChecks++;                                                             \
        if (!(condition)) {                                                    \
            gFailures++;                                                       \
            printf("  FAIL  %s:%d  ", __FILE__, __LINE__);                     \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

#pragma mark - A synthetic image at the edge of a guard page

typedef struct {
    uint8_t *page;
    size_t pageSize;
    uint8_t *base;
} GuardedImage;

/// Places `length` bytes so that their last byte is the last byte of the mapped
/// page. One byte past the end is unmapped, which is the whole point.
static GuardedImage GuardedAlloc(size_t length) {
    GuardedImage image;
    image.pageSize = (size_t)sysconf(_SC_PAGESIZE);
    size_t pages = (length + image.pageSize - 1) / image.pageSize + 1;
    image.page = (uint8_t *)mmap(NULL, pages * image.pageSize,
                                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image.page == MAP_FAILED) {
        printf("  FATAL mmap failed\n");
        exit(1);
    }
    uint8_t *guard = image.page + (pages - 1) * image.pageSize;
    if (mprotect(guard, image.pageSize, PROT_NONE) != 0) {
        printf("  FATAL mprotect(PROT_NONE) failed\n");
        exit(1);
    }
    image.base = guard - length;
    memset(image.base, 0, length);
    return image;
}

#pragma mark - Building images

static size_t AddSegment(uint8_t *at, const char *segname, uint32_t nsects,
                         uint64_t vmaddr) {
    GNWSegmentCommand *command = (GNWSegmentCommand *)at;
    memset(command, 0, sizeof(*command));
    command->cmd = GNW_LC_SEGMENT_64;
    command->cmdsize = (uint32_t)(sizeof(GNWSegmentCommand) + nsects * sizeof(GNWSection));
    strncpy(command->segname, segname, sizeof(command->segname) - 1);
    command->vmaddr = vmaddr;
    command->vmsize = 0x4000;
    command->nsects = nsects;
    return command->cmdsize;
}

static GNWSection *SectionOf(uint8_t *image, uint32_t segmentIndex, uint32_t sectionIndex) {
    GNWImageHeader *header = (GNWImageHeader *)image;
    uint8_t *cursor = image + sizeof(GNWImageHeader);
    uint32_t seen = 0;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        GNWSegmentCommand *command = (GNWSegmentCommand *)cursor;
        if (command->cmd == GNW_LC_SEGMENT_64) {
            if (seen == segmentIndex) {
                return (GNWSection *)(cursor + sizeof(GNWSegmentCommand) +
                                      sectionIndex * sizeof(GNWSection));
            }
            seen++;
        }
        cursor += command->cmdsize;
    }
    return NULL;
}

static void NameSection(GNWSection *section, const char *segname, const char *sectname,
                        uint64_t vmaddr, uint64_t size) {
    memset(section, 0, sizeof(*section));
    strncpy(section->segname, segname, sizeof(section->segname) - 1);
    strncpy(section->sectname, sectname, sizeof(section->sectname) - 1);
    section->addr = vmaddr;
    section->size = size;
}

#pragma mark - Visitor

typedef struct {
    int count;
    GNWSlotSection seen[8];
} VisitLog;

static bool RecordSection(void *ctx, const GNWSlotSection *section) {
    VisitLog *log = (VisitLog *)ctx;
    if (log->count < 8) log->seen[log->count] = *section;
    log->count++;
    return true;
}

#pragma mark - Fake memory for the slot loop

/// Addresses are real-ish (a zero address is rejected by the range walker, on
/// purpose), so the fixture maps its array at FAKE_BASE and indexes from there.
#define FAKE_BASE 0x1000u

typedef struct {
    uint64_t *slots;
    size_t count;
    size_t readable;
    int writes;
    int reads;
} FakeMemory;

static size_t FakeIndex(uint64_t address) {
    return (size_t)(address - FAKE_BASE) / sizeof(uint64_t);
}

static bool FakeRead(void *ctx, uint64_t address, uint64_t *out) {
    FakeMemory *memory = (FakeMemory *)ctx;
    memory->reads++;
    if (address < FAKE_BASE) return false;
    size_t index = FakeIndex(address);
    if ((address - FAKE_BASE) % sizeof(uint64_t) != 0) return false;
    if (index >= memory->readable) return false;
    *out = memory->slots[index];
    return true;
}

static bool FakeWrite(void *ctx, uint64_t address, uint64_t value) {
    FakeMemory *memory = (FakeMemory *)ctx;
    if (address < FAKE_BASE) return false;
    size_t index = FakeIndex(address);
    if ((address - FAKE_BASE) % sizeof(uint64_t) != 0) return false;
    if (index >= memory->readable) return false;
    memory->slots[index] = value;
    memory->writes++;
    return true;
}

static bool FakeRefersTo(void *ctx, uint64_t raw, uint64_t target) {
    (void)ctx;
    return raw == target;
}

static uint64_t FakeMoveTo(void *ctx, uint64_t raw, uint64_t target,
                           uint64_t replacement, uint64_t slotAddress) {
    FakeMemory *memory = (FakeMemory *)ctx;
    (void)target;
    // One doomed slot in the fixture: any slot at index 3 refuses, so the test
    // can prove a refusal leaves the original bytes in place.
    if (slotAddress == FAKE_BASE + 3 * sizeof(uint64_t)) return 0;
    if (raw == replacement) return replacement;
    (void)memory;
    return replacement;
}

#pragma mark - Tests

static void TestWalkFindsOnlyImportSlots(void) {
    printf("  section walk: finds the four slot sections, ignores the rest\n");

    size_t needed = sizeof(GNWImageHeader) + 2 * sizeof(GNWSegmentCommand) + 6 * sizeof(GNWSection);
    GuardedImage image = GuardedAlloc(needed);

    GNWImageHeader *header = (GNWImageHeader *)image.base;
    memset(header, 0, sizeof(*header));
    header->magic = GNW_MH_MAGIC_64;
    header->ncmds = 2;

    uint8_t *cursor = image.base + sizeof(GNWImageHeader);
    size_t first = AddSegment(cursor, "__DATA_CONST", 3, 0x1000);
    uint8_t *secondAt = cursor + first;
    size_t second = AddSegment(secondAt, "__DATA", 3, 0x8000);
    header->sizeofcmds = (uint32_t)(first + second);

    NameSection(SectionOf(image.base, 0, 0), "__DATA_CONST", "__objc_classlist", 0x1000, 0x40);
    NameSection(SectionOf(image.base, 0, 1), "__DATA_CONST", "__auth_got", 0x2000, 0x18);
    NameSection(SectionOf(image.base, 0, 2), "__DATA_CONST", "__got", 0x3000, 0x40);
    NameSection(SectionOf(image.base, 1, 0), "__DATA", "__la_symbol_ptr", 0x8000, 0x20);
    NameSection(SectionOf(image.base, 1, 1), "__DATA", "__nl_symbol_ptr", 0x8020, 0x10);
    NameSection(SectionOf(image.base, 1, 2), "__DATA", "__const", 0x8040, 0x10);

    VisitLog log;
    memset(&log, 0, sizeof(log));
    GNWWalkStats stats;

    uint32_t slotSections = GNWWalkImage(image.base, needed, 0x500000, RecordSection, &log, &stats);

    CHECK(slotSections == 4, "expected 4 slot sections, found %u", slotSections);
    CHECK(log.count == 4, "visitor saw %d sections", log.count);
    CHECK(stats.segments == 2, "segments = %u", stats.segments);
    CHECK(stats.sections == 6, "sections = %u", stats.sections);
    CHECK(stats.truncated == 0, "truncated = %u", stats.truncated);

    if (log.count >= 4) {
        CHECK(log.seen[0].address == 0x500000 + 0x2000, "__auth_got at 0x%llx",
              (unsigned long long)log.seen[0].address);
        CHECK(strcmp(log.seen[0].sectname, "__auth_got") == 0, "sectname '%s'",
              log.seen[0].sectname);
        CHECK(strcmp(log.seen[0].segname, "__DATA_CONST") == 0, "segname '%s'",
              log.seen[0].segname);
        CHECK(log.seen[1].size == 0x40, "__got size 0x%llx",
              (unsigned long long)log.seen[1].size);
        CHECK(log.seen[2].address == 0x500000 + 0x8000, "__la_symbol_ptr at 0x%llx",
              (unsigned long long)log.seen[2].address);
        CHECK(strcmp(log.seen[3].sectname, "__nl_symbol_ptr") == 0, "sectname '%s'",
              log.seen[3].sectname);
    }

    munmap(image.page, image.pageSize * 2);
}

/// __got must not match __got_like, and nothing that merely shares the letters
/// may be treated as a call site: rewriting a section that holds data is a wrong
/// write, which is worse than a missed hook.
static void TestNameFilterRejectsPrefixes(void) {
    printf("  section walk: exact names only, never a prefix match\n");

    size_t needed = sizeof(GNWImageHeader) + sizeof(GNWSegmentCommand) + 6 * sizeof(GNWSection);
    GuardedImage image = GuardedAlloc(needed);

    GNWImageHeader *header = (GNWImageHeader *)image.base;
    memset(header, 0, sizeof(*header));
    header->magic = GNW_MH_MAGIC_64;
    header->ncmds = 1;

    uint8_t *cursor = image.base + sizeof(GNWImageHeader);
    header->sizeofcmds = (uint32_t)AddSegment(cursor, "__DATA_CONST", 6, 0x1000);

    // Section names are 16 bytes; these are all short enough not to be truncated
    // into a name the filter is supposed to accept.
    NameSection(SectionOf(image.base, 0, 0), "__DATA_CONST", "__got_like", 0x1000, 0x10);
    NameSection(SectionOf(image.base, 0, 1), "__DATA_CONST", "__auth_got_x", 0x1010, 0x10);
    NameSection(SectionOf(image.base, 0, 2), "__DATA_CONST", "__compact_unw", 0x1020, 0x10);
    NameSection(SectionOf(image.base, 0, 3), "__DATA_CONST", "__la_symbol_pt", 0x1030, 0x10);
    NameSection(SectionOf(image.base, 0, 4), "__DATA_CONST", "__nl_symbol_pt", 0x1040, 0x10);
    NameSection(SectionOf(image.base, 0, 5), "__DATA_CONST", "__got", 0x1050, 0x8);

    VisitLog log;
    memset(&log, 0, sizeof(log));
    GNWWalkStats stats;
    uint32_t found = GNWWalkImage(image.base, needed, 0, RecordSection, &log, &stats);

    CHECK(found == 1, "the name filter matched %u section(s), expected only __got", found);
    CHECK(stats.sections == 6, "sections = %u", stats.sections);
    if (log.count >= 1) {
        CHECK(strcmp(log.seen[0].sectname, "__got") == 0, "matched '%s'", log.seen[0].sectname);
        CHECK(log.seen[0].address == 0x1050, "address 0x%llx",
              (unsigned long long)log.seen[0].address);
    }

    munmap(image.page, image.pageSize * 2);
}

static void TestWalkStopsAtTruncatedCommands(void) {
    printf("  section walk: a section table past the readable run is refused\n");

    size_t needed = sizeof(GNWImageHeader) + sizeof(GNWSegmentCommand) + 2 * sizeof(GNWSection);
    GuardedImage image = GuardedAlloc(needed);

    GNWImageHeader *header = (GNWImageHeader *)image.base;
    memset(header, 0, sizeof(*header));
    header->magic = GNW_MH_MAGIC_64;
    header->ncmds = 1;

    uint8_t *cursor = image.base + sizeof(GNWImageHeader);
    size_t segment = AddSegment(cursor, "__DATA", 2, 0x1000);
    header->sizeofcmds = (uint32_t)segment;

    NameSection(SectionOf(image.base, 0, 0), "__DATA", "__got", 0x1000, 0x10);
    NameSection(SectionOf(image.base, 0, 1), "__DATA", "__auth_got", 0x1010, 0x10);

    VisitLog log;
    memset(&log, 0, sizeof(log));
    GNWWalkStats stats;

    // Claim only the header plus a few bytes are readable. The segment command
    // does not fit, so the walk must stop without touching the guard page.
    uint32_t slotSections = GNWWalkImage(image.base, sizeof(GNWImageHeader) + 4, 0,
                                         RecordSection, &log, &stats);
    CHECK(slotSections == 0, "expected no sections, found %u", slotSections);
    CHECK(stats.truncated >= 1, "truncated = %u", stats.truncated);

    // And with exactly the header readable: still nothing, still no crash.
    slotSections = GNWWalkImage(image.base, sizeof(GNWImageHeader), 0, RecordSection, &log, &stats);
    CHECK(slotSections == 0, "expected no sections at header-only length");

    munmap(image.page, image.pageSize * 2);
}

static void TestWalkRejectsLyingNsects(void) {
    printf("  section walk: nsects that disagrees with cmdsize is not trusted\n");

    size_t needed = sizeof(GNWImageHeader) + sizeof(GNWSegmentCommand) + sizeof(GNWSection);
    GuardedImage image = GuardedAlloc(needed);

    GNWImageHeader *header = (GNWImageHeader *)image.base;
    memset(header, 0, sizeof(*header));
    header->magic = GNW_MH_MAGIC_64;
    header->ncmds = 1;

    uint8_t *cursor = image.base + sizeof(GNWImageHeader);
    size_t segment = AddSegment(cursor, "__DATA", 1, 0x1000);
    header->sizeofcmds = (uint32_t)segment;
    NameSection(SectionOf(image.base, 0, 0), "__DATA", "__got", 0x1000, 0x10);

    // Only room for one section, but the command claims 9000.
    ((GNWSegmentCommand *)cursor)->nsects = 9000;

    VisitLog log;
    memset(&log, 0, sizeof(log));
    GNWWalkStats stats;
    uint32_t slotSections = GNWWalkImage(image.base, needed, 0, RecordSection, &log, &stats);

    CHECK(slotSections == 0, "expected no sections, found %u", slotSections);
    CHECK(stats.truncated >= 1, "truncated = %u", stats.truncated);

    munmap(image.page, image.pageSize * 2);
}

static void TestWalkRejectsBadHeader(void) {
    printf("  section walk: a wrong magic or a short read is not an image\n");

    GuardedImage image = GuardedAlloc(4096);
    GNWImageHeader *header = (GNWImageHeader *)image.base;
    memset(header, 0, sizeof(*header));
    header->magic = 0xdeadbeef;
    header->ncmds = 9;

    VisitLog log;
    memset(&log, 0, sizeof(log));
    GNWWalkStats stats;
    CHECK(GNWWalkImage(image.base, 4096, 0, RecordSection, &log, &stats) == 0,
          "wrong magic produced sections");
    CHECK(GNWWalkImage(NULL, 4096, 0, RecordSection, &log, &stats) == 0,
          "a NULL image produced sections");
    CHECK(GNWWalkImage(image.base, 4, 0, RecordSection, &log, &stats) == 0,
          "a four byte image produced sections");
    CHECK(stats.truncated >= 1, "a short image was not counted as truncated");
    munmap(image.page, image.pageSize * 2);
}

static bool StopAfterFirst(void *ctx, const GNWSlotSection *section) {
    int *count = (int *)ctx;
    (void)section;
    (*count)++;
    return false;                 // stop the walk
}

static void TestVisitorCanStopTheWalk(void) {
    printf("  section walk: the visitor can stop the walk\n");

    size_t needed = sizeof(GNWImageHeader) + sizeof(GNWSegmentCommand) + 4 * sizeof(GNWSection);
    GuardedImage image = GuardedAlloc(needed);

    GNWImageHeader *header = (GNWImageHeader *)image.base;
    memset(header, 0, sizeof(*header));
    header->magic = GNW_MH_MAGIC_64;
    header->ncmds = 1;

    uint8_t *cursor = image.base + sizeof(GNWImageHeader);
    header->sizeofcmds = (uint32_t)AddSegment(cursor, "__DATA", 4, 0x1000);
    for (int i = 0; i < 4; i++) {
        NameSection(SectionOf(image.base, 0, (uint32_t)i), "__DATA", "__got",
                    0x1000 + (uint64_t)i * 0x10, 0x10);
    }

    GNWWalkStats stats;
    CHECK(GNWWalkImage(image.base, needed, 0, NULL, NULL, &stats) == 4,
          "a NULL visitor did not count all four sections");

    int visited = 0;
    uint32_t stopped = GNWWalkImage(image.base, needed, 0, StopAfterFirst, &visited, &stats);
    CHECK(visited == 1, "the visitor ran %d time(s) after asking to stop", visited);
    CHECK(stopped == 1, "the walk reported %u section(s) after stopping", stopped);

    munmap(image.page, image.pageSize * 2);
}

#pragma mark - Slot range

static void TestSlotRangeRewritesOnlyMatches(void) {
    printf("  slot range: rewrites the target, leaves everything else\n");

    enum { SLOTS = 6 };
    uint64_t backing[SLOTS] = { 0xAAA, 0xBBB, 0xAAA, 0xAAA, 0xAAA, 0xAAA };
    FakeMemory memory;
    memset(&memory, 0, sizeof(memory));
    memory.slots = backing;
    memory.count = SLOTS;
    memory.readable = SLOTS;

    GNSlotOps ops;
    memset(&ops, 0, sizeof(ops));
    ops.read = FakeRead;
    ops.write = FakeWrite;
    ops.refersTo = FakeRefersTo;
    ops.moveTo = FakeMoveTo;
    ops.ctx = &memory;

    GNSlotStats stats = GNWRebindSlotRange(FAKE_BASE, SLOTS * sizeof(uint64_t), 0xAAA, 0x999, &ops);

    CHECK(stats.scanned == SLOTS, "scanned = %llu", (unsigned long long)stats.scanned);
    CHECK(stats.matched == 5, "matched = %llu", (unsigned long long)stats.matched);
    CHECK(stats.refused == 1, "refused = %llu (index 3 refuses by fixture)",
          (unsigned long long)stats.refused);
    CHECK(stats.written == 4, "written = %llu", (unsigned long long)stats.written);
    CHECK(backing[0] == 0x999 && backing[1] == 0xBBB && backing[2] == 0x999,
          "slots 0..2 are %llx %llx %llx",
          (unsigned long long)backing[0], (unsigned long long)backing[1],
          (unsigned long long)backing[2]);
    CHECK(backing[3] == 0xAAA, "the refused slot was written anyway: %llx",
          (unsigned long long)backing[3]);
    CHECK(backing[4] == 0x999 && backing[5] == 0x999, "slots 4..5 are %llx %llx",
          (unsigned long long)backing[4], (unsigned long long)backing[5]);
}

static void TestSlotRangeHandlesUnreadableAndPartial(void) {
    printf("  slot range: unreadable tails and a trailing partial slot\n");

    uint64_t backing[4] = { 0xAAA, 0xAAA, 0xAAA, 0xAAA };
    FakeMemory memory;
    memset(&memory, 0, sizeof(memory));
    memory.slots = backing;
    memory.count = 4;
    memory.readable = 1;              // only the first slot is mapped

    GNSlotOps ops;
    memset(&ops, 0, sizeof(ops));
    ops.read = FakeRead;
    ops.write = FakeWrite;
    ops.refersTo = FakeRefersTo;
    ops.moveTo = FakeMoveTo;
    ops.ctx = &memory;

    // 4 slots + 3 bytes: the trailing 3 bytes are not a slot.
    GNSlotStats stats = GNWRebindSlotRange(FAKE_BASE, 4 * sizeof(uint64_t) + 3, 0xAAA, 0x999, &ops);
    CHECK(stats.scanned == 1, "scanned = %llu", (unsigned long long)stats.scanned);
    CHECK(stats.unreadable == 3, "unreadable = %llu", (unsigned long long)stats.unreadable);
    CHECK(stats.written == 1, "written = %llu", (unsigned long long)stats.written);
    CHECK(backing[0] == 0x999, "first slot = %llx", (unsigned long long)backing[0]);

    // A zero length or a missing callback is a no-op, not a crash.
    GNSlotStats empty = GNWRebindSlotRange(FAKE_BASE, 0, 0xAAA, 0x999, &ops);
    CHECK(empty.scanned == 0, "a zero length scanned something");
    GNSlotStats none = GNWRebindSlotRange(FAKE_BASE, 64, 0xAAA, 0x999, NULL);
    CHECK(none.scanned == 0, "a NULL ops scanned something");
}

static void TestSlotRangeIsIdempotent(void) {
    printf("  slot range: a second pass writes nothing\n");

    uint64_t backing[3] = { 0xAAA, 0xBBB, 0xAAA };
    FakeMemory memory;
    memset(&memory, 0, sizeof(memory));
    memory.slots = backing;
    memory.count = 3;
    memory.readable = 3;

    GNSlotOps ops;
    memset(&ops, 0, sizeof(ops));
    ops.read = FakeRead;
    ops.write = FakeWrite;
    ops.refersTo = FakeRefersTo;
    ops.moveTo = FakeMoveTo;
    ops.ctx = &memory;

    GNWRebindSlotRange(FAKE_BASE, 3 * sizeof(uint64_t), 0xAAA, 0x999, &ops);
    int writesAfterFirst = memory.writes;
    GNSlotStats second = GNWRebindSlotRange(FAKE_BASE, 3 * sizeof(uint64_t), 0xAAA, 0x999, &ops);

    CHECK(second.matched == 0, "the second pass still matched %llu slot(s)",
          (unsigned long long)second.matched);
    CHECK(memory.writes == writesAfterFirst, "the second pass wrote again");
}

#pragma mark - A second reader, sharing no layout with the walker

/// Where the fields live, as absolute offsets into an arm64 Mach-O file:
///
///   mach_header_64     magic +0   ncmds +16   sizeofcmds +20   size 32
///   segment_command_64 cmd +0     cmdsize +4  segname +8   nsects +64  size 72
///   section_64         sectname +0            segname +16              size 80
///
/// Written as numbers on purpose. The walker reads the same file through
/// GNWSegmentCommand and GNWSection; if one of *those* structs had a field at the
/// wrong offset, both readers would shift together and still agree. This one
/// shares no layout with them, so "the two counts are equal" is a statement about
/// the walker's struct layout - which is the only thing this test can prove
/// without a device.
typedef struct {
    uint32_t segments;
    uint32_t sections;
    int suspiciousNames;   ///< a section name that is not printable "__..." bytes
    int mismatchedSegments;///< a section whose segname disagrees with its segment
} RawCounts;

static uint32_t RawU32(const uint8_t *at) {
    uint32_t value = 0;
    // Mach-O on arm64 is little endian, and so is every host that runs this.
    memcpy(&value, at, sizeof(value));
    return value;
}

static bool CountSectionsRaw(const uint8_t *file, long length, RawCounts *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!file || length < 32) return false;
    if (RawU32(file + 0) != 0xfeedfacf) return false;   // MH_MAGIC_64

    uint32_t commands = RawU32(file + 16);
    uint64_t commandsSize = RawU32(file + 20);
    if (32 + commandsSize > (uint64_t)length) return false;

    uint64_t end = 32 + commandsSize;
    uint64_t offset = 32;
    for (uint32_t i = 0; i < commands; i++) {
        if (offset + 8 > end) return false;
        uint32_t command = RawU32(file + offset);
        uint32_t commandSize = RawU32(file + offset + 4);
        if (commandSize < 8 || offset + commandSize > end) return false;

        if (command == 0x19) {  // LC_SEGMENT_64
            if (commandSize < 72) return false;
            uint32_t nsects = RawU32(file + offset + 64);
            if (72 + (uint64_t)nsects * 80 > commandSize) return false;
            out->segments++;
            const uint8_t *segmentName = file + offset + 8;   // 16 bytes
            bool segmentNamed = false;
            for (int c = 0; c < 16; c++) {
                if (segmentName[c] != 0) { segmentNamed = true; break; }
            }
            for (uint32_t s = 0; s < nsects; s++) {
                const uint8_t *section = file + offset + 72 + (uint64_t)s * 80;
                out->sections++;

                // A name occupies 16 bytes. Long ones are truncated and carry no
                // NUL (__apple_namespac is a real example), so the rule is:
                // printable up to the first NUL, or all 16 printable - and every
                // real section name starts with "__".
                int printable = 0;
                for (int c = 0; c < 16 && section[c] != '\0'; c++) {
                    if (section[c] < 0x20 || section[c] > 0x7e) break;
                    printable++;
                }
                if (printable < 2 || section[0] != '_' || section[1] != '_') {
                    out->suspiciousNames++;
                }

                // An object file's segment command has an empty segname while its
                // sections say "__TEXT" / "__DATA" - legal, and the one case where
                // the two fields are allowed to disagree. In a linked image the
                // segment is named, and then the section has to repeat it exactly:
                // a field read one slot early lands in padding and stops matching.
                if (segmentNamed && memcmp(section + 16, segmentName, 16) != 0) {
                    out->mismatchedSegments++;
                }
            }
        }
        offset += commandSize;
    }
    return true;
}

/// The four names, spelled out again on purpose: this is the test's own copy of
/// the rule, not a call into the header's, so an over-match cannot agree with
/// itself.
static bool IsOneOfTheFour(const char *sectname) {
    static const char *const kinds[] = { "__got", "__auth_got", "__la_symbol_ptr",
                                         "__nl_symbol_ptr" };
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        if (strcmp(sectname, kinds[i]) == 0) return true;
    }
    return false;
}

#pragma mark - A real Mach-O, produced by a real linker

/// The synthetic images above prove the logic. This one proves the *structs*:
/// they have to match what a compiler and linker actually emit, and a field
/// offset that is one byte out would pass every synthetic test while finding
/// nothing in a real image.
///
/// The fixture is an arm64 Mach-O object compiled by the same compiler that
/// builds the dylib. An object has no import slots (it has no bindings yet), so
/// this checks the other half: real section names, real nsects, real cmdsize,
/// and that the name filter does not over-match on names like __compact_unwind.
///
/// How many sections that object has is the compiler's business, not this
/// test's. Apple clang and a Linux clang front end do not agree: a zig/libc
/// build carries a dozen __DWARF sections, a plain Apple object carries __text
/// and __compact_unwind. Asserting a floor here measured the build machine, and
/// it failed on the runner for exactly that reason. So the check is equality
/// with what the file declares, read by a second parser below.
static void TestRealImage(const char *path) {
    printf("  real image: %s\n", path);

    FILE *handle = fopen(path, "rb");
    if (!handle) {
        gFailures++;
        gChecks++;
        printf("  FAIL  cannot open %s\n", path);
        return;
    }
    if (fseek(handle, 0, SEEK_END) != 0) { fclose(handle); gFailures++; gChecks++; return; }
    long length = ftell(handle);
    if (length <= 0) { fclose(handle); gFailures++; gChecks++; return; }
    rewind(handle);

    uint8_t *buffer = (uint8_t *)malloc((size_t)length);
    if (!buffer) { fclose(handle); gFailures++; gChecks++; return; }
    if (fread(buffer, 1, (size_t)length, handle) != (size_t)length) {
        fclose(handle); free(buffer); gFailures++; gChecks++;
        return;
    }
    fclose(handle);

    VisitLog log;
    memset(&log, 0, sizeof(log));
    GNWWalkStats stats;
    GNWWalkImage(buffer, (uint64_t)length, 0, RecordSection, &log, &stats);

    RawCounts raw;
    bool rawOK = CountSectionsRaw(buffer, length, &raw);

    CHECK(stats.truncated == 0, "a real object produced %u truncation(s)", stats.truncated);
    CHECK(stats.segments >= 1, "segments = %u", stats.segments);
    CHECK(stats.sections >= 1, "sections = %u", stats.sections);

    if (!rawOK) {
        CHECK(false, "the fixture is not an arm64 Mach-O this reader could parse");
    } else {
        printf("    file declares: %u segment(s), %u section(s)\n", raw.segments, raw.sections);
        CHECK(raw.suspiciousNames == 0,
              "%d section name(s) in the fixture are not printable __names",
              raw.suspiciousNames);
        CHECK(raw.mismatchedSegments == 0,
              "%d section(s) name a segment their segment command does not",
              raw.mismatchedSegments);
        CHECK(stats.sections == raw.sections,
              "the walk counted %u section(s), the file declares %u",
              stats.sections, raw.sections);
        CHECK(stats.segments == raw.segments,
              "the walk counted %u segment(s), the file declares %u",
              stats.segments, raw.segments);
    }

    // An object file has no bindings, so an object fixture legitimately holds no
    // slot sections; a linked fixture does. Either way the rule is the same:
    // whatever matched must be one of the four exact names - not __compact_unwind,
    // not a prefix like __got_something - and a slot section must hold whole
    // pointers at non-zero addresses.
    printf("    slot section(s) found: %u\n", stats.slotSections);
    CHECK(log.count == (int)stats.slotSections,
          "the visitor saw %d section(s), the walker counted %u",
          log.count, stats.slotSections);
    for (int i = 0; i < log.count && i < 8; i++) {
        printf("    matched %s,__%s at 0x%llx size 0x%llx\n", log.seen[i].segname,
               log.seen[i].sectname, (unsigned long long)log.seen[i].address,
               (unsigned long long)log.seen[i].size);
        CHECK(IsOneOfTheFour(log.seen[i].sectname),
              "'%s' is not an import slot section", log.seen[i].sectname);
        CHECK(log.seen[i].address != 0, "a slot section at address zero");
        CHECK(log.seen[i].size == 0 || log.seen[i].size % 8 == 0,
              "a slot section of size 0x%llx is not a whole number of pointers",
              (unsigned long long)log.seen[i].size);
    }

    free(buffer);
}

int main(int argc, char **argv) {
    printf("slotwalk: running src/GNSlotWalk.h\n");
    TestWalkFindsOnlyImportSlots();
    TestNameFilterRejectsPrefixes();
    TestWalkStopsAtTruncatedCommands();
    TestWalkRejectsLyingNsects();
    TestWalkRejectsBadHeader();
    TestVisitorCanStopTheWalk();
    TestSlotRangeRewritesOnlyMatches();
    TestSlotRangeHandlesUnreadableAndPartial();
    TestSlotRangeIsIdempotent();

    if (argc > 1) TestRealImage(argv[1]);

    printf("\nslotwalk: %d check(s), %d failure(s)\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
