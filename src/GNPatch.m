//
//  GNPatch.m
//  Config driven unlocking engine.
//
//  Three ways to change behaviour, in order of how much you can trust them:
//
//    BytePatches   - a static offset in a known image. Exact, but tied to one
//                    build of the app. Offsets are relative to the image's
//                    __TEXT start, so they survive ASLR.
//    Anchors       - a C string the code references. The dylib finds the
//                    ADRP+ADD pair, walks back to the function start and
//                    applies the action there. Survives small app updates as
//                    long as the string reference does not move.
//    Swizzles      - ObjC only. Useless for the Swift-only purchase stack, but
//                    handy for everything else.
//
//  Everything honours DryRun: it logs what it would do and writes nothing.
//

#import "GNUnlock.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <string.h>
#import <stdlib.h>

#pragma mark - Instruction helpers

static uint32_t GNReadInsn(uintptr_t address) {
    return *(const uint32_t *)address;
}

static BOOL GNDecodeADRP(uint32_t insn, uintptr_t pc, uintptr_t *pageOut) {
    if ((insn & 0x9F000000) != 0x90000000) return NO;

    int64_t immlo = (insn >> 29) & 0x3;
    int64_t immhi = (insn >> 5) & 0x7FFFF;
    int64_t imm21 = (immhi << 2) | immlo;
    if (imm21 & (1LL << 20)) imm21 -= (1LL << 21);

    intptr_t page = (intptr_t)(pc & ~(uintptr_t)0xFFF) + (intptr_t)(imm21 * 4096);
    if (pageOut) *pageOut = (uintptr_t)page;
    return YES;
}

static BOOL GNDecodeADDImm(uint32_t insn, uint32_t *rdOut, uint32_t *rnOut, uint64_t *immOut) {
    if ((insn & 0xFF800000) != 0x91000000) return NO;
    uint32_t rd = insn & 0x1F;
    uint32_t rn = (insn >> 5) & 0x1F;
    uint64_t imm = (insn >> 10) & 0xFFF;
    if ((insn >> 22) & 1) imm <<= 12;
    if (rdOut) *rdOut = rd;
    if (rnOut) *rnOut = rn;
    if (immOut) *immOut = imm;
    return YES;
}

static BOOL GNIsFunctionTerminator(uint32_t insn) {
    if (insn == 0xD65F03C0) return YES;                 // ret
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) return YES;  // retaa / retab
    if ((insn & 0xFFE0001F) == 0xD4200000) return YES;  // brk / udf
    return NO;
}

static BOOL GNLooksLikePrologue(uint32_t insn) {
    if (insn == 0xD503237F) return YES;                          // pacibsp
    if (insn == 0xD503245F) return YES;                          // bti c
    if (insn == 0xA9BF7BFD) return YES;                          // stp x29,x30,[sp,#-16]!
    if ((insn & 0xFFC00000) == 0xA9800000) return YES;           // any stp with x29
    if ((insn & 0xFF8003FF) == 0xD10003FF) return YES;           // sub sp, sp, #imm
    return NO;
}

static uintptr_t GNFindFunctionStart(uintptr_t textStart, uintptr_t textEnd,
                                     uintptr_t site, NSUInteger *distanceOut) {
    const size_t kMaxScan = 0x800;
    uintptr_t lowest = site;
    uintptr_t cursor = site;

    size_t scanned = 0;
    while (cursor > textStart + 4 && scanned < kMaxScan) {
        cursor -= 4;
        scanned += 4;
        uint32_t insn = GNReadInsn(cursor);
        if (GNIsFunctionTerminator(insn)) {
            break;
        }
        if (GNLooksLikePrologue(insn)) {
            lowest = cursor;
        }
    }
    if (distanceOut) *distanceOut = (NSUInteger)(site - lowest);
    return lowest;
}

#pragma mark - Section helpers

static BOOL GNTextBounds(const char *image, uintptr_t *start, uintptr_t *end) {
    uintptr_t addr = 0;
    uint64_t size = 0;
    if (!GNSection(image, "__TEXT", "__text", &addr, &size)) return NO;
    if (start) *start = addr;
    if (end) *end = addr + size;
    return YES;
}

static uintptr_t GNFindCString(const char *image, const char *needle) {
    if (!needle || !*needle) return 0;
    size_t needleLen = strlen(needle);

    const char *sections[][2] = {
        { "__TEXT", "__cstring" },
        { "__TEXT", "__objc_methname" },
        { "__DATA", "__objc_selrefs" },
    };

    for (size_t i = 0; i < sizeof(sections) / sizeof(sections[0]); i++) {
        if (strcmp(sections[i][1], "__objc_selrefs") == 0) continue; // pointer array, not strings

        uintptr_t addr = 0;
        uint64_t size = 0;
        if (!GNSection(image, sections[i][0], sections[i][1], &addr, &size)) continue;

        if (!addr || size <= needleLen + 1) continue;
        const char *begin = (const char *)addr;
        const char *last = begin + size - needleLen - 1;
        for (const char *p = begin; p <= last; p++) {
            if (memcmp(p, needle, needleLen) == 0 && p[needleLen] == '\0') {
                return (uintptr_t)p;
            }
        }
    }
    return 0;
}

#pragma mark - Target checks

/// Refuses targets that can never be written safely, whatever the certificate.
///
/// Anything inside a system image (dyld shared cache, /System, /usr/lib) is
/// code that belongs to Apple, is covered by a signature we do not own, and
/// cannot be re-signed by us. Writing to it is the CODESIGNING / Invalid Page
/// crash. The only fix for such a call site is to intercept the caller or to
/// patch the app's own Mach-O on disk before signing.
static BOOL GNEnsurePatchableTarget(NSString *image, NSString *label) {
    const char *name = image.UTF8String;
    int index = GNImageIndexForName(name);

    if (index < 0) {
        GNLogC("%s: image '%s' not loaded - skipped", label.UTF8String, name);
        return NO;
    }

    const char *path = _dyld_get_image_name((uint32_t)index);
    if (GNIsSystemImagePath(path)) {
        GNLogC("%s: '%s' is a system image (%s) - REFUSED", label.UTF8String, name,
               path ?: "?");
        GNLogC("  shared cache pages are signed by Apple; patching one from inside the "
               "process is always fatal");
        GNLogC("  intercept the caller instead (Hooks section) or patch the app's own "
               "Mach-O offline (scripts/gnstatic.py)");
        return NO;
    }

    if (!GNIsAppOwnedImage((uint32_t)index)) {
        GNLogC("%s: '%s' is not part of the app bundle - skipped", label.UTF8String, name);
        return NO;
    }

    return YES;
}

#pragma mark - Patch primitives

static const uint8_t GNBytesRet1[8] = { 0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6 };
static const uint8_t GNBytesRet0[8] = { 0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6 };
static const uint8_t GNBytesNop[4]  = { 0x1F, 0x20, 0x03, 0xD5 };

static BOOL GNApplyCodeAction(NSString *action, NSString *customHex,
                              const char *image, uintptr_t address,
                              NSString *label) {
    const void *bytes = NULL;
    size_t length = 0;
    void *owned = NULL;

    BOOL isWrite = ([action isEqualToString:@"ret1"] || [action isEqualToString:@"ret0"] ||
                    [action isEqualToString:@"zero"] || [action isEqualToString:@"nop"] ||
                    [action isEqualToString:@"bytes"]);
    if (isWrite && !GNCodePatchingAllowed()) {
        GNLogC("  -> %s: skipped - %s signature, executable writes are not available",
               label.UTF8String, GNSignatureMode());
        GNLogC("     same effect offline: scripts/gnstatic.py patch (see README)");
        return NO;
    }

    if ([action isEqualToString:@"ret1"]) {
        bytes = GNBytesRet1;
        length = sizeof(GNBytesRet1);
    } else if ([action isEqualToString:@"ret0"] || [action isEqualToString:@"zero"]) {
        bytes = GNBytesRet0;
        length = sizeof(GNBytesRet0);
    } else if ([action isEqualToString:@"nop"]) {
        bytes = GNBytesNop;
        length = sizeof(GNBytesNop);
    } else if ([action isEqualToString:@"bytes"]) {
        size_t parsed = 0;
        if (!GNDataFromHex(customHex, &owned, &parsed) || parsed == 0) {
            GNLogC("  -> %s: bad Bytes field", label.UTF8String);
            return NO;
        }
        bytes = owned;
        length = parsed;
    } else {
        return NO; // "log" and anything unknown: nothing to write
    }

    if (!GNContainsAddress(image, address, length)) {
        GNLogC("  -> %s: address 0x%llx not inside '%s' - refused",
               label.UTF8String, (unsigned long long)address, image);
        if (owned) free(owned);
        return NO;
    }

    NSData *before = [NSData dataWithBytes:(const void *)address length:length];
    BOOL dryRun = GNCFG(@"DryRun", NO);
    NSString *pretty = [before.description stringByReplacingOccurrencesOfString:@" " withString:@""];

    if (dryRun) {
        GNLogC("  -> %s: DRY RUN, would write %zu bytes at 0x%llx (currently %s)",
               label.UTF8String, length, (unsigned long long)address, pretty.UTF8String);
        if (owned) free(owned);
        return YES;
    }

    BOOL ok = GNPatchCodeBytes(address, bytes, length);
    GNLogC("  -> %s: wrote %zu bytes at 0x%llx (was %s) %s",
           label.UTF8String, length, (unsigned long long)address, pretty.UTF8String,
           ok ? "ok" : "FAILED");

    if (owned) free(owned);
    return ok;
}

#pragma mark - Byte patches

static void GNApplyBytePatches(NSDictionary *cfg) {
    NSArray *patches = cfg[@"BytePatches"];
    if (![patches isKindOfClass:[NSArray class]] || patches.count == 0) {
        GNLogC("bytepatches: none configured");
        return;
    }

    int index = 0;
    for (id entry in patches) {
        index++;
        if (![entry isKindOfClass:[NSDictionary class]]) continue;

        NSString *image = entry[@"Image"];
        if (![image isKindOfClass:[NSString class]] || image.length == 0) {
            image = [NSString stringWithUTF8String:GNMainImageName()];
        }
        NSString *bpLabel = [NSString stringWithFormat:@"bytepatches[%d]", index];
        if (!GNEnsurePatchableTarget(image, bpLabel)) continue;

        uint64_t offset = 0;
        id offsetValue = entry[@"Offset"];
        if ([offsetValue isKindOfClass:[NSString class]]) {
            GNParseAddress(offsetValue, &offset);
        } else if ([offsetValue respondsToSelector:@selector(unsignedLongLongValue)]) {
            offset = [offsetValue unsignedLongLongValue];
        }
        if (offset == 0) {
            GNLogC("bytepatches[%d]: missing/invalid Offset - skipped", index);
            continue;
        }

        uintptr_t base = GNImageBase(image.UTF8String);
        uintptr_t address = base + (uintptr_t)offset;
        NSString *note = entry[@"Note"] ?: @"";
        NSString *action = entry[@"Action"] ?: @"bytes";
        NSString *hex = entry[@"Bytes"];

        GNLogC("bytepatches[%d]: %s + 0x%llx = 0x%llx  %s",
               index, image.UTF8String, (unsigned long long)offset,
               (unsigned long long)address, note.UTF8String);

        if ([action isEqualToString:@"log"]) {
            uint32_t insn = GNContainsAddress(image.UTF8String, address, 4)
                ? GNReadInsn(address) : 0;
            GNLogC("  -> 0x%08x", insn);
            continue;
        }

        GNApplyCodeAction(action, hex, image.UTF8String, address,
                          [NSString stringWithFormat:@"bytepatches[%d]", index]);
    }
}

#pragma mark - Anchors

static void GNApplyAnchors(NSDictionary *cfg) {
    NSArray *anchors = cfg[@"Anchors"];
    if (![anchors isKindOfClass:[NSArray class]] || anchors.count == 0) {
        GNLogC("anchors: none configured");
        return;
    }

    int index = 0;
    for (id entry in anchors) {
        index++;
        if (![entry isKindOfClass:[NSDictionary class]]) continue;

        NSString *needle = entry[@"String"];
        if (![needle isKindOfClass:[NSString class]] || needle.length == 0) {
            GNLogC("anchors[%d]: missing String - skipped", index);
            continue;
        }

        NSString *image = entry[@"Image"];
        if (![image isKindOfClass:[NSString class]] || image.length == 0) {
            image = [NSString stringWithUTF8String:GNMainImageName()];
        }
        NSString *anchorLabel = [NSString stringWithFormat:@"anchors[%d]", index];
        if (!GNEnsurePatchableTarget(image, anchorLabel)) continue;

        NSString *action = entry[@"Action"] ?: @"log";
        NSString *mode = entry[@"Mode"] ?: @"function";
        NSInteger wanted = [entry[@"Occurrence"] respondsToSelector:@selector(integerValue)]
            ? [entry[@"Occurrence"] integerValue] : 0;
        NSInteger maxHits = [entry[@"MaxHits"] respondsToSelector:@selector(integerValue)]
            ? [entry[@"MaxHits"] integerValue] : 6;

        uintptr_t cstring = GNFindCString(image.UTF8String, needle.UTF8String);
        if (!cstring) {
            GNLogC("anchors[%d]: string '%s' not found in '%s'",
                   index, needle.UTF8String, image.UTF8String);
            continue;
        }

        uintptr_t textStart = 0, textEnd = 0;
        if (!GNTextBounds(image.UTF8String, &textStart, &textEnd)) {
            GNLogC("anchors[%d]: no __text in '%s'", index, image.UTF8String);
            continue;
        }

        GNLogC("anchors[%d]: '%s' cstring=0x%llx", index, needle.UTF8String,
               (unsigned long long)cstring);

        NSInteger seen = 0;
        NSInteger applied = 0;

        for (uintptr_t cursor = textStart; cursor + 16 < textEnd; cursor += 4) {
            uint32_t insn = GNReadInsn(cursor);
            uintptr_t page = 0;
            if (!GNDecodeADRP(insn, cursor, &page)) continue;

            uint32_t adrpRd = insn & 0x1F;
            BOOL matched = NO;

            for (int step = 1; step <= 4; step++) {
                uint32_t next = GNReadInsn(cursor + step * 4);
                uint32_t rd = 0, rn = 0;
                uint64_t imm = 0;
                if (!GNDecodeADDImm(next, &rd, &rn, &imm)) continue;
                if (rn != adrpRd) continue;
                if (page + imm == cstring) {
                    matched = YES;
                    break;
                }
            }
            if (!matched) continue;

            if (seen < wanted) {
                seen++;
                continue;
            }
            seen++;

            uintptr_t imageBase = GNImageBase(image.UTF8String);
            uintptr_t functionStart = cursor;
            if ([mode isEqualToString:@"function"]) {
                NSUInteger distance = 0;
                functionStart = GNFindFunctionStart(textStart, textEnd, cursor, &distance);
                GNLogC("anchors[%d] hit %ld: ref=0x%llx (static 0x%llx) func=0x%llx (static 0x%llx) dist=%lu",
                       index, (long)applied,
                       (unsigned long long)cursor, (unsigned long long)(cursor - imageBase),
                       (unsigned long long)functionStart,
                       (unsigned long long)(functionStart - imageBase),
                       (unsigned long)distance);
            } else {
                GNLogC("anchors[%d] hit %ld: ref=0x%llx (static 0x%llx)",
                       index, (long)applied,
                       (unsigned long long)cursor, (unsigned long long)(cursor - imageBase));
            }

            GNApplyCodeAction(action, entry[@"Bytes"], image.UTF8String, functionStart,
                              [NSString stringWithFormat:@"anchors[%d] '%@'", index, needle]);

            applied++;
            if (maxHits > 0 && applied >= maxHits) {
                GNLogC("anchors[%d]: hit cap (%ld) reached - stopping", index, (long)maxHits);
                break;
            }
        }

        if (seen == 0) {
            GNLogC("anchors[%d]: no ADRP+ADD reference to '%s' found", index, needle.UTF8String);
        }
    }
}

#pragma mark - Generic swizzles

static id GNSwizzleReturnZero(id self, SEL _cmd) { return nil; }

// ARC forbids casting an integer straight to `id`. Routing the value through a
// void * and a __bridge cast is the supported form; 0x1 is a tagged pointer, so
// the retain/release that ARC emits around the call are no-ops at runtime.
static id GNSwizzleReturnOne(id self, SEL _cmd) {
    return (__bridge id)(void *)(uintptr_t)1;
}

static void GNApplySwizzles(NSDictionary *cfg) {
    NSArray *swizzles = cfg[@"Swizzles"];
    if (![swizzles isKindOfClass:[NSArray class]] || swizzles.count == 0) {
        GNLogC("swizzles: none configured");
        return;
    }

    for (id entry in swizzles) {
        if (![entry isKindOfClass:[NSDictionary class]]) continue;

        NSString *className = entry[@"Class"];
        NSString *selector = entry[@"Selector"];
        if (!className.length || !selector.length) {
            GNLogC("swizzles: entry without Class/Selector - skipped");
            continue;
        }

        NSString *behavior = entry[@"Behavior"] ?: entry[@"Return"] ?: @"zero";
        NSString *normalized = [behavior lowercaseString];

        if ([normalized isEqualToString:@"orig"] || [normalized isEqualToString:@"skip"]) {
            GNLogC("swizzles: [%s %s] left alone (Behavior=%s)",
                   className.UTF8String, selector.UTF8String, normalized.UTF8String);
            continue;
        }

        BOOL wantsTrue = ([normalized isEqualToString:@"true"] ||
                          [normalized isEqualToString:@"one"] ||
                          [normalized isEqualToString:@"yes"]);
        // Both replacements return a register-sized 0 or 1, which is correct for
        // BOOL, int, NSInteger and pointer returns at the ABI level. That is the
        // point: we do not need the method signature to force a value.
        IMP replacement = wantsTrue ? (IMP)GNSwizzleReturnOne : (IMP)GNSwizzleReturnZero;
        BOOL isClassMethod = [entry[@"ClassMethod"] respondsToSelector:@selector(boolValue)]
            ? [entry[@"ClassMethod"] boolValue] : NO;

        if (GNCFG(@"DryRun", NO)) {
            GNLogC("swizzles: DRY RUN would hook %c[%s %s] -> %s",
                   isClassMethod ? '+' : '-', className.UTF8String,
                   selector.UTF8String, wantsTrue ? "true" : "false");
            continue;
        }

        GNHookIfExists(className.UTF8String, selector.UTF8String,
                       replacement, NULL, isClassMethod);
    }
}

#pragma mark - NSUserDefaults overrides

static void GNApplyDefaultOverrides(NSDictionary *cfg) {
    NSMutableDictionary *writes = [NSMutableDictionary dictionary];

    NSArray *keysTrue = cfg[@"BoolKeysTrue"];
    if ([keysTrue isKindOfClass:[NSArray class]]) {
        for (NSString *key in keysTrue) {
            if ([key isKindOfClass:[NSString class]] && key.length) writes[key] = @YES;
        }
    }

    NSArray *keysFalse = cfg[@"BoolKeysFalse"];
    if ([keysFalse isKindOfClass:[NSArray class]]) {
        for (NSString *key in keysFalse) {
            if ([key isKindOfClass:[NSString class]] && key.length) writes[key] = @NO;
        }
    }

    NSDictionary *direct = cfg[@"DefaultsSet"];
    if ([direct isKindOfClass:[NSDictionary class]]) {
        [writes addEntriesFromDictionary:direct];
    }

    if (writes.count == 0) {
        GNLogC("defaults: nothing to write");
        return;
    }

    if (GNCFG(@"DryRun", NO)) {
        // GNLogC is a C variadic function: %@ is not available, pass UTF-8 bytes.
        NSString *description = writes.description ?: @"";
        GNLogC("defaults: DRY RUN would write %s", description.UTF8String ?: "");
        return;
    }

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [writes enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
        // Dot syntax is not legal on `id`: resolve the type first.
        if (![key isKindOfClass:[NSString class]]) return;
        NSString *keyString = (NSString *)key;
        if (keyString.length == 0) return;
        [defaults setObject:value forKey:keyString];
    }];
    [defaults synchronize];
    GNLogC("defaults: wrote %lu keys", (unsigned long)writes.count);
}

#pragma mark - Recon

static void GNLogImageTable(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        const struct mach_header_64 *header =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        GNLogC("image[%u] base=%p slide=0x%llx %s", i, header,
               (unsigned long long)_dyld_get_image_vmaddr_slide(i), path ?: "?");
    }
}

static void GNWriteRecon(NSDictionary *cfg) {
    NSString *path = [GNDocumentsPath() stringByAppendingPathComponent:@"gnunlock-recon.txt"];
    NSMutableString *out = [NSMutableString string];

    [out appendFormat:@"# GNUnlock recon\n"];
    [out appendFormat:@"main image: %s\n", GNMainImageName()];
    [out appendFormat:@"base: 0x%llx\n", (unsigned long long)GNImageBase(NULL)];
    [out appendFormat:@"slide: 0x%llx\n\n", (unsigned long long)GNImageSlide(NULL)];

    uintptr_t textStart = 0, textEnd = 0;
    if (GNTextBounds(NULL, &textStart, &textEnd)) {
        [out appendFormat:@"__text: 0x%llx - 0x%llx (%llu bytes)\n\n",
         (unsigned long long)textStart, (unsigned long long)textEnd,
         (unsigned long long)(textEnd - textStart)];
    }

    [out appendFormat:@"## images\n"];
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *path0 = _dyld_get_image_name(i);
        [out appendFormat:@"%u\tslide=0x%llx\t%s\n", i,
         (unsigned long long)_dyld_get_image_vmaddr_slide(i), path0 ?: "?"];
    }

    int classCount = objc_getClassList(NULL, 0);
    [out appendFormat:@"\n## objc classes: %d\n", classCount];

    if (classCount > 0) {
        Class *classes = (Class *)malloc(sizeof(Class) * (size_t)classCount);
        int actual = objc_getClassList(classes, classCount);
        for (int i = 0; i < actual; i++) {
            const char *name = class_getName(classes[i]);
            if (name) [out appendString:[NSString stringWithUTF8String:name] ?: @"?"];
            [out appendString:@"\n"];
        }
        free(classes);
    }

    NSError *error = nil;
    [out writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error];
    GNLogC("recon: wrote %lu bytes to %s (%s)", (unsigned long)out.length,
           path.UTF8String, error ? error.localizedDescription.UTF8String : "ok");
}

/// Dumps the immediate-member block of a Swift class metadata. Pointers that
/// land inside __text are the vtable candidate slots - this is what you need to
/// turn "somewhere in that function" into an exact slot index.
static void GNProbeClasses(NSDictionary *cfg) {
    NSArray *names = cfg[@"ProbeClasses"];
    if (![names isKindOfClass:[NSArray class]] || names.count == 0) return;

    uintptr_t textStart = 0, textEnd = 0;
    GNTextBounds(NULL, &textStart, &textEnd);

    for (NSString *name in names) {
        if (![name isKindOfClass:[NSString class]]) continue;

        Class cls = objc_getClass(name.UTF8String);
        if (!cls) cls = NSClassFromString(name);
        if (!cls) {
            GNLogC("probe: class '%s' not found", name.UTF8String);
            continue;
        }

        uintptr_t metadata = (uintptr_t)cls;
        GNLogC("probe: %s metadata=0x%llx", name.UTF8String, (unsigned long long)metadata);

        for (NSInteger slot = 0; slot < 32; slot++) {
            uintptr_t address = metadata + 0x28 + (uintptr_t)(slot * 8);
            uintptr_t value = *(const uintptr_t *)address;
            BOOL inText = (value >= textStart && value < textEnd);
            GNLogC("probe:   +0x%02lx = 0x%016llx%s",
                   (long)(0x28 + slot * 8), (unsigned long long)value,
                   inText ? "   <-- __text" : "");
        }
    }
}

#pragma mark - Entry point

void GNRunPatches(NSDictionary *cfg) {
    GNLogC("---- patch pipeline start (dryRun=%d) ----", GNCFG(@"DryRun", NO) ? 1 : 0);
    GNLogC("main image '%s' base=0x%llx slide=0x%llx", GNMainImageName(),
           (unsigned long long)GNImageBase(NULL),
           (unsigned long long)GNImageSlide(NULL));

    if (GNCFG(@"LogImages", NO)) GNLogImageTable();

    @try {
        GNApplyDefaultOverrides(cfg);
        GNApplyBytePatches(cfg);
        GNApplyAnchors(cfg);
        GNApplySwizzles(cfg);
        GNProbeClasses(cfg);
        if (GNCFG(@"Recon", NO)) GNWriteRecon(cfg);
    } @catch (NSException *exception) {
        GNLogC("pipeline exception: %s: %s", exception.name.UTF8String ?: "?",
               exception.reason.UTF8String ?: "?");
    }

    GNLogC("---- patch pipeline done ----");
}
