//
//  GNThrowTrampoline.m
//  Classify the throw site, then either rethrow or - where the instruction at
//  the return address proves it is safe - return. (v20)
//
//  Read GNThrowTrampoline.h first: it explains why "an assembly stub that
//  swallows" is not one thing but two, and why only one of them exists.
//
//  This file is the reason half. Every throw through objc_exception_throw now
//  produces one line that says what the next instruction after the call is, in
//  English and in encoding, so the next launch answers "could that have been
//  swallowed" with the bytes rather than with an opinion.
//

#import "GNThrowTrampoline.h"
#import "GNUnlock.h"
#import "GNBeacon.h"

#import <dlfcn.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#pragma mark - State

static void   *gRealThrow        = NULL;
static BOOL    gArmed            = NO;
static int32_t gSwallowed        = 0;
static int32_t gClassified       = 0;
static int32_t gLogBudget        = 16;
static int32_t gSwallowBudget    = 4;
static BOOL    gSwallowAtSite    = NO;
static __thread BOOL gInside     = NO;

// v23: two additions to the swallow decision, both about making a forced
// swallow a bounded experiment instead of a global lie.
//
//   gSwallowForce   lift the "the next instruction is provably a return"
//                   requirement. Off by default; see the file header.
//   gSwallowImages  only swallow when the *throwing* function lives in one of
//                   these images (substring match on the basename). A forced
//                   swallow in CloudKit's own code is the experiment; a forced
//                   swallow in Foundation would be an unrelated crash invited
//                   into a launch that was already being debugged.
static BOOL      gSwallowForce   = NO;
static NSArray  *gSwallowImages  = nil;
static int32_t   gForced         = 0;

// v26: what a *forced* swallow puts in x0.
//
// The proven-return path returns the exception object, because the caller asked
// for a value and an object pointer is a value it can hold without dereferencing
// it. A forced swallow has no such guarantee, and on the site this build exists
// for the return type is `Optional<CKPersona>` - a Swift optional class
// reference, where zero is `.none` and anything else is a pointer the caller
// will message as a persona. Handing back the exception object there is a
// pointer-shaped lie that passes a `guard let` and fails at the first method
// call; zero takes the branch CloudKit already has for "no persona".
//
// Off (ThrowSwallowReturnNil = false) restores the v23 behaviour exactly, for
// comparison on a launch that behaves differently.
static BOOL      gSwallowReturnNil = YES;

#pragma mark - AArch64 decoding

/// The four encodings this decision needs. Everything else is "not provably a
/// return", which is the safe answer: an unknown instruction costs a swallow that
/// did not happen, never a control transfer into bytes that were never code.
#if defined(__aarch64__)
static BOOL GNInsnIsReturn(uint32_t insn) {
    return (insn & 0xFFFFFC1Fu) == 0xD65F0000u;             // ret [xn]
}
static BOOL GNInsnIsBranchAlways(uint32_t insn) {
    return (insn & 0xFC000000u) == 0x14000000u;             // b <imm26>
}
static BOOL GNInsnIsFramePop(uint32_t insn) {
    return (insn & 0xFFC07FFFu) == 0xA8C07BFDu;             // ldp x29, x30, [sp], #imm
}
static BOOL GNInsnIsTrap(uint32_t insn) {
    if ((insn & 0xFFE0001Fu) == 0xD4200000u) return YES;    // brk #imm
    if ((insn & 0xFFE0001Fu) == 0xD4400000u) return YES;    // hlt #imm
    return NO;
}
#endif

/// What a caller does immediately after `bl objc_exception_throw`.
///
/// `safe` means the next instruction is a return, a tail branch, or a frame pop
/// followed by a return - i.e. returning from objc_exception_throw really does
/// leave the throwing function, and x0 becomes its result.
typedef struct {
    BOOL     readable;
    BOOL     safe;
    uint32_t instruction;
    uint32_t followOn;
    const char *name;
} GNContinuation;

static GNContinuation GNClassifyContinuation(const void *address) {
    GNContinuation result;
    memset(&result, 0, sizeof(result));
    result.name = "unreadable";

    if (!address) { result.name = "no-return-address"; return result; }

#if defined(__aarch64__)
    // The address is a live return address, so the page is mapped and readable.
    // `volatile` so the two loads are not merged: the second is only needed for
    // the frame-pop case, but reading both keeps the branch-free shape.
    const volatile uint32_t *code = (const volatile uint32_t *)address;
    uint32_t first = code[0];
    uint32_t second = code[1];

    result.readable = YES;
    result.instruction = first;
    result.followOn = second;

    if (GNInsnIsReturn(first)) { result.safe = YES; result.name = "ret"; return result; }
    if (GNInsnIsBranchAlways(first)) { result.safe = YES; result.name = "b"; return result; }
    if (GNInsnIsFramePop(first)) {
        result.followOn = second;
        if (GNInsnIsReturn(second)) { result.safe = YES; result.name = "ldp x29,x30,[sp],#imm; ret"; }
        else result.name = "ldp x29,x30,[sp],#imm; <not ret>";
        return result;
    }
    if (GNInsnIsTrap(first)) { result.name = "trap (brk/hlt)"; return result; }
    if (first == 0xD503201Fu) { result.name = "nop (padding)"; return result; }

    result.name = "mid-function";
    return result;
#else
    (void)address;
    return result;
#endif
}

#pragma mark - Reporting

static void GNTrampolineSay(const char *fmt, ...) __attribute__((format(__printf__, 1, 2)));

static void GNTrampolineSay(const char *fmt, ...) {
    int32_t count = __sync_add_and_fetch(&gClassified, 1);
    if (count > gLogBudget) return;

    va_list args;
    va_start(args, fmt);
    char text[640];
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);

    GNBeaconLine("trampoline: %s", text);
}

/// image + offset for a code address, which is the same arithmetic the .ips does
/// with imageIndex and imageOffset.
static void GNImageAndOffset(const void *address, char *out, size_t size) {
    if (!out || size == 0) return;
    out[0] = '\0';

    Dl_info info;
    if (address && dladdr(address, &info) && info.dli_fname) {
        const char *base = strrchr(info.dli_fname, '/');
        snprintf(out, size, "%s + 0x%llx", base ? base + 1 : info.dli_fname,
                 (unsigned long long)((uintptr_t)address - (uintptr_t)info.dli_fbase));
        return;
    }
    snprintf(out, size, "%p (no image)", address);
}

/// YES when `address` lives in one of the images named by `fragments`.
///
/// The basename is what is compared, not the path: in the dyld shared cache the
/// path is /System/Library/PrivateFrameworks/CloudKit.framework/CloudKit and on
/// a development device the same image shows up under /Developer/..., so a
/// substring match on the last component is the only comparison that is true on
/// both. An empty or absent list means "no filter", which is the v20 behaviour.
static BOOL GNAddressIsInImages(const void *address, NSArray *fragments) {
    if (![fragments isKindOfClass:[NSArray class]] || fragments.count == 0) return YES;
    if (!address) return NO;

    Dl_info info;
    if (!dladdr(address, &info) || !info.dli_fname) return NO;

    const char *base = strrchr(info.dli_fname, '/');
    base = base ? base + 1 : info.dli_fname;

    NSString *image = [NSString stringWithUTF8String:base];
    if (!image) return NO;

    for (id fragment in fragments) {
        if (![fragment isKindOfClass:[NSString class]] || [fragment length] == 0) continue;
        if ([image containsString:(NSString *)fragment]) return YES;
    }
    return NO;
}

static NSString *GNExceptionName(id exception) {
    @try {
        if (![exception isKindOfClass:[NSException class]]) return nil;
        NSString *name = [(NSException *)exception name];
        return [name isKindOfClass:[NSString class]] ? name : nil;
    } @catch (__unused NSException *ignored) {
        return nil;
    }
}

static NSString *GNExceptionReason(id exception) {
    @try {
        if (![exception isKindOfClass:[NSException class]]) return nil;
        NSString *reason = [(NSException *)exception reason];
        return [reason isKindOfClass:[NSString class]] ? reason : nil;
    } @catch (__unused NSException *ignored) {
        return nil;
    }
}

/// The same allow list the guard uses: a name, not a reason substring, because
/// the reason text is reworded between OS versions and contains the very value
/// this project is chasing.
static BOOL GNNameIsSwallowable(NSString *name) {
    if (!name) return NO;
    NSArray *names = GNConfig()[@"CloudKitExceptionNames"];
    if (![names isKindOfClass:[NSArray class]] || names.count == 0) {
        names = @[ @"CKException", @"NSCloudKitException" ];
    }
    return [names containsObject:name];
}

#pragma mark - Public

void GNThrowTrampolineArm(void *realFunction) {
    if (realFunction && !gRealThrow) gRealThrow = realFunction;

    gSwallowAtSite = GNCFG(@"ThrowSwallowAtSite", NO);
    gSwallowForce  = GNCFG(@"ThrowSwallowForce", NO);
    gSwallowReturnNil = GNCFG(@"ThrowSwallowReturnNil", YES);
    gSwallowImages = GNCFGArray(@"ThrowSwallowImages");
    if (![gSwallowImages isKindOfClass:[NSArray class]] || gSwallowImages.count == 0) {
        gSwallowImages = nil;
    }
    gSwallowBudget = (int32_t)GNCGI(@"ThrowSwallowBudget", 4);
    if (gSwallowBudget < 0) gSwallowBudget = 0;
    gLogBudget = (int32_t)GNCGI(@"ThrowTrampolineLogBudget", 16);
    if (gLogBudget < 1) gLogBudget = 1;

    if (!gRealThrow) {
        GNBeaconLine("trampoline: no real objc_exception_throw - not armed");
        return;
    }
    gArmed = YES;

    GNBeaconLine("trampoline: armed - objc_exception_throw now routes through this dylib");
    GNBeaconLine("trampoline: swallow-at-site %s (budget %d, images %s); a swallow happens where "
                 "the instruction after the call is provably a return%s",
                 gSwallowAtSite ? "ON" : "off", (int)gSwallowBudget,
                 gSwallowImages ? [[gSwallowImages componentsJoinedByString:@","] UTF8String]
                                : "any",
                 gSwallowForce
                     ? ", and everywhere else in those images too because ThrowSwallowForce is ON "
                       "- a forced swallow resumes the block, so read the FORCED lines"
                     : " unless ThrowSwallowForce is on");
    GNBeaconLine("trampoline: forced swallow returns %s (ThrowSwallowReturnNil)",
                 gSwallowReturnNil ? "nil in x0" : "the exception object in x0");
}

int32_t GNThrowTrampolineSwallowedCount(void) {
    return gSwallowed;
}

/// v23: how many of those swallows were *forced*, i.e. happened at a site whose
/// continuation the decoder could not prove was a return.
int32_t GNThrowTrampolineForcedCount(void) {
    return gForced;
}

int32_t GNThrowTrampolineClassifiedCount(void) {
    return gClassified;
}

/// The replacement itself.
///
/// Return type is a pointer, not void, on purpose: on the swallow path the value
/// becomes the throwing function's result (x0), and an object pointer is the one
/// thing a caller can hold without dereferencing garbage. It is the exception
/// object itself - a lie, but a well formed one.
void *GNThrowTrampolineObject(void *exceptionRaw) {
    if (gInside) {
        // A throw from inside the reporting below must not re-enter the decision.
        if (gRealThrow) ((void (*)(void *))gRealThrow)(exceptionRaw);
        return exceptionRaw;
    }

    const void *returnAddress = __builtin_extract_return_addr(__builtin_return_address(0));
    GNContinuation continuation = GNClassifyContinuation(returnAddress);

    id exception = (__bridge id)exceptionRaw;
    NSString *name = GNExceptionName(exception);
    NSString *reason = GNExceptionReason(exception);

    char place[192];
    GNImageAndOffset(returnAddress, place, sizeof(place));

    gInside = YES;

    // The full record - name, reason, symbolicated stack, dyld image table - goes
    // to the same file the v18 tap wrote, for the names that matter. It is the
    // artifact that answers "which frame threw" after the launch is gone.
    GNThrowTraceRecord(exception);

    GNTrampolineSay("throw %s: %s",
                    (name ?: @"(no name)").UTF8String,
                    (reason ?: @"(no reason)").UTF8String);
    GNTrampolineSay("  site %s  continuation=%s (0x%08x, then 0x%08x) -> %s",
                    place, continuation.name,
                    continuation.instruction, continuation.followOn,
                    continuation.safe ? "returning from here is a real return"
                                      : "returning from here would run bytes that are not code");

    BOOL nameAllowed  = GNNameIsSwallowable(name);
    BOOL imageAllowed = GNAddressIsInImages(returnAddress, gSwallowImages);

    BOOL maySwallow = gSwallowAtSite
        && gSwallowed < gSwallowBudget
        && nameAllowed
        && imageAllowed
        && (continuation.safe || gSwallowForce);

    // v26: one line per classified throw saying which term decided, before the
    // branch that acts on it.
    //
    // The v25 log was silent in two cases that matter: an exception name outside
    // CloudKitExceptionNames, and a spent budget. Both produce no swallow and no
    // line, so a launch that dies with force turned on reads exactly like force
    // not being read at all - which is the one ambiguity this project cannot
    // afford, because the next launch is the only experiment there is.
    GNTrampolineSay("  decision: name=%s image=%s force=%s nil=%s used=%d/%d -> %s",
                    nameAllowed ? "in-list" : "NOT-in-CloudKitExceptionNames",
                    imageAllowed ? "in-scope" : "NOT-in-ThrowSwallowImages",
                    gSwallowForce ? "on" : "off",
                    gSwallowReturnNil ? "yes" : "no",
                    (int)gSwallowed, (int)gSwallowBudget,
                    maySwallow ? "swallow"
                               : (gSwallowAtSite ? "rethrow" : "rethrow (ThrowSwallowAtSite off)"));

    if (maySwallow) {
        int32_t count = __sync_add_and_fetch(&gSwallowed, 1);
        gInside = NO;

        if (continuation.safe) {
            GNBeaconLine("trampoline: SWALLOWED #%d %s - the instruction after the call is a "
                         "return, so this one really is survivable. The throwing function "
                         "returns the exception object; nothing was unwound because nothing "
                         "was thrown", (int)count, (name ?: @"?").UTF8String);
            return exceptionRaw;
        }

        __sync_add_and_fetch(&gForced, 1);
        GNBeaconLine("trampoline: FORCED SWALLOW #%d %s - the throw site is %s, so this is NOT "
                     "the proven-return path: the throwing function resumes at the instruction "
                     "after the call with x0 = %s. Two outcomes are possible and the log cannot "
                     "tell them apart in advance: the block ends here and the swallow worked, or "
                     "the resumed bytes are not the end of the block and the launch dies at %s "
                     "with a different signal. The second outcome is still information - it names "
                     "the address", (int)count, (name ?: @"?").UTF8String, continuation.name,
                     gSwallowReturnNil ? "nil" : "the exception object", place);
        return gSwallowReturnNil ? NULL : exceptionRaw;
    }

    if (gSwallowAtSite && nameAllowed && !imageAllowed) {
        GNBeaconLine("trampoline: NOT swallowed - the throw site is %s, which is outside "
                     "ThrowSwallowImages (%s). Scoped on purpose: a forced swallow in another "
                     "framework would be an unrelated crash invited into this launch",
                     place,
                     gSwallowImages ? [[gSwallowImages componentsJoinedByString:@","] UTF8String]
                                    : "any");
    } else if (gSwallowAtSite && nameAllowed && !continuation.safe) {
        GNBeaconLine("trampoline: NOT swallowed - the throw site is %s. Returning there would "
                     "resume a basic block the compiler emitted as unreachable; set "
                     "ThrowSwallowForce to try it anyway and read the address above if the "
                     "launch then dies somewhere else", continuation.name);
    }

    gInside = NO;

    if (gRealThrow) {
        // Last statement: the compiler emits this as a tail branch, so the frame
        // this function pushed is gone before the unwind starts and the stack the
        // .ips renders is the app's, not ours.
        ((void (*)(void *))gRealThrow)(exceptionRaw);
    }

    // Only reachable if the "real" function returned, which objc_exception_throw
    // does not do. Continuing from a throw that never started is worse than
    // stopping here.
    _exit(134);
    return exceptionRaw;
}
