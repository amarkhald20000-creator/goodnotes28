//
//  GNCapability.m
//  One question, one answer: may this process modify executable memory and
//  live to tell the tale?
//
//  Why this file exists
//  --------------------
//  iOS validates every page that belongs to a code signed image. When we take a
//  __text page of a system framework (or of the app) and write through it with
//
//      vm_protect(..., VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)
//
//  the kernel does not hand us the real page. It manufactures a private,
//  anonymous, copy-on-write page and lets us scribble on that. The bytes are
//  ours; the page is no longer covered by a code signature. The first time the
//  CPU fetches an instruction from it, pmap asks "is this page signed?" - it is
//  not - and the answer is KERN_PROTECTION_FAILURE, then amfi kills the task:
//
//      termination reason : CODESIGNING / Invalid Page
//      ktriageinfo        : Failed to fault in a page with execute permissions
//
//  There is exactly one escape hatch: a process that carries get-task-allow (or
//  is being debugged) has CS_DEBUGGED set, its pages are exempt from that check,
//  and patched code runs. That flag comes from the signing certificate. A
//  Development / enterprise-with-get-task-allow build has it. A Distribution
//  build never does.
//
//  Consequence for this project: on a Distribution certificate every in-memory
//  byte patch, anchor rewrite and inline hook is a one-way ticket to a
//  CODESIGNING kill. So we detect it once, up front, and every write path asks
//  before it touches an executable page. What still works on Distribution:
//
//    * data patches (defaults, preference files, forged responses)
//    * ObjC swizzling (method lists are data)
//    * import slot rebinding (the app's own __got is data)
//    * editing the Mach-O on disk before it is signed (scripts/gnstatic.py)
//
//  And that is the whole design of v3.
//

#import "GNUnlock.h"

#import <mach-o/dyld.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>
#import <sys/types.h>

/// csops(2) is not in the public SDK headers but has been exported from
/// libsystem_kernel forever and is used by every signing aware tool.
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif

#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000
#endif

#pragma mark - Probe

static int  gDebuggedProbe = -1;   // -1 unknown, 0 no, 1 yes

static BOOL GNProcessIsDebugged(void) {
    if (gDebuggedProbe >= 0) return gDebuggedProbe == 1;

    unsigned int flags = 0;
    int result = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    if (result != 0) {
        gDebuggedProbe = 0;
        return NO;
    }

    BOOL debugged = (flags & CS_DEBUGGED) != 0;
    gDebuggedProbe = debugged ? 1 : 0;
    return debugged;
}

const char *GNSignatureMode(void) {
    static char mode[24];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        unsigned int flags = 0;
        if (csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags)) != 0) {
            strncpy(mode, "unknown", sizeof(mode) - 1);
            return;
        }
        if (flags & CS_DEBUGGED) {
            strncpy(mode, "development", sizeof(mode) - 1);
        } else {
            strncpy(mode, "distribution", sizeof(mode) - 1);
        }
    });
    return mode;
}

BOOL GNCodePatchingAllowed(void) {
    static BOOL allowed = NO;
    static dispatch_once_t once;

    dispatch_once(&once, ^{
        // Two independent gates, both must be open:
        //   1. the kernel must consider this process debug-signed (CS_DEBUGGED),
        //      which no config key can fake - it comes from the certificate;
        //   2. the config must not have opted out.
        // Default is opt-out, so a v3 build never writes a code page unless
        // somebody deliberately turned it back on for a debug-signed build.
        BOOL optedIn = GNCFG(@"AllowCodePatching", NO);
        BOOL debugged = GNProcessIsDebugged();
        allowed = debugged && optedIn;

        GNLogC("capability: signature=%s CS_DEBUGGED=%s AllowCodePatching=%s -> codePatching %s",
               GNSignatureMode(), debugged ? "yes" : "no", optedIn ? "yes" : "no",
               allowed ? "ALLOWED" : "BLOCKED");
    });

    return allowed;
}

const char *GNMemoryPolicySummary(void) {
    static char summary[192];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        snprintf(summary, sizeof(summary),
                 "signature=%s codePatching=%s gotRebinding=%s",
                 GNSignatureMode(),
                 GNCodePatchingAllowed() ? "allowed" : "blocked",
                 GNCFG(@"EnableGOTRebinding", NO) ? "enabled" : "disabled");
    });
    return summary;
}
