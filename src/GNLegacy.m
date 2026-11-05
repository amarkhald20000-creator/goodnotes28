//
//  GNLegacy.m
//  The v8-v11 hook stack, kept intact but unreachable by default.
//
//  It lives in its own translation unit for one reason: config/GNUnlock.plist
//  ships ObserveOnly = true, and that has to be auditable. With the whole stack
//  in one file, "does the constructor install hooks?" could only be answered by
//  reading every branch. Now src/GNUnlock.m names none of these symbols, and
//  scripts/v12_lint.py enforces that it stays that way.
//
//  Nothing here runs unless someone sets ObserveOnly to false. When they do,
//  this is exactly v11's behaviour: launch guard, throw tracer, run level
//  ladder, data hooks, container fallbacks, symbol interposition, patch
//  pipeline.
//
//  Read the v9-v11 notes before enabling it. Two of those launches died inside
//  this code path, and the reason v12 exists is that we still cannot prove they
//  did not.
//

#import "GNUnlock.h"
#import "GNBeacon.h"

#import <dispatch/dispatch.h>

static void GNSchedulePatchPipeline(NSDictionary *cfg) {
    double delay = GNCFGD(@"Delay", 2.0);
    if (delay < 0) delay = 0;

    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   queue, ^{
        @autoreleasepool {
            @try {
                GNSetPhase("patching");
                GNRunPatches(cfg);
                GNSetPhase("ready:patched");
                GNBeaconLine("full mode: patch pipeline finished");
            } @catch (NSException *e) {
                GNBeaconLine("full mode: patch pipeline threw %s: %s",
                             (e.name ?: @"?").UTF8String,
                             (e.reason ?: @"?").UTF8String);
            }
        }
    });
}

void GNRunLegacyMode(void) {
    GNBeaconLine("full mode: installing hooks - this changes app behaviour");

    GNLogBoot();
    GNInstallLaunchGuard();
    GNInstallThrowTracer(GNGuardNetCount());

    int level = GNRunLevel();
    NSDictionary *cfg = GNConfig();

    GNLogC("run level: %d - %s", level, GNRunLevelName(level));
    GNBeaconLine("full mode: run level %d - %s", level, GNRunLevelName(level));

    if (level <= 0) {
        GNSetPhase("ready:inert");
        GNBeaconLine("full mode: level 0 - nothing installed");
        GNShowLaunchNotice();
        return;
    }

    GNSetPhase("hooks");
    @try {
        if (level >= 1) GNInstallDataHooks(cfg);
        if (level >= 2) GNInstallResignContainerFixes(cfg);
        if (level >= 3) GNInstallResignSymbolFixes(cfg);
    } @catch (NSException *exception) {
        GNBeaconLine("full mode: install threw %s: %s",
                     (exception.name ?: @"?").UTF8String,
                     (exception.reason ?: @"?").UTF8String);
    }

    GNSetPhase("hooked");
    GNObserveLaunchCompletion();
    GNSchedulePatchPipeline(cfg);
    GNShowLaunchNotice();
}
