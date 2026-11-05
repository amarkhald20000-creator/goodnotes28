//
//  GNUnlock.m
//  Entry point - v12.
//
//  ============================ what v12 is ============================
//
//  v9 through v11 all assumed the crash arrived *through* code of ours, and each
//  one added another mechanism to catch it: a delegate wrapper, a boundary net
//  on a private UIKit method, a throw tracer, an experiment ladder, a
//  three-level auto bisect. Every one of those mechanisms is itself a behaviour
//  change in a process that is throwing an exception out of a dispatch_once
//  during app initialisation. That is a bad trade: we kept buying the ability to
//  diagnose a crash by making the crash more likely.
//
//  v12 inverts the default. The constructor does a short, fixed list and stops:
//
//      1. GNBoot()                       open the log, prove we ran        (C only)
//      2. GNProbeSignedState()           read the entitlements and containers
//      3. GNInstallEntitlementRepair()   answer CloudKit with the right type  (v15)
//      4. GNInstallExceptionForensics()  name the exception if one is thrown
//      5. GNInstallCloudKitGuard()       survive the CKException v13 named (v14)
//
//  All four are read-mostly with respect to the app. No delegate is wrapped, no
//  private selector is hooked, no container answer is overridden, no import slot
//  is rebound, no preference is written, no code page is touched. The one
//  deliberate exception is (4): v13's probe proved that re-signing writes a
//  malformed com.apple.developer.icloud-services and CloudKit raises out of app
//  initialisation because of it, so v14 swallows that named exception and
//  nothing else. Everything else behaves exactly as it does with no dylib.
//
//  ==================== why "no log file" was impossible ====================
//
//  A dylib's constructor runs from dyld's initialiser list, before main(), and
//  therefore long before UIApplicationMain. If the dylib is listed in
//  LC_LOAD_DYLIB and the process reached UIApplicationMain - which the crash
//  report proves it did, the frames are there - then this constructor ran.
//
//  So "no gnunlock.log" never meant "our code did not run". It meant one of:
//
//      a) the file was written somewhere the user could not reach, or
//      b) the write itself failed, or
//      c) it was written and not found.
//
//  v11 logged through NSSearchPathForDirectoriesInDomains + NSString + a
//  buffered NSFileHandle, i.e. through Foundation, during dyld init. v12 writes
//  through open(2)/write(2)/fsync(2) to four candidate paths, one of which is
//  $HOME itself. One of them will be reachable.
//
//  ============================== lifecycle ==============================
//
//    constructor        beacon, probe, exception capture. Nothing else.
//    full mode only     the hook stack, from GNLegacy.m, on a delayed queue.
//
//  GNLegacy.m is a separate translation unit on purpose: this file names none of
//  the hook symbols, and scripts/v12_lint.py enforces that. "Does the
//  constructor install anything?" is answerable by reading one short function.
//

#import "GNUnlock.h"
#import "GNBeacon.h"
#import "GNEntitlementRepair.h"
#import "GNCloudKitStub.h"
#import "GNThrowInterpose.h"
#import "GNCloudKitSymbolQuarantine.h"
#import "GNXPCGate.h"
#import "GNCloudKitQuarantine.h"

#include <dispatch/dispatch.h>

__attribute__((constructor(101)))
static void GNUnlockEntry(void) {
    // No autorelease pool yet on purpose: this call sends no messages at all.
    GNBoot();

    @autoreleasepool {
        @try {
            BOOL enabled = GNCFG(@"Enabled", YES);
            BOOL observe = GNCFG(@"ObserveOnly", YES);

            GNBeaconLine("config: Enabled=%s ObserveOnly=%s",
                         enabled ? "yes" : "no", observe ? "yes" : "no");

            if (!enabled) {
                GNBeaconLine("Enabled=false - beacon only, nothing installed");
                return;
            }

            // ---- 1. what does this process actually hold? (read only) -------
            if (GNCFG(@"ProbeSignedState", YES)) {
                GNProbeSignedState();
                GNProbeScheduledChecks();
            } else {
                GNBeaconLine("probe: disabled by config");
            }

            // ---- 1b. every throw in this process, cache included ------------
            // v20's trampoline was installed on the three import slots the walk
            // could attribute - Goodnotes, MSAL, CoreUI. CloudKit was not one of
            // them, which is why the device log had three classified throw sites
            // and a launch that still died. The table this installs is read by
            // dyld against every binding in the process, so "does this image have
            // a slot" stops being the question.
            if (GNCFG(@"ThrowInterpose", YES)) {
                GNInstallThrowInterpose(GNConfig());
            } else {
                GNBeaconLine("throw-interpose: disabled by config - the table stays installed "
                             "as a pass-through and CloudKit's throw sites are unclassified");
            }

            // ---- 1c. the two names the v22 stack gave us -------------------
            // CKPersona.launch and CKMainBundleIsAppleExecutable are a Swift
            // static property getter and a C function: neither is in any
            // Objective-C method list, so the quarantine below cannot see them
            // however wide it is.
            //
            // v24 tried to reach them with an __DATA,__interpose table and did
            // not link: neither name is in CloudKit's .tbd, so weak_import or not
            // the linker had nothing to bind. v25 resolves at run time instead -
            // dlsym first, then the offset the crash log prints mapped through
            // LC_FUNCTION_STARTS - and redirects the import slots that hold the
            // result. The log reports, per entry, where the address came from and
            // how many slots held it: zero means the call is a direct branch
            // inside CloudKit, and the throw-level swallow below is then the only
            // layer that can act on it.
            if (GNCFG(@"CloudKitSymbolQuarantine", YES)) {
                GNInstallCloudKitSymbolQuarantine(GNConfig());
            } else {
                GNBeaconLine("symbol-quarantine: disabled by config - CKPersona.launch and "
                             "CKMainBundleIsAppleExecutable run unchanged");
            }

            // ---- 2. answer with the type CloudKit requires ------------------
            // v14 tried to survive the CKException at -[NSException raise]; the
            // next launch proved CloudKit uses @throw and never reaches it. v15
            // prevents the exception instead: dyld interposes
            // SecTaskCopyValueForEntitlement for the whole process and the four
            // iCloud keys are answered with the type Apple's schema requires.
            // Like the guard below, this is not a feature switch - it is the
            // difference between a launch and a crash - so it runs in observe
            // mode too, and it changes nothing when the value is already right.
            if (GNCFG(@"EntitlementRepair", YES)) {
                GNInstallEntitlementRepair(GNConfig());
            } else {
                GNBeaconLine("repair: disabled by config - a malformed iCloud "
                             "entitlement kills the launch again");
            }

            // ---- 2b. reach the call site the interposition cannot ----------
            // Layer 1 (above) is dyld rewriting *bindings*; it cannot touch a
            // caller that reaches the function by direct branch, and it cannot
            // see a slot in an image dyld does not rebind for us. Layer 2 rewrites
            // the import slots themselves - found by the address they hold, not by
            // name, because the shared cache keeps no symbol table - and layer 3
            // calls the function twice and reports whether the replacement ran.
            // That measurement is the point: v15 logged "armed" and nothing was
            // intercepted.
            if (GNCFG(@"EntitlementSlotRebind", YES)) {
                GNInstallEntitlementSlotHook(GNConfig());
            } else {
                GNBeaconLine("slot: disabled by config - the interposition is the only "
                             "layer left, and a direct branch call site has none");
            }

            // ---- 2c. cover the read that goes through a *lookup* ------------
            // v17 measured that no image has a slot for the plural SecTask call
            // while the singular one has, in the same walk of the same process.
            // That is what a framework that soft-links a newer API looks like: it
            // resolves the symbol once and calls through the value it kept, so the
            // call site has no slot and the address is plain data. Interposing the
            // lookup is the only data-only way to reach it.
            if (GNCFG(@"DlsymTap", YES)) {
                GNInstallDlsymTap(GNConfig());
            } else {
                GNBeaconLine("dlsym: disabled by config - a lookup-resolved entitlement "
                             "read stays unrepaired");
            }

            // ---- 2e. cut the daemon conversation at the connection ---------
            // v20 answered the Objective-C entry points and the log shows one of
            // them being reached and ignored - then the same CKException, one step
            // later. Whatever is left is underneath: an operation that reaches the
            // daemon by a route that never passes through -[CKDatabase addOperation:],
            // or a check cloudd performs on the signature itself.
            //
            // Both are answered by the same thing, so this does not distinguish
            // them: a CloudKit connection is pointed at a service name with nothing
            // behind it, and libxpc answers XPC_ERROR_CONNECTION_INVALID the way it
            // does for any daemon that is not running. No code page is written and
            // no reply object is fabricated.
            if (GNCFG(@"XPCGate", YES)) {
                GNInstallXPCGate(GNConfig());
            } else {
                GNBeaconLine("xpc-gate: disabled by config - CloudKit reaches a real daemon "
                             "again, and whatever that daemon answers arrives unchanged");
            }

            // ---- 2f. the property, not the list ---------------------------
            // v20 named fourteen entry points. This replaces, by shape, every
            // void-returning work method on every class CloudKit defines: a method
            // with no return value cannot hand anything back, so dropping its body
            // leaves a stall rather than a contradiction. Return-value methods are
            // untouched - that is what the substitute objects above are for.
            //
            // Runs before the stub on purpose: the stub's fourteen answers are
            // better than an empty body, and have to be the last word on those
            // selectors.
            if (GNCFG(@"CloudKitQuarantine", YES)) {
                GNInstallCloudKitQuarantine(GNConfig());
            } else {
                GNBeaconLine("quarantine: disabled by config - only the named entry points are "
                             "covered, and an unnamed one is a crash with an old log");
            }

            // ---- 2d. stop asking CloudKit, answer for it -------------------
            // v15-v19 all tried to make CloudKit's own entitlement check pass,
            // and every mechanism measured LIVE while the launch kept dying of
            // the same CKException. v20 takes the conclusion: the value is not
            // read through any door this dylib can reach. So instead of making
            // iCloud *work*, it is made *unavailable* - CKAccountStatusNoAccount,
            // the same answer an app gets from a device with no iCloud account,
            // which is a state GoodNotes already ships UI for.
            //
            // This replaces the entry point rather than catching what it throws.
            // That distinction is the whole design: CloudKit validates inside a
            // dispatch_once, and an exception out of that block leaves the gate
            // owned by this thread for ever. Never entering the block is the only
            // version of this that does not leave a landmine behind.
            if (GNCFG(@"CloudKitStub", YES)) {
                if (!GNInstallCloudKitStub(GNConfig())) {
                    // CloudKit can be loaded lazily. Retry a few times, cheap and
                    // idempotent, and let the constructor continue either way.
                    static const double kRetries[] = { 0.05, 0.30, 0.90, 2.0, 4.0 };
                    for (int i = 0; i < (int)(sizeof(kRetries) / sizeof(kRetries[0])); i++) {
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                                     (int64_t)(kRetries[i] * NSEC_PER_SEC)),
                                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                            @autoreleasepool {
                                if (GNCloudKitStubIsInstalled()) return;
                                @try {
                                    // Same order as the first pass: CloudKit's
                                    // classes appear when the framework loads, so
                                    // the quarantine has to get a chance at them
                                    // before the stub owns the named selectors.
                                    GNInstallCloudKitQuarantine(GNConfig());
                                    GNInstallCloudKitStub(GNConfig());
                                } @catch (NSException *e) {
                                    GNBeaconLine("cloudkit-stub: retry threw %s",
                                                 (e.name ?: @"?").UTF8String);
                                }
                            }
                        });
                    }
                }
            } else {
                GNBeaconLine("cloudkit-stub: disabled by config - CloudKit validates its own "
                             "entitlements and the CKException kills the launch again");
            }

            // ---- 3. name the exception if one is coming ---------------------
            if (GNCFG(@"ExcForensics", YES)) {
                GNInstallExceptionForensics();
            } else {
                GNBeaconLine("forensics: disabled by config - a launch crash will be anonymous");
            }

            // ---- 4. survive the one v13 named ------------------------------
            // The probe above proves the entitlements; this keeps the CKException
            // that a malformed iCloud entitlement raises from killing the launch.
            // It is a suppressor, not a fix: the signer still owns the value.
            // Since v15 it is the second line of defence rather than the first -
            // CloudKit's throw bypasses -[NSException raise], which is why the
            // repair above exists.
            if (GNCFG(@"CloudKitGuard", YES)) {
                GNInstallCloudKitGuard(GNConfig());
            } else {
                GNBeaconLine("cloudkit-guard: disabled by config - a CKException will kill "
                             "the launch again");
            }

            // ---- 5. the two measurements that need the app to be up --------
            // v18 could prove the repair *ran*; it could not say on whose call.
            // The audit records every door hit with its caller return address
            // and resolves them a few seconds in (never during dyld init), so
            // the next log either names the CloudKit call site or states that
            // nothing in this process reached a door at all - which are two very
            // different next steps.
            //
            // The CloudKit probe boundaries are retried here for the same
            // reason: CloudKit is usually loaded after the constructor, so the
            // first pass finds no class and the retry finds it.
            BOOL audit = GNCFG(@"CallSiteAudit", YES);
            if (audit) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                               dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                    @autoreleasepool {
                        @try {
                            GNReadAuditDump();
                            GNEntitlementReadSurfaceDump();
                        } @catch (NSException *e) {
                            GNBeaconLine("audit: dump threw %s - the counters are still above",
                                         (e.name ?: @"?").UTF8String);
                        }
                    }
                });
                GNBeaconLine("audit: caller attribution scheduled for +5.0s");
            } else {
                GNBeaconLine("audit: disabled by config - the next log can say the repair ran, "
                             "but not on whose call");
            }

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                           dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                @autoreleasepool {
                    @try {
                        GNInstallCloudKitProbeBoundaries();
                    } @catch (NSException *e) {
                        GNBeaconLine("boundary(observe): retry threw %s",
                                     (e.name ?: @"?").UTF8String);
                    }
                }
            });

            if (observe) {
                // "ObserveOnly" has always meant "the v8-v11 hook stack is off". It has
                // never meant "change nothing": the entitlement repair, the guard and -
                // since v20 - the CloudKit substitute are launch fixes, and a launch fix
                // that only runs in a mode nobody uses is not a fix. This line says
                // which of the two is in force so the log cannot be read the wrong way.
                GNBeaconLine("observe mode: legacy hook stack off (no preference override, no "
                             "container fallback, no code patch, no rebind of the app's own "
                             "symbols)");
                GNBeaconLine("observe mode: the entitlement repair, the exception guard and - if "
                             "CloudKitStub is on - the CloudKit substitute ARE installed: they "
                             "are launch fixes, not features");
                GNBeaconLine("observe mode: ready, constructor finished at +%.1fms",
                             GNBeaconUptimeMs());
                return;
            }

            GNRunLegacyMode();
        } @catch (NSException *exception) {
            // The constructor must never be the thing that kills the launch.
            GNBeaconLine("constructor threw %s: %s - swallowing, app continues",
                         (exception.name ?: @"?").UTF8String,
                         (exception.reason ?: @"?").UTF8String);
        }
    }
}
