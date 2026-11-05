//
//  GNUnlock.h
//  Shared declarations for the GNUnlock dylib.
//
//  Design constraints:
//    * no Theos, no CydiaSubstrate, no external dependencies
//    * only public / stable Apple APIs (dlsym for the private-ish ones)
//    * every entry point must be safe to call from a dylib constructor
//    * nothing writes executable memory unless the process is allowed to
//      (see GNCapability.m - with a Distribution certificate it never is)
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma mark - Logging / state

/// Must be the very first call. Opens the log, reads the crash-loop state file,
/// and decides whether this launch runs in SAFE MODE.
void GNLogBoot(void);

/// Appends one line to Documents/gnunlock.log (and NSLog).
void GNLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);

/// Same, but C varargs - safe to call from a signal handler.
void GNLogC(const char *fmt, ...) __attribute__((format(__printf__, 1, 2)));

/// Writes the phase marker into the state file. Used by the crash-loop breaker.
void GNSetPhase(const char *phase);

/// The phase marker currently held in memory, e.g. "hooked".
const char *GNCurrentPhase(void);

/// YES when the previous launch died inside our code. Disables all patching.
BOOL GNSafeModeActive(void);

NSString *GNDocumentsPath(void);

/// Documents/gnunlock-lastcrash.txt - written by the uncaught exception
/// handler, presented by GNShowLaunchNotice() on the next launch.
NSString *GNLastCrashPath(void);

#pragma mark - Run level (auto bisect)

/// How much of the dylib is allowed to run this launch.
///
///    0  inert            log + diagnostics only, nothing is installed
///    1  data hooks       NSUserDefaults overrides
///    2  + containers     app group / ubiquity fallbacks
///    3  + interposition  keychain / SecCode / SecTask (needs GOT rebinding)
///
/// Resolved from RunLevel in the config, then lowered by one for every launch
/// that died before the app finished launching (AutoBisect). The decision is
/// persisted in Documents/gnunlock.bisect, so a bad hook costs one crashed
/// launch instead of a boot loop, and the settled level tells us which feature
/// group is fatal without anyone having to read a log.
int GNRunLevel(void);

const char *GNRunLevelName(int level);

/// Presents the auto-bisect / last-crash summary on screen, once, a few
/// seconds after the app is up. No-op when there is nothing to report.
void GNShowLaunchNotice(void);

/// Puts one diagnosis on screen, once per launch, retrying until there is a
/// window to present from. The first caller wins: a caught launch exception
/// therefore takes precedence over the generic bisect notice.
void GNPresentDiagnostic(NSString *title, NSString *body);

/// Drops the persisted auto-bisect level by one and records why. Called by the
/// launch guard when it catches an exception, so the next launch runs with less
/// of this dylib installed without needing a crashed launch to get there.
void GNDropRunLevel(const char *reason);

/// YES when the previous launch never reached
/// UIApplicationDidFinishLaunchingNotification.
///
/// Both ladders step on this and only this. v10 re-read the state file instead,
/// which by then already held the "boot" this launch had written - so the
/// ladder stepped down once per launch whether or not anything had failed.
BOOL GNPreviousLaunchWasEarly(void);

#pragma mark - Experiment ladder

/// One variable per launch, persisted in Documents/gnunlock.experiment.
///
/// The run level says *which group* is guilty; the experiment ladder says which
/// answer is right inside that group (app group container -> nil / home /
/// removed, keychain removed, and a nothing-installed control). The first step
/// that survives a launch is kept and the ladder stops. Returns -1 when off.
int GNExperimentStep(void);

/// "step 2/6 - app group answers the app container (trying)" for the log and
/// the on-screen notice.
NSString *GNExperimentStatus(void);

/// Marks the current step as the one that survived. Called once the app is up.
void GNExperimentNoteSurvived(void);

/// YES while a step is still being tried, i.e. while this ladder owns the run
/// level. Without it both ladders step on the same signal and a relaunch changes
/// two things at once.
BOOL GNExperimentControlsRunLevel(void);

/// The level the current launch was told to try after dropping, or -1.
int GNDroppedToLevel(void);

/// Watches for UIApplicationDidFinishLaunchingNotification and marks the
/// launch as survived, so the next boot keeps the current run level.
void GNObserveLaunchCompletion(void);

#pragma mark - Capability

/// YES only when this process may modify executable memory and still run.
///
/// A page that belongs to a code signed image is validated by amfi. Writing
/// through it with VM_PROT_COPY does not unlock it, it creates a private
/// anonymous copy, and the first instruction fetch from that copy is fatal:
///     termination reason  CODESIGNING
///     ktriageinfo        Failed to fault in a page with execute permissions
///
/// The only exception is a process that carries get-task-allow / is being
/// debugged (CS_DEBUGGED). That is a property of the signing certificate, so a
/// Development build tolerates in-memory patches and a Distribution build
/// never will.
BOOL GNCodePatchingAllowed(void);

/// "development" (CS_DEBUGGED) / "distribution" / "unknown".
const char *GNSignatureMode(void);

/// One line summary for the boot log.
const char *GNMemoryPolicySummary(void);

#pragma mark - Config

/// Merged config: baked-in  <-  app bundle  <-  Documents/GNUnlock.plist
NSDictionary *GNConfig(void);

BOOL        GNCFG(NSString *key, BOOL def);
NSInteger   GNCGI(NSString *key, NSInteger def);
double      GNCFGD(NSString *key, double def);
NSString   *GNCGS(NSString *key);
NSDictionary *GNCFGDict(NSString *key);
NSArray    *GNCFGArray(NSString *key);

#pragma mark - Mach-O

/// Basename of the main executable, e.g. "Goodnotes".
const char *GNMainImageName(void);

/// dyld image index for a basename, or -1.
int GNImageIndexForName(const char *image);

/// Load address of an image (== header address == slid __TEXT vmaddr).
uintptr_t GNImageBase(const char *image);

/// Slide of an image.
intptr_t  GNImageSlide(const char *image);

/// Looks up a section. `addr` comes back already slid. Pass NULL for the main image.
BOOL GNSection(const char *image, const char *seg, const char *sect,
               uintptr_t *addr, uint64_t *size);

/// YES if [addr, addr+len) lies inside one of the image's mapped segments.
BOOL GNContainsAddress(const char *image, uintptr_t addr, uint64_t len);

/// YES if the segment containing addr is executable.
BOOL GNIsExecutableAddress(uintptr_t addr);

/// YES if the image is currently loaded.
BOOL GNImageIsLoaded(const char *image);

/// YES for images that ship inside the app bundle (the app and its frameworks).
BOOL GNIsAppOwnedImage(uint32_t imageIndex);

/// YES for /System, /usr/lib, the dyld shared cache and other Apple images.
BOOL GNIsSystemImagePath(const char *path);

#pragma mark - Memory

/// Length of the readable run that starts at `addr`, capped at `maxLen`.
///
/// Found by walking the process' region table (vm_region_64) and stopping at
/// the first region that is not readable, or at the first gap. Returns 0 when
/// the mapping cannot be described at all - callers must treat that as "no
/// access", never as "probably fine".
size_t GNReadableRunLength(uintptr_t addr, size_t maxLen);

/// YES only when every byte in [addr, addr+len) is mapped and readable.
BOOL GNRangeIsReadable(uintptr_t addr, size_t len);

/// Writes bytes into a data page (mprotect RW -> write -> restore).
///
/// Refuses executable pages when GNCodePatchingAllowed() is NO: on a
/// Distribution signature that write is not "risky", it is a guaranteed kill.
BOOL GNWriteBytes(uintptr_t addr, const void *bytes, size_t len);

/// Writes bytes into a code page. Same gate as GNWriteBytes.
BOOL GNPatchCodeBytes(uintptr_t addr, const void *bytes, size_t len);

/// Parses "C0 03 5F D6" / "c0035fd6" / "0xC0,0x03" into a malloc'd buffer.
/// Caller frees *out.
BOOL GNDataFromHex(NSString *hex, void **out, size_t *len);

/// "0x231F1FC" / "231f1fc" -> 0x231F1FC
BOOL GNParseAddress(NSString *string, uint64_t *out);

#pragma mark - Symbol interception

/// Redirects a C symbol without touching executable memory.
///
/// Development signature -> classic inline hook (trampoline + branch).
/// Distribution signature -> data only: the app's own import slots
/// (__got / __auth_got / __la_symbol_ptr) are rewritten, which is plain memory
/// in a data page and therefore invisible to the code signing check.
///
/// `original` always receives the real function address.
BOOL GNInterposeSymbol(const char *symbol, void *replacement, void **original);

/// Rewrites every import slot for `symbol` in every app owned image.
/// Returns the number of call sites redirected. Never writes code pages.
NSInteger GNRebindSymbolInAppImages(const char *symbol, void *replacement, void **original);

/// Inline-patches the first 16 bytes of a dynamically resolved symbol.
/// Returns NO when code patching is not allowed for this process.
BOOL GNInlineHookSymbol(const char *symbol, void *replacement, void **original);

#pragma mark - Import slots found by address (v16)

/// The plain address inside a possibly authenticated function pointer.
uintptr_t GNSlotStripAddress(uintptr_t value);

/// true when `raw` points at `target`, plainly or through a signature this
/// slice can look through.
bool GNSlotRefersTo(uintptr_t raw, uintptr_t target);

/// The value that makes `slotAddress` point at `replacement` instead of `target`,
/// or 0 when the slot's signature cannot be reproduced exactly - in which case
/// the caller must leave the slot untouched. See src/GNRebind.m for why the
/// reproduction is the proof.
uintptr_t GNSlotMoveTo(uintptr_t raw, uintptr_t target, uintptr_t replacement,
                       uintptr_t slotAddress, const char **why);

/// Rewrites every import slot in the process that currently holds `symbol`,
/// including slots in dyld shared cache images. Data pages only - no code page
/// is written, so this is available on a Distribution signature.
///
/// Slots are matched by the address they hold, not by name: the cache keeps no
/// symbol table, which is why a name based rebinder finds nothing there.
/// `watchNewImages` rescans any framework loaded later with dlopen.
///
/// Returns the number of import slot *sections* the walk found, which is the
/// number that makes a zero explainable: zero means this process has no slot for
/// that symbol at all, i.e. every caller reaches it by direct branch and no
/// data-only mechanism can intercept it.
int32_t GNSlotRebindSymbol(const char *symbol, void *replacement, void **original,
                           bool watchNewImages);

/// The same sweep, for an address that was resolved without a name (v25).
///
/// The two CloudKit names this dylib cares about are not in the framework's stub
/// and not exported by the loaded image, so dlsym cannot produce them and the
/// name-keyed entry point above is unreachable for them. An address obtained
/// another way - the crash log's interior offset, mapped onto the image's
/// LC_FUNCTION_STARTS - goes here instead.
///
/// `label` is only for the log. `matchedOut` receives how many slots held the
/// target; zero is a result, not a failure: it means every caller reaches the
/// function by direct branch, and no data-only mechanism can intercept it.
int32_t GNSlotRebindAddress(const char *label, uintptr_t target, void *replacement,
                            bool watchNewImages, int32_t *matchedOut);

/// Counts the import slots that hold `target`, in every image, without writing
/// one of them. Same measurement GNSlotProbeSymbol makes for a named symbol,
/// for a target that has no name to look up.
int32_t GNSlotProbeAddress(uintptr_t target, int32_t *matchedOut);

/// Slots actually rewritten this launch, across every image.
int32_t GNSlotRewriteCount(void);

/// Slots that held a target address, whether or not the write was allowed.
/// The dry-run probe below is what makes this counter worth having: it answers
/// "how many callers go through a slot" for symbols this dylib does not hook.
int32_t GNSlotMatchCount(void);

/// A count-only sweep for one symbol: every import slot that holds its address is
/// counted and none is written. See the comment on the definition for why the
/// read-surface table needs to measure doors it deliberately does not arm.
int32_t GNSlotProbeSymbol(const char *symbol, void **resolvedOut);

/// Import slot sections visited this launch.
int32_t GNSlotSectionCount(void);

/// Slots that matched but were refused (signature could not be reproduced).
int32_t GNSlotRefusedCount(void);

#pragma mark - Interposing a lookup, not a function (v18)

/// Rewrites every import slot that holds dlsym() to a replacement that answers
/// with this dylib's entitlement repair for the three entitlement symbols and
/// defers everything else to the real dlsym.
///
/// Why this exists: v17 measured that no image in the process has an import slot
/// holding SecTaskCopyValuesForEntitlements - 2622 images walked, zero matches -
/// while the singular form had one. The two ways that can happen are a direct
/// branch (unreachable for a data-only hook) and a pointer resolved once with
/// dlsym and cached in a variable. This covers the second, and it covers it at
/// the only place that can: the resolution itself.
void GNInstallDlsymTap(NSDictionary *cfg);

/// How many lookups the tap has answered with a replacement this launch.
int32_t GNDlsymTapHitCount(void);

/// The tap itself. Called through a rewritten slot; public so the installer can
/// compare its address with what dlsym resolves.
void *GNDlsymTap(void *handle, const char *symbol);

/// The object tap installed for objc_exception_throw: records the exception and
/// the throw site, then calls the real function. Never changes control flow - see
/// the comment on its definition for why "returning instead of throwing" is not a
/// catch and cannot be made into one.
/// The v18 tap, kept for the legacy rebinder in GNThrowTrace.m. Not noreturn:
/// since v20 it routes through GNThrowTrampolineObject, whose swallow path
/// returns on purpose.
void GNThrowTapObject(id exception);

/// Writes the exception record (name, reason, symbolicated stack, image table)
/// and returns. Split out in v20 so the trampoline can act *after* the evidence
/// exists: a swallow that leaves no trace is indistinguishable from a throw that
/// never happened.
void GNThrowTraceRecord(id exception);

/// The real objc_exception_throw, as the slot walker resolved it. NULL until the
/// throw slot has been walked.
void *GNThrowTapRealThrow(void);

/// Hands the tap the real objc_exception_throw, resolved by the slot walker, and
/// sets the launch budget. Safe to call before or after the slot rewrite.
void GNThrowTapActivate(void *real);


#pragma mark - Who asked (v19)

/// The three doors the repair stands in front of. One enum instead of a string
/// so the per-door counters are an array index, and so two translation units
/// cannot disagree about the spelling of a door.
typedef enum {
    GNReadDoorSingle = 0,       ///< "SecTaskCopyValueForEntitlement"
    GNReadDoorBatch,            ///< "SecTaskCopyValuesForEntitlements"
    GNReadDoorSigningInfo,      ///< "SecCodeCopySigningInformation"
    GNReadDoorCount
} GNReadDoor;

/// Records one call through a repaired door: which door, the caller's return
/// address, and whether the value was rewritten.
///
/// v18 could say "the interception is LIVE" - which only means the replacement
/// runs on paths that go through a binding we control. It could not say whether
/// CloudKit was one of those paths, and the launch dying with the same exception
/// while the self-test passed means exactly that distinction matters. This is the
/// measurement that separates the two claims.
void GNReadAuditNote(GNReadDoor door, const void *caller, bool changed);

/// Stops the audit counting calls made by this dylib on purpose (the slot
/// self-test calls a door to prove the binding is ours). Balanced pair.
void GNReadAuditSuspend(void);
void GNReadAuditResume(void);

int32_t GNReadAuditHitCount(void);
int32_t GNReadAuditChangedCount(void);

/// One line: totals per door.
NSString *GNReadAuditSummary(void);

/// The paragraph that decides what to do next - see the header of
/// src/GNReadAudit.m for the three cases and what each one means.
NSString *GNReadAuditVerdict(void);

/// Prints the summary, one line per resolved call site, and the verdict. Runs on
/// a background queue a few seconds in: resolving addresses costs a dladdr per
/// site and must never happen inside a call CloudKit makes during dyld init.
void GNReadAuditDump(void);

#pragma mark - ObjC hooks (data only)

/// Swizzles an instance method. `original` receives the previous IMP.
BOOL GNHookInstance(Class cls, const char *selector, IMP replacement, IMP *original);

/// Swizzles a class method (correctly, on the metaclass).
BOOL GNHookClass(Class cls, const char *selector, IMP replacement, IMP *original);

/// ObjC convenience: hooks if the class and selector both exist.
BOOL GNHookIfExists(const char *className, const char *selector,
                    IMP replacement, IMP *original, BOOL classMethod);

#pragma mark - Modules

/// Installs launch forensics: wraps the app delegate's launch entry points so
/// an exception thrown during launch is caught, named, recorded and (by
/// default) swallowed, and traces abort()/exit() calls made by app owned code.
/// Method lists and data files only - safe on every signature.
/// Call this before the run level gate: without it a level 0 crash is as
/// opaque as the crash it is meant to explain.
void GNInstallLaunchGuard(void);

/// How many @try nets the launch guard actually got installed.
///
/// This is the number that decides whether another launch is capable of telling
/// us anything. v10 had exactly one net - the app delegate's launch methods -
/// and the crash arrived on a path where it was not in the chain, so the report
/// never happened and the .ips was as anonymous as before.
NSInteger GNGuardNetCount(void);

/// Last resort: traces objc_exception_throw itself.
///
/// `netsInstalled` is GNGuardNetCount(). With "auto" (the default) this only
/// installs when the @try nets all failed to install, because a constructor
/// time rebinding is the one thing in this dylib that has already cost a launch
/// once. When it does install, every ObjC exception is logged with its name,
/// reason and throw site, and then thrown for real.
void GNInstallThrowTracer(NSInteger netsInstalled);

/// Installs the re-sign compatibility hooks that only touch method lists:
/// app group / ubiquity container fallbacks. Safe before UIApplicationMain.
void GNInstallResignContainerFixes(NSDictionary *cfg);

/// Installs the C level re-sign fixes (SecItem*, SecStaticCode*, SecTask*).
/// Every one of them needs GOT rebinding on a Distribution signature, so this
/// is the riskiest group and the last one the auto-bisect ladder keeps.
void GNInstallResignSymbolFixes(NSDictionary *cfg);

/// Installs the config driven data-only hooks: NSUserDefaults overrides,
/// SyncedDefaults identifier override, forged HTTP responses.
/// Never writes executable memory, safe to call from the constructor.
void GNInstallDataHooks(NSDictionary *cfg);

/// Runs the config driven patch pipeline (byte patches, anchors, defaults,
/// swizzles, recon, probes). Intended to run after the app is up.
void GNRunPatches(NSDictionary *cfg);

#pragma mark - v12 forensics

/// Read-only probe of what this signed process actually holds: the entitlements
/// as they survived re-signing, and what every app group lookup really returns.
/// Installs nothing and changes nothing. See GNProbe.m.
void GNProbeSignedState(void);

/// Schedules the checks that must not run during dyld init because they block
/// on a daemon (the ubiquity container lookup). Safe to call from the
/// constructor: it only enqueues work.
void GNProbeScheduledChecks(void);

/// Captures the Objective-C exception that kills a launch, by hooking
/// -[NSException initWithName:reason:userInfo:]. Records at most a few
/// exceptions, writes each one with fsync, then removes itself.
///
/// This is the only capture in the dylib that is on the actual path every
/// exception must take - see GNExcForensics.m for why
/// NSSetUncaughtExceptionHandler never fired and why the @try nets missed.
void GNInstallExceptionForensics(void);

/// Installs the CloudKit entitlement guard: a name-allow-listed suppressor on
/// -[NSException raise], plus optional boundaries around the iCloud entry
/// points. Swallows only the CKException a malformed re-signed entitlement
/// produces; every other exception is raised untouched. See GNCloudKitGuard.m.
void GNInstallCloudKitGuard(NSDictionary *cfg);

/// Installs the v19 probe list: CloudKit's container/database entry points
/// wrapped in *observe* mode - the wrapper calls the real method and, if it
/// throws, writes the class, the selector and the exception down and then
/// rethrows. Behaviour is unchanged by construction; the log gains the name of
/// the call that actually throws, which is the one thing the v18 log could not
/// say (it recorded no SWALLOWED line and no throw site).
///
/// Safe to call more than once and after launch: CloudKit is frequently loaded
/// after the constructor runs, and a boundary for a class that is not there yet
/// is skipped rather than failed. Already-guarded pairs are skipped, so the
/// retry cannot make a wrapper call itself.
void GNInstallCloudKitProbeBoundaries(void);

/// v20: the read-surface sweep. Counts, for every public entitlement door in this
/// process, how many import slots hold its address - without rewriting one. Run
/// after launch, never during dyld init, because it is fourteen image-list walks.
void GNEntitlementReadSurfaceDump(void);

/// The v8-v11 hook stack, unchanged, from GNLegacy.m. Reached only when
/// ObserveOnly is false. Keeping it in its own file lets the lint prove that
/// src/GNUnlock.m never names a hook symbol.
void GNRunLegacyMode(void);

#ifdef __cplusplus
}
#endif
