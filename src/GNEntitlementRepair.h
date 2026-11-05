//
//  GNEntitlementRepair.h
//  Fix the entitlement CloudKit chokes on, in process, before CloudKit reads it.
//
//  v14's evidence, in three lines of the log:
//
//      probe: com.apple.developer.icloud-services = *
//      EXCEPTION name=CKException
//                reason=Application has malformed entitlements. Found value "*"
//                       for entitlement com.apple.developer.icloud-services,
//                       expected an array of strings
//
//  v14 tried to survive the exception at -[NSException raise]. The next launch
//  showed why that could not work: CloudKit uses @throw, which calls
//  objc_exception_throw directly and never sends -raise. So the exception is not
//  something to survive after the fact, it is something to prevent: the value
//  CloudKit reads has the wrong *type*, and the process can answer with the
//  right one.
//
//  Who is allowed to answer
//  ------------------------
//  The read is SecTaskCopyValueForEntitlement(), and it is not made by this
//  dylib - CloudKit and the ubiquity client call it from inside system images
//  that live in the dyld shared cache. Rewriting the call site (GNRebind) is not
//  available there: that walker only rebinds slots in images inside the app
//  bundle, by design, because writing an unsigned pointer into an auth slot in
//  the cache is a crash rather than a hook.
//
//  dyld can do it properly. A `__DATA,__interpose` table is read by dyld at load
//  time and applied to every binding of that symbol in the process - including
//  the bindings inside shared cache images, which dyld patches itself, with the
//  correct pointer authentication for each slot. That is the mechanism this
//  module is built on:
//
//      GNEntitlementRepairInterpose.m   the table (the only file naming the API)
//      GNEntitlementRepair.m            the policy: which keys, which type
//
//  What it will and will not do
//  ----------------------------
//  It rewrites a value only when the *type* is wrong - a scalar where CloudKit
//  requires an array of strings, an array where it requires a string, or the
//  literal wildcard "*" some signers write when they do not know the real value.
//  A correctly typed value is passed through untouched, whatever it says. This
//  is a type repair, not an entitlement grant: it does not invent an
//  entitlement the signature never had, and it cannot make iCloud work on a
//  Distribution certificate. It only stops a malformed value from being the
//  reason the launch dies.
//
#pragma once

#include <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

/// The two replacements the interpose table installs.
///
/// Declared here and defined in GNEntitlementRepair.m, so that the table itself
/// stays the only place in the tree that names a private symbol - and so that
/// scripts/v12_lint.py can keep enforcing that property.
///
/// Both signatures match the real functions at the ABI level: the task handle is
/// an opaque pointer either way, and these are C functions with no variadic or
/// struct arguments to disagree about.
CFTypeRef GNRepairCopyValueForEntitlement(const void *task, CFStringRef entitlement,
                                          CFErrorRef *error);
CFTypeRef GNRepairCopyValuesForEntitlements(const void *task, CFArrayRef entitlements,
                                            CFErrorRef *error);

/// SecCodeCopySigningInformation(), with the entitlements dictionary inside the
/// answer repaired.
///
/// v18: the v17 log proved the singular SecTask call was not the only read on the
/// path, so the third public door is covered too. A client that reads the signing
/// information dictionary gets the same repaired values, and everything else in
/// that dictionary is passed through untouched.
///
/// Returns the OSStatus the real function returned; repairs the dictionary in
/// place by replacing *information with a mutable copy when anything changed.
uint32_t GNRepairCopySigningInformation(const void *code, uint32_t flags,
                                        CFDictionaryRef *information);

/// Reads the switch, resolves the originals and states in the log whether the
/// interposition is live. Safe from the dylib constructor; installs nothing if
/// it is already installed, and never aborts on a missing symbol.
///
/// Must run before the observe early return: like the v14 CloudKit guard, this
/// is not a feature switch, it is the difference between a launch and a crash,
/// and the shipped default is the configuration the crash happens in.
void GNInstallEntitlementRepair(NSDictionary *cfg);

/// How many entitlement values were rewritten this launch. Zero with no
/// "repair:" line in the log means nothing ever asked - see the note in
/// GNInstallEntitlementRepair about what that proves.
int GNEntitlementRepairCount(void);

/// One line, for the delayed probe summary: "armed (n=0)" / "disabled" / ...
const char *GNEntitlementRepairStatus(void);

#pragma mark - Slot rewrite + launch-time self-test (v16, implemented in GNEntitlementSlot.m)

/// Rewrites every import slot in the process that holds either SecTask copy
/// function - shared cache images included - and then *measures* whether the
/// interception actually runs, by calling the same entitlement through dlsym and
/// through this dylib's own binding and comparing which ones the repair touched.
///
/// Layer 2 of three: the interpose table above is layer 1, and the self-test is
/// layer 3. Data pages only; no code page is written.
///
/// Must run before the observe early return, for the same reason as the repair.
void GNInstallEntitlementSlotHook(NSDictionary *cfg);

/// "armed (symbols=2/2, sections=41, rewritten=3, refused=0, fired=yes)"
const char *GNEntitlementSlotStatus(void);

/// "string \"*\" -> array(1) [\"CloudKit\", ...] (replacement ran)"
const char *GNEntitlementSlotSelfTestText(void);

#pragma mark - The interpose table (implemented in GNEntitlementRepairInterpose.m)

/// Number of entries in the table that ships in this build.
int GNEntitlementInterposeCount(void);

/// The address dyld bound for entry `index`'s replacee, or 0 when the symbol was
/// absent from the process (a weak import that did not resolve).
const void *GNEntitlementInterposeBoundTarget(int index);

/// The name of entry `index`'s replacee, for logging. ASCII, never NULL.
const char *GNEntitlementInterposeName(int index);

/// Calls SecTaskCopyValueForEntitlement through this dylib's own *binding* for
/// it, not through a dlsym address.
///
/// That is the difference between the two numbers v16 reports:
///
///   dlsym(RTLD_DEFAULT, ...)     the real function. dyld does not apply an
///                                interpose to dlsym, so this is the value the
///                                process actually holds.
///   this call                    whatever the process would reach through an
///                                import slot: an interposed replacement if the
///                                interposition is live, the real function if it
///                                is not.
///
/// The launch-time self-test calls both and compares. That is the in-process
/// proof v15 could not produce from a log line that only said "armed".
CFTypeRef GNEntitlementCallThroughImport(CFTypeRef task, CFStringRef entitlement,
                                         CFErrorRef *error);

/// YES when the weak import for SecTaskCopyValueForEntitlement resolved, i.e.
/// when there is a binding for the call above to go through at all.
bool GNEntitlementImportBound(void);

/// The plural equivalents (v18). The v17 log showed the plural read reachable by
/// nobody's slot, so the launch-time self-test now measures it the same way the
/// singular one was measured: call it twice, once through dlsym and once through
/// this dylib's binding, and report the type of both answers.
CFTypeRef GNEntitlementCallValuesThroughImport(CFTypeRef task, CFArrayRef entitlements,
                                               CFErrorRef *error);
bool GNEntitlementValuesImportBound(void);

#ifdef __cplusplus
}
#endif
