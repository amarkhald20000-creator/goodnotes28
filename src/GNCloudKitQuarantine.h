//
//  GNCloudKitQuarantine.h
//  Stop enumerating entry points. Enumerate the property instead. (v21)
//
//  ============================ why the list kept growing ============================
//
//  v20 replaced fourteen Objective-C entry points on CKContainer and CKDatabase,
//  chosen by hand. The device log then showed the app getting past one of them
//  and dying of the same exception anyway:
//
//      cloudkit-stub: -[GNStubCKDatabase addOperation:] -> ignored
//      EXCEPTION name=CKException reason=Application has malformed entitlements ...
//
//  That is the signature of an enumeration: it covers the calls somebody thought
//  of. CloudKit is a framework with several hundred methods across a dozen
//  classes, and the next version would have added three more names to the list
//  and learned nothing.
//
//  ============================ the property, not the list ============================
//
//  This module does not ask "which selector starts the daemon conversation". It
//  asks "which methods can start one at all", and the answer is a shape, not a
//  name:
//
//      a method that returns void can only have an effect through its arguments
//      or its side effects - it cannot hand a result back to the caller.
//
//  Every CloudKit method that submits work is of that shape: addOperation:,
//  fetchWithCompletionHandler:, saveRecord:completionHandler:, start, perform,
//  submit, requestApplicationPermission:completionHandler:, and so on. So the
//  rule is: on classes defined by a CloudKit image, any method that returns void
//  and whose selector begins with one of a small set of verb prefixes is
//  replaced by an empty implementation, and the original is never called.
//
//  ============================ why this is safe to do at this width ============================
//
//    * the return type is checked before anything is replaced. A method that
//      returns an object is left alone, because inventing a return value for a
//      non-optional Swift type is a trap, not a fallback. Those are handled
//      deliberately in GNCloudKitStub.m, one at a time, with the right object.
//
//    * the classes are filtered by the image they are defined in. A class is only
//      touched if its defining image path contains "CloudKit", so an app class
//      that happens to start with CK is not in scope.
//
//    * void, no-argument and void, many-argument methods are both covered by one
//      replacement: on arm64 the extra argument registers are simply ignored by a
//      function that declares none.
//
//  What a caller sees is "the work did not happen", which is what a device with
//  no iCloud account looks like from CloudKit's own API. What it does not see is
//  an exception out of a dispatch_once.
//
#pragma once

#import <Foundation/Foundation.h>

/// Replaces the void-returning work methods of every CloudKit class currently
/// loaded. Idempotent, and safe to call again when more CloudKit classes have
/// been loaded (CloudKit loads lazily; the launcher retries).
///
/// Honours:
///   CloudKitQuarantine              bool   master switch (default true)
///   CloudKitQuarantineMode          string "neutralise" (default) | "assert"
///   CloudKitQuarantinePrefixes      array  selector prefixes (defaults below)
///   CloudKitQuarantineLogBudget     int    selector names printed (default 12)
BOOL GNInstallCloudKitQuarantine(NSDictionary *cfg);

/// How many methods have been neutralised this launch, across all calls.
int32_t GNCloudKitQuarantineReplacedCount(void);

/// How many CloudKit classes were inspected the last time it ran.
int32_t GNCloudKitQuarantineClassCount(void);
