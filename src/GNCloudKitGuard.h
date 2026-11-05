//
//  GNCloudKitGuard.h
//  Stops the launch crash the v13 probe finally named.
//
//  v13 proved the exception is real and where it comes from:
//
//      probe: com.apple.developer.icloud-services = *
//      EXCEPTION name=CKException
//                reason=Application has malformed entitlements. Found value "*"
//                       for entitlement com.apple.developer.icloud-services,
//                       expected an array of strings
//
//  The re-sign wrote a string where CloudKit requires an array. CloudKit reads
//  its own entitlements in process, finds the wrong type, and raises. Nothing
//  in this dylib caused that, and nothing in this dylib can make the entitlement
//  well formed after the fact - only the signer can. What this module can do is
//  stop that one exception from killing the process.
//
#pragma once

#import <Foundation/Foundation.h>

/// Installs the suppressor described by `cfg`.
///
/// Safe to call from the dylib constructor: it swizzles method lists only, never
/// writes a code page, and takes no lock another framework could be holding
/// during dyld init.
void GNInstallCloudKitGuard(NSDictionary *cfg);

/// How many exceptions have been swallowed this launch. Non-zero in the log is
/// the proof that the crash was reached and survived rather than avoided.
int GNCloudKitGuardSuppressedCount(void);
