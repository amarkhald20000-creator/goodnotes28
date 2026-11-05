//
//  GNCloudKitStub.h
//  Stop asking CloudKit. Start answering for it. (v20)
//
//  ============================ why this exists ============================
//
//  v15 through v19 all tried to make CloudKit's own entitlement check pass: the
//  singular SecTask read, the plural SecTask read, the dlsym that resolves them,
//  the signing-information dictionary. Every one of them measured LIVE on the
//  device and every one of them left the launch dying of the same CKException.
//
//  That result is information, and it is worth stating plainly: the value CloudKit
//  rejects does not come from any door this dylib can reach. Whatever the route
//  is - another reader, a cached copy taken before this dylib loaded, or a check
//  performed outside the process altogether - the conclusion is the same. A
//  data-only hook cannot reach it, and an inline hook cannot be written on a
//  Distribution signature without losing the launch to the code page.
//
//  So v20 stops trying to make iCloud *work* and makes it *unavailable*, which
//  is a state every app already handles. An app whose user has not signed in to
//  iCloud still has to launch, so "no account" is a supported answer with a
//  supported UI behind it; "malformed entitlements" is not.
//
//  ============================== how it works ==============================
//
//  The dylib builds a runtime subclass of the real CKContainer, allocates one
//  instance of it with zeroed ivars, and answers the entry points itself. The
//  original method is never called, which matters for a reason that is not
//  cosmetic:
//
//      CloudKit validates its entitlements inside a dispatch_once. An exception
//      thrown out of that block leaves the once gate owned by this thread, and
//      the next call to the same dispatch_once from this thread is a
//      "dispatch_once() called recursively" fault. Every design that *catches*
//      the exception keeps that landmine armed. This one never enters the block.
//
//  ============================== what it is not ==============================
//
//  Not a hook on CloudKit's internals, not a code page write, not a claim that
//  iCloud will sync. It is a substitution at the outermost Objective-C entry
//  point, in a data page, reversible with one plist key.
//
#pragma once

#import <Foundation/Foundation.h>

/// Installs the substitute described by `cfg`. Idempotent and safe to call
/// before CloudKit is loaded - it returns NO and the launcher retries.
///
/// Honours:
///   CloudKitStub          bool   master switch (default true)
///   CloudKitStubMode      string "noAccount" (default) | "nil" | "observe"
///   CloudKitStubLogBudget int    log lines this launch (default 12)
BOOL GNInstallCloudKitStub(NSDictionary *cfg);

/// YES once the entry points are actually replaced in this process. The log
/// prints this; "armed" without "installed" is exactly the failure mode v15
/// shipped and v16 had to measure its way out of.
BOOL GNCloudKitStubIsInstalled(void);

/// How many calls the substitute has answered this launch.
int32_t GNCloudKitStubServeCount(void);

/// Exposed for the self test: the class the substitute instances belong to, or
/// Nil when the stub is not installed.
Class GNCloudKitStubContainerClass(void);
