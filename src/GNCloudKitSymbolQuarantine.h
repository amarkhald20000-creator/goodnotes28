//
//  GNCloudKitSymbolQuarantine.h
//  The two names the v22 crash log gave, resolved at run time instead of at
//  link time. (v25)
//
//  ==================== why v24 could not link ====================
//
//  v23/v24 put these two in a __DATA,__interpose tuple:
//
//      CloudKit  $sSo9CKPersonaC8CloudKitE6launchABSgvgZ + 592   (CKPersona.launch)
//      CloudKit  CKMainBundleIsAppleExecutable + 60
//
//  weak_import did not save it. A weak import still has to name something the
//  linker can recognise, and neither name is in CloudKit's .tbd:
//
//      Undefined symbols for architecture arm64:
//        "static (extension in CloudKit):__C.CKPersona.launch.getter : __C.CKPersona?"
//        "_CKMainBundleIsAppleExecutable"
//
//  That is the same fact the v23 install log was already reporting at run time -
//  "is not exported by any image in this process" - arriving one stage earlier,
//  as a build failure. So v25 removes the last link-time reference to either
//  name. Nothing in this file is an extern any more.
//
//  ==================== what replaces it ====================
//
//  Two steps, and the first one is expected to fail:
//
//    1. dlsym. RTLD_DEFAULT, RTLD_NEXT, then a RTLD_NOLOAD handle on CloudKit.
//       For a symbol that is not in the stub this answers NULL, which is
//       measured and logged rather than assumed either way.
//
//    2. The offset from the crash log. A .ips frame gives an *interior* offset
//       ("CKPersona.launch + 592"), and the image carries its function entry
//       points without names in LC_FUNCTION_STARTS. Walking that delta list and
//       keeping the last start <= the offset turns "somewhere 592 bytes into
//       this function" into the entry address a caller would bind. See
//       src/GNFunctionStarts.h - it is pure, and executed by a host test.
//
//  Whatever step 2 produces is then handed to the address-keyed slot rebinder
//  (GNSlotRebindAddress), which walks every import slot section in the process
//  and redirects the slots that hold that address. No symbol name is involved at
//  any point after the dlsym attempt.
//
//  ==================== the boundary, stated once ====================
//
//  A slot rewrite reaches *bindings*. CloudKit calling its own function inside
//  its own image is a direct branch, and there is no slot to rewrite. The log
//  therefore reports, per entry: the address, where it came from, how many slots
//  held it, and how many were rewritten. Zero slots is a finished measurement,
//  not a failure - it says the remaining layer is the throw-level swallow, and
//  the log says that in one sentence instead of implying coverage it does not
//  have.
//
#pragma once

#import <Foundation/Foundation.h>

/// How many entries this file knows about. Constant: a table with one entry
/// missing is a table that quietly stops answering for a name the backtrace
/// produced.
int32_t GNCloudKitSymbolQuarantineCount(void);

/// Human name for the log: "CKPersona.launch", "CKMainBundleIsAppleExecutable".
const char *GNCloudKitSymbolQuarantineName(int32_t index);

/// YES when an address was obtained for this entry - by dlsym, or from the
/// configured offset. NO means both sources came up empty and nothing was
/// rewritten for it; the log says which source failed and why.
BOOL GNCloudKitSymbolQuarantineIsResolved(int32_t index);

/// The resolved entry address, stripped of any PAC, or 0.
uintptr_t GNCloudKitSymbolQuarantineTarget(int32_t index);

/// Slots that held the target, across every image, whether or not the write was
/// allowed. 0 with IsResolved() YES is the direct-branch answer.
int32_t GNCloudKitSymbolQuarantineMatchCount(int32_t index);

/// Slots actually redirected for this entry.
int32_t GNCloudKitSymbolQuarantineRewriteCount(int32_t index);

/// How many times a replacement ran this launch (any entry).
int32_t GNCloudKitSymbolQuarantineHitCount(void);

/// Installs the layer. Honours:
///
///   CloudKitSymbolQuarantine                     bool   master switch
///   CloudKitSymbolRebind                         bool   rewrite slots (default
///                                                       true; false = measure only)
///   CloudKitSymbolQuarantinePersonaLaunch        bool   entry 1 (default true)
///   CloudKitSymbolQuarantineMainBundleIsApple    bool   entry 2 (default true)
///   CloudKitSymbolQuarantineMainBundleAnswer     bool   what entry 2 answers
///                                                       (default true)
///   CloudKitSymbolQuarantineLogBudget            int    lines (default 8)
///   CloudKitSymbolImage                          string image to resolve offsets
///                                                       against (default "CloudKit")
///   CloudKitSymbolOffsets                        dict   label -> hex offset
///   CloudKitSymbolOffsetKind                     string "interior" (default) or
///                                                       "entry"
///
/// "interior" means the number is the one the crash log prints after the function
/// name ("+ 592"), and the entry is found through LC_FUNCTION_STARTS. "entry"
/// means the number already is the entry offset from the image base, which is
/// what an offline load-command dump gives.
void GNInstallCloudKitSymbolQuarantine(NSDictionary *cfg);
