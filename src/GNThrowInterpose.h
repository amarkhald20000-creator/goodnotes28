//
//  GNThrowInterpose.h
//  Give v20's trampoline the reach it was always missing. (v21)
//
//  v20 classified three throw sites and shipped a perfectly good decoder that
//  never saw the throw that mattered, because it was installed by rewriting import
//  slots and CloudKit's call did not come through one.
//
//  dyld's __DATA,__interpose table is applied to every binding in the process -
//  shared cache images included - so the same decoder, the same return-site
//  proof and the same swallow budget now see every Objective-C exception thrown
//  anywhere in the process.
//
//  The table is link time and cannot be removed at run time. That is stated in
//  three places on purpose (here, the .m, and the plist) because a switch that
//  keeps working after being turned off is worse than no switch: "off" means
//  pass-through here, and the log says so.
//
#pragma once

#import <Foundation/Foundation.h>

/// Arms the interposed replacement with the real function and copies the
/// trampoline's own configuration in.
///
/// Honours:
///   ThrowInterpose             bool  gate (default true; off = pass-through)
///   ThrowSwallowAtSite         bool  (read by GNThrowTrampolineArm)
///   ThrowSwallowBudget         int   (likewise)
///   ThrowTrampolineLogBudget   int   (likewise)
void GNInstallThrowInterpose(NSDictionary *cfg);

/// Entries in the interpose table. One; the number is logged so a log can never
/// be read as "installed" when the table came out empty.
int32_t GNThrowInterposeCount(void);

/// Exceptions that arrived through the table this launch.
int32_t GNThrowInterposeCallCount(void);

/// YES once the real function has been resolved and the trampoline armed.
BOOL GNThrowInterposeIsArmed(void);
