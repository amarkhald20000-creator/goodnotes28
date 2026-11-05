//
//  GNPrivateSecTask.h
//  The only place in this tree that names the private SecTask API.
//
//  Why this file exists
//  --------------------
//  v12.1 called SecTaskCreateFromSelf() / SecTaskCopyValueForEntitlement()
//  directly, and the macOS job stopped on ten errors in src/GNProbe.m:
//
//      error: unknown type name 'SecTaskRef'; did you mean 'SecTrustRef'?
//      error: call to undeclared function 'SecTaskCreateFromSelf'
//
//  Those symbols are exported by Security.framework at run time, but they are
//  not in <Security/Security.h> and they are not in the SDK's Security.tbd.
//  That makes them two problems, not one:
//
//    compile  the type and the prototypes do not exist, so naming them is a
//             hard front-end error;
//    link     a hand-written `extern` prototype compiles and then fails with
//             `Undefined symbols for architecture arm64: _SecTaskCreateFromSelf`,
//             because the linker resolves against the .tbd, not the framework.
//
//  So the fix is not a declaration, it is a lookup. Everything goes through
//  dlsym(RTLD_DEFAULT, ...) in GNPrivateSecTask.m, once per process, and every
//  caller in src/ uses the wrappers below. Nothing in this tree names a private
//  symbol outside a quoted string - scripts/v12_lint.py enforces that, and the
//  stub SDK deliberately no longer declares these symbols, so the pre-flight
//  now fails where the real SDK fails instead of painting it green.
//
//  Everything here is read-only. It resolves symbols and reads entitlements; it
//  installs nothing.
//
#pragma once

#include <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Opaque handle standing in for SecTaskRef.
///
/// Deliberately structure-free: the real definition is private, and a
/// hand-written `typedef struct __SecTask *` would be a private declaration by
/// another name. A SecTask is a CFType, so CFRelease() is the correct way to
/// drop it.
typedef const void *GNSecTaskHandle;

/// Resolves the two symbols once and logs the outcome. Safe from a dylib
/// constructor, safe to call repeatedly, and a failure is a log line - never an
/// abort, never a guess.
void GNPrivateSecTaskResolve(void);

/// YES when both symbols resolved in this process. Callers have to check it:
/// where Security never loaded there is nothing to read, and the honest answer
/// is "unknown" rather than a fabricated one.
bool GNPrivateSecTaskAvailable(void);

/// SecTaskCreateFromSelf(); NULL when the symbol is unavailable.
GNSecTaskHandle GNPrivateSecTaskCreateFromSelf(void);

/// SecTaskCopyValueForEntitlement(); the caller owns the returned object.
/// NULL when the symbol is unavailable or the entitlement is absent.
CFTypeRef GNPrivateSecTaskCopyEntitlement(GNSecTaskHandle task, CFStringRef entitlement);

/// SecTaskCopyValuesForEntitlements(); the caller owns the returned dictionary.
/// The plural form, resolved the same way. NULL when unavailable.
CFTypeRef GNPrivateSecTaskCopyValues(GNSecTaskHandle task, CFArrayRef entitlements);

#ifdef __cplusplus
}
#endif
