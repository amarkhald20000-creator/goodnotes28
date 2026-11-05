//
//  GNXPCGate.h
//  Cut the daemon conversation at the connection, not at the API above it. (v21, v22)
//
//  ============================ the v20 result, read honestly ============================
//
//  v20's substitution worked exactly as designed:
//
//      cloudkit-stub: installed (mode=noAccount)
//      cloudkit-stub: -[GNStubCKDatabase addOperation:] -> ignored, there is no
//                     database behind this object
//
//  and the launch still died of the same CKException, one step later. That is a
//  very specific piece of information: the Objective-C entry point we replaced
//  was not the thing that failed. Something *underneath* it was still running,
//  and it was still talking to cloudd.
//
//  Two possibilities produce that, and they need different tools:
//
//    1. GoodNotes does not only call CKDatabase. It builds a CKOperation, and the
//       operation machinery reaches the daemon by a route that never passes
//       through -[CKDatabase addOperation:]. Then the entry point that matters is
//       the connection, not the API.
//
//    2. The check that fails is performed by cloudd itself, from the process's
//       code signature. Then no in-process value can ever satisfy it, and the
//       only fix is to stop asking.
//
//  This module is the answer to both, because both are the same answer: do not
//  let a CloudKit connection reach a real service.
//
//  ============================ how, without a code page ============================
//
//  Two data-page mechanisms:
//
//    * __DATA,__interpose on xpc_connection_create. A CloudKit service name is
//      replaced with a name that has no service behind it. The connection object
//      is real, the resume is real, and the failure CloudKit receives is the
//      genuine XPC_ERROR_CONNECTION_INVALID libxpc produces for a dead endpoint -
//      no fabricated reply object, no invented error.
//
//    * -[NSXPCConnection initWithMachServiceName:options:] gets the same name
//      substitution, for the parts of CloudKit that use the Foundation flavour.
//
//  Nothing here calls the operation methods, mocks a CK object, or writes code.
//  A connection to a name with nothing behind it is a state libxpc defines.
//
//  ============================ v22: the entry point that had to go ============================
//
//  v21 also interposed xpc_connection_create_mach_service, and that is what broke
//  the build:
//
//      error: 'xpc_connection_create_mach_service' is unavailable: not available on iOS
//      error: conflicting types for 'xpc_connection_create_mach_service'
//
//  Apple declares it in <xpc/connection.h> with __attribute__((unavailable)) on
//  this platform. A function the SDK says does not exist here cannot be named in
//  an initialiser, and there is no in-process substitute for interposing it: an
//  inline hook needs a code page, and a Distribution signature forbids that
//  (GNCapability.m reports codePatching BLOCKED). So it is gone - declaration,
//  replacement, table entry and dlsym name - and the log says so on every launch
//  instead of letting the word "installed" imply a coverage this file does not
//  have.
//
//  The remaining C entry point is declared under a private identifier with an asm
//  label (see GNXPCGate.m), which is the same shape the other two interposing
//  files in this tree use. The compiler has no declaration to compare against and
//  no identifier for an availability attribute to attach to, so the file cannot
//  repeat v21's failure whatever headers the SDK pulls in.
//
#pragma once

#import <Foundation/Foundation.h>

/// Installs the gate described by `cfg`.
///
/// Honours:
///   XPCGate           bool    master switch (default true)
///   XPCGateNSXPC      bool    also rewrite NSXPCConnection service names (default true)
///   XPCGateServices   array   substrings that count as CloudKit (default:
///                             cloudd, cloudkit, com.apple.ck.)
///   XPCGateLogBudget  int     log lines this launch (default 8)
void GNInstallXPCGate(NSDictionary *cfg);

/// How many connection creations were redirected this launch.
int32_t GNXPCGateRedirectCount(void);

/// The substitute service name. Exposed so the log and the self test agree on
/// what "redirected" means, instead of each spelling it separately.
const char *GNXPCGateBlackholeName(void);
