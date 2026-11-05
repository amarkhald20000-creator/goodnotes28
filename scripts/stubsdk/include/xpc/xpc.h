//
//  xpc/xpc.h - the part of libxpc this project names, with the availability
//  attributes the real SDK carries.
//
//  ===================== why this stub exists =====================
//
//  v21 named xpc_connection_create_mach_service in an interpose table and died on
//  the macOS runner with
//
//      error: 'xpc_connection_create_mach_service' is unavailable: not available on iOS
//      error: conflicting types for 'xpc_connection_create_mach_service'
//
//  while this pre-flight was green. The reason is the rule this directory is
//  written to (see mach/mach_vm.h): a stub is only worth running if it fails where
//  the SDK fails, and scripts/stubsdk had no xpc header at all - so a source that
//  declared its own prototypes had nothing to disagree with here, and the first
//  contradiction happened on the runner.
//
//  So: the declarations below are Apple's, including the attribute that makes the
//  mach-service variant unnameable on this platform, and <Foundation/Foundation.h>
//  in this stub includes this header for the same reason the real one does (v21's
//  error came from a header that arrived transitively, not from an include of its
//  own).
//
//  scripts/stubcheck.sh requires three things of it, so it cannot drift back:
//
//    * naming xpc_connection_create_mach_service must be rejected,
//    * re-declaring xpc_connection_create by hand must be rejected as a conflict,
//    * the asm-labelled declaration this tree uses must compile next to Apple's.
//
#pragma once

#include <stdint.h>
#include <dispatch/dispatch.h>

/// Apple's type: an opaque struct pointer, not void*. That detail is what makes a
/// hand-written `extern void *xpc_connection_create(...)` a conflicting
/// declaration rather than a harmless duplicate.
typedef struct xpc_connection_s *xpc_connection_t;

xpc_connection_t xpc_connection_create(const char *name, dispatch_queue_t targetq);

/// Available on macOS, not available on iOS. The message is the SDK's own wording,
/// because the point of the stub is to reproduce the diagnostic, not to improve it.
xpc_connection_t xpc_connection_create_mach_service(const char *name,
                                                    dispatch_queue_t targetq,
                                                    uint64_t flags)
    __attribute__((unavailable("not available on iOS")));
