//
//  GNThrowTrampoline.h
//  The objc_exception_throw replacement, with an instruction-level answer to
//  "can this one be returned from". (v20)
//
//  ============================ what v19 asked for ============================
//
//  "Implement the Assembly Trampoline for objc_exception_throw ... to safely
//  swallow the exception when the name is CKException."
//
//  Half of that is possible and this file does it. The other half is not, and
//  the interesting part is *why*, because it is not a matter of writing better
//  assembly.
//
//  A slot rewrite already is a trampoline. The caller reaches the function
//  through `blr x16`, so when our replacement starts, x0 holds the exception and
//  x30 holds the return address - exactly the state a hand written stub would
//  have. There is no register to save that C does not already save, and the tail
//  call to the real function is emitted as one branch.
//
//  What assembly *could* additionally do is skip the call and return to x30.
//  Whether that is a swallow or a crash is decided entirely by the instruction at
//  x30, because the compiler emitted that call knowing the function does not
//  return:
//
//    * if the next instruction is `ret`, or `b`, or `ldp x29, x30, [sp], #n`
//      followed by `ret`, then returning really does return from the throwing
//      function, with x0 as its result. Control flow stays valid. The value is a
//      lie, but it is a lie the caller survives.
//
//    * otherwise (the common case - the throw is mid-function, and the next
//      bytes are another basic block or another function's prologue) returning
//      resumes into code that was never meant to run, with registers still
//      holding the operands of the throw. That is not a swallow, it is a
//      different crash with a worse log, and in CloudKit it happens inside a
//      dispatch_once whose gate is now owned by this thread for ever.
//
//  So v20 decodes that instruction and tells you which case you are in, every
//  time, in the log. Swallowing is available - ThrowSwallowAtSite - and it only
//  ever fires where the decode proves the continuation is a return.
//
#pragma once

#import <Foundation/Foundation.h>

/// Installs the trampoline as the process-wide objc_exception_throw replacement.
/// Takes the real function, resolved by the slot walker before any slot is
/// rewritten, so the trampoline can never call itself.
void GNThrowTrampolineArm(void *realFunction);

/// The replacement the slot walker installs. Same ABI as objc_exception_throw:
/// one pointer argument in x0, result in x0.
///
/// Deliberately *not* declared noreturn here: the swallow path returns, and a
/// function that returns must not be declared as one that cannot.
void *GNThrowTrampolineObject(void *exception);

/// One line per swallow decision this launch, for the log and the self test.
int32_t GNThrowTrampolineSwallowedCount(void);

/// v23: how many of those were forced - swallowed at a site whose continuation
/// the decoder could not prove was a return. Non-zero means the launch is running
/// on the resume-the-block gamble described in the config, not on the proof.
int32_t GNThrowTrampolineForcedCount(void);

/// How many throw sites have been classified this launch.
int32_t GNThrowTrampolineClassifiedCount(void);
