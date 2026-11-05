//
//  GNInterposeReal.h
//  The one place that answers "what is the function this replacement replaced".
//  (v22)
//
//  ====================== why this is a module and not a line of dlsym ======================
//
//  v21 resolved the real function with `dlsym(RTLD_DEFAULT, name)` and trusted
//  the answer. dyld is entitled to interpose a dlsym result: in dyld4 every
//  symbol lookup ends in `targetAddressForDlsym = interpose(state, ...)`, on all
//  three lookup paths. In a process where that happens, "the real function" is
//  this dylib's own replacement, and calling it is unbounded recursion with a log
//  line in front of it claiming the call-through worked.
//
//  v18 met that risk in the entitlement repair and guarded one file's worth of it
//  (GNRefuseOwnReplacement). v21 added two more interposing files and guarded
//  neither. This is that guard, once, for all of them.
//
//  ====================== the two sources, in the order that is safe ======================
//
//   1. dlsym. Correct in the common case, where dyld resolves the symbol without
//      applying the table to its own lookup. Refused if the answer *is* the
//      replacement, which is the tell that interposition applied to dlsym here.
//
//   2. the replacee half of our own __DATA,__interpose tuple. That pointer is
//      what dyld read in order to install this replacement. If the replacement
//      is running at all, the tuple was intact when dyld used it, and this is
//      the real address - which is why this source is tried before giving up and
//      why it is the one that still answers when dlsym cannot.
//
//  If neither is trustworthy the answer is NULL, and every caller in this tree is
//  required to degrade rather than to call something and hope. dlsym and the
//  tuple disagreeing in this direction is not a case to paper over: it means the
//  table and the lookup are in different worlds, and the log says so by name.
//
#pragma once

#import <Foundation/Foundation.h>

/// Resolve the function to call through, for a replacement installed by an
/// __DATA,__interpose table.
///
/// \param name         the symbol name as a string, e.g. "objc_exception_throw"
/// \param tableHalf    the replacee half of the tuple this replacement was
///                     installed with, or NULL when the caller does not have one
/// \param replacement  the replacement itself; an answer equal to this is refused
/// \param tag          log prefix, e.g. "throw-interpose" or "xpc-gate"
/// \return the real function, or NULL when nothing trustworthy is left
void *GNInterposeReal(const char *name, const void *tableHalf, const void *replacement,
                      const char *tag);

/// How many resolutions have been logged this launch (for the beacon's tail).
int32_t GNInterposeRealLogCount(void);
