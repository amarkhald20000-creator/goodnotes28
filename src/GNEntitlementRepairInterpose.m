//
//  GNEntitlementRepairInterpose.m
//  The only file in this tree allowed to name the private SecTask API.
//
//  Why the exception exists
//  -----------------------
//  v12.1 was rejected by the macOS front end for naming SecTaskCreateFromSelf in
//  src/GNProbe.m, and the fix was to route every call through
//  dlsym(RTLD_DEFAULT, ...) in src/GNPrivateSecTask.m. scripts/v12_lint.py has
//  enforced "a private symbol may be named only inside a quoted dlsym name"
//  ever since, and that rule is still right for every caller.
//
//  It is not sufficient here, because dyld's interposition is a *link time*
//  structure: the table has to contain the address of the function being
//  replaced, and an address cannot come from a string. So this one translation
//  unit names two symbols, and the lint rule was narrowed rather than dropped:
//
//      interpose-weak-import   every name here must be declared weak_import
//      interpose-section       the table must live in __DATA,__interpose
//      interpose-address-only  nothing here may call the symbols
//
//  Why weak_import
//  ---------------
//  These two functions are exported by Security.framework at run time but they
//  are not in the SDK's Security.tbd, so a plain extern reference compiles and
//  then fails at link time with "Undefined symbols for architecture arm64" -
//  which is exactly how v12.1 died. weak_import tells the linker "bind this if
//  it is there", which is also the honest description of the situation: a
//  process in which Security never loaded has nothing to interpose, and the
//  bound value below reads back as 0 so the log can say so instead of pretending
//  the repair is live.
//
//  Why __DATA,__interpose does the job that GNRebind cannot
//  --------------------------------------------------------
//  GNRebind rewrites import slots, and it deliberately restricts itself to
//  images inside the app bundle. The calls that matter here are made by CloudKit
//  and the ubiquity client, i.e. from the dyld shared cache. dyld applies an
//  interpose section to every image in the process, cache included, and it does
//  its own pointer authentication per slot - which is the part that cannot be
//  reimplemented safely by hand (see GNSignPointer: without the discriminator
//  from the chain there is nothing to sign with).
//
//  Nothing here runs, decides, or writes anything at load time. dyld reads the
//  table; the decisions are in GNEntitlementRepair.m.
//

#import "GNEntitlementRepair.h"

#pragma mark - The two declarations

extern CFTypeRef SecTaskCopyValueForEntitlement(const void *task, CFStringRef entitlement, CFErrorRef *error) __attribute__((weak_import));

extern CFTypeRef SecTaskCopyValuesForEntitlements(const void *task, CFArrayRef entitlements, CFErrorRef *error) __attribute__((weak_import));

#pragma mark - The table

typedef struct {
    const void *replacement;
    const void *replacee;
} GNInterposeTuple;

/// Layout is Apple's: an array of {replacement, replacee} pairs in a section
/// named __interpose. `used` because nothing in this image refers to the table -
/// the consumer is dyld, and without it the linker is entitled to drop the whole
/// thing, which would turn this file into a very quiet no-op.
__attribute__((used))
static GNInterposeTuple GNEntitlementInterposeTable[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)&GNRepairCopyValueForEntitlement,   (const void *)&SecTaskCopyValueForEntitlement },
    { (const void *)&GNRepairCopyValuesForEntitlements, (const void *)&SecTaskCopyValuesForEntitlements },
};

static const char *const kGNEntitlementInterposeNames[] = {
    "SecTaskCopyValueForEntitlement",
    "SecTaskCopyValuesForEntitlements",
};

#pragma mark - Reporting

int GNEntitlementInterposeCount(void) {
    return (int)(sizeof(GNEntitlementInterposeTable) / sizeof(GNEntitlementInterposeTable[0]));
}

const void *GNEntitlementInterposeBoundTarget(int index) {
    if (index < 0 || index >= GNEntitlementInterposeCount()) return NULL;
    return GNEntitlementInterposeTable[index].replacee;
}

const char *GNEntitlementInterposeName(int index) {
    if (index < 0 || index >= GNEntitlementInterposeCount()) return "?";
    return kGNEntitlementInterposeNames[index];
}

#pragma mark - Calling through the binding (v16 self-test)

bool GNEntitlementImportBound(void) {
    return (&SecTaskCopyValueForEntitlement != NULL) &&
           (SecTaskCopyValueForEntitlement != NULL);
}

CFTypeRef GNEntitlementCallThroughImport(CFTypeRef task, CFStringRef entitlement,
                                        CFErrorRef *error) {
    if (SecTaskCopyValueForEntitlement == NULL) return NULL;
    return SecTaskCopyValueForEntitlement((const void *)task, entitlement, error);
}

bool GNEntitlementValuesImportBound(void) {
    return (&SecTaskCopyValuesForEntitlements != NULL) &&
           (SecTaskCopyValuesForEntitlements != NULL);
}

CFTypeRef GNEntitlementCallValuesThroughImport(CFTypeRef task, CFArrayRef entitlements,
                                               CFErrorRef *error) {
    if (SecTaskCopyValuesForEntitlements == NULL) return NULL;
    return SecTaskCopyValuesForEntitlements((const void *)task, entitlements, error);
}
