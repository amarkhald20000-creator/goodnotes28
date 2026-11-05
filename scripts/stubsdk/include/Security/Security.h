//
//  Stub <Security/Security.h>
//
//  Declares exactly the public API this project calls, with the SDK signatures,
//  so the front end can type check the replacement functions and their dlsym
//  casts. Not a usable Security implementation.
//
//  It must not declare anything the public SDK does not declare. v12.1 built
//  green in scripts/stubcheck.sh and failed on the macOS runner with ten errors,
//  because this stub used to declare the private SecTask family: the pre-flight
//  was checking a header it had authored, not the one CI compiles against.
//
//  A stub that is more permissive than the SDK does not test anything - it
//  converts a front-end error into a false green. The private symbols
//  (SecTaskRef, SecTaskCreateFromSelf, SecTaskCopyValueForEntitlement, ...) are
//  intentionally absent here so the pre-flight fails where the SDK fails.
//  They are resolved at run time through src/GNPrivateSecTask.h.
//
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <CoreFoundation/CoreFoundation.h>

typedef int32_t OSStatus;
typedef uint32_t SecCSFlags;
typedef struct __SecCode *SecCodeRef;
typedef struct __SecStaticCode *SecStaticCodeRef;
typedef struct __SecRequirement *SecRequirementRef;
typedef struct __SecKeychain *SecKeychainRef;

extern const CFStringRef kSecClass;
extern const CFStringRef kSecAttrAccessGroup;
extern const CFStringRef kSecAttrService;
extern const CFStringRef kSecAttrAccount;
extern const CFStringRef kSecAttrGeneric;
extern const CFStringRef kSecValueData;
extern const CFStringRef kSecReturnData;
extern const CFStringRef kSecReturnAttributes;
extern const CFStringRef kSecMatchLimit;
extern const CFStringRef kSecMatchLimitOne;

enum {
    errSecSuccess = 0,
    errSecParam = -50,
    errSecItemNotFound = -25300,
    errSecMissingEntitlement = -34018,
};

#ifdef __cplusplus
extern "C" {
#endif

OSStatus SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result);
OSStatus SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result);
OSStatus SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
OSStatus SecItemDelete(CFDictionaryRef query);

OSStatus SecStaticCodeCheckValidity(SecStaticCodeRef staticCode,
                                    SecCSFlags flags,
                                    SecRequirementRef requirement);
OSStatus SecStaticCodeCheckValidityWithErrors(SecStaticCodeRef staticCode,
                                              SecCSFlags flags,
                                              SecRequirementRef requirement,
                                              CFErrorRef *errors);
OSStatus SecCodeCheckValidity(SecCodeRef code, SecCSFlags flags,
                              SecRequirementRef requirement);
OSStatus SecCodeCheckValidityWithErrors(SecCodeRef code, SecCSFlags flags,
                                        SecRequirementRef requirement,
                                        CFErrorRef *errors);
OSStatus SecCodeCopySigningInformation(SecCodeRef code, SecCSFlags flags,
                                       CFDictionaryRef *information);
OSStatus SecStaticCodeCreateWithPath(CFURLRef path, SecCSFlags flags,
                                     SecStaticCodeRef *staticCode);

// The SecTask family is deliberately not declared here. See the note at the top:
// it is private, the public SDK has no such declaration, and a stub that offers
// one turns a real front-end error into a green local build.

#ifdef __cplusplus
}
#endif
