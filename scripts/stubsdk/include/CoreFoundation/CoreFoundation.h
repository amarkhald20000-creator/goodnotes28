// Stub <CoreFoundation/CoreFoundation.h>
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <objc/runtime.h>

typedef const void *CFTypeRef;
typedef const struct __CFString *CFStringRef;
typedef const struct __CFArray *CFArrayRef;
typedef const struct __CFDictionary *CFDictionaryRef;
typedef struct __CFDictionary *CFMutableDictionaryRef;
typedef const struct __CFAllocator *CFAllocatorRef;
typedef const struct __CFError *CFErrorRef;
typedef const struct __CFBoolean *CFBooleanRef;
typedef const struct __CFData *CFDataRef;
typedef const struct __CFURL *CFURLRef;
typedef const struct __CFNumber *CFNumberRef;
typedef long CFIndex;
typedef unsigned long CFTypeID;
typedef unsigned int CFOptionFlags;

typedef struct {
    CFIndex version;
    void *info;
    const void *(*retain)(const void *info);
    void (*release)(const void *info);
    CFStringRef (*copyDescription)(const void *info);
} CFDictionaryKeyCallBacks;

typedef struct {
    CFIndex version;
    void *info;
    const void *(*retain)(const void *info);
    void (*release)(const void *info);
    CFStringRef (*copyDescription)(const void *info);
} CFDictionaryValueCallBacks;

extern const CFAllocatorRef kCFAllocatorDefault;
extern const CFBooleanRef kCFBooleanTrue;
extern const CFBooleanRef kCFBooleanFalse;

#ifdef __cplusplus
extern "C" {
#endif

CFTypeRef CFRetain(CFTypeRef cf);
void CFRelease(CFTypeRef cf);
CFIndex CFGetRetainCount(CFTypeRef cf);
CFTypeID CFGetTypeID(CFTypeRef cf);
CFTypeID CFBooleanGetTypeID(void);
CFTypeID CFStringGetTypeID(void);
CFTypeID CFDictionaryGetTypeID(void);
CFTypeID CFArrayGetTypeID(void);

CFMutableDictionaryRef CFDictionaryCreateMutableCopy(CFAllocatorRef allocator,
                                                     CFIndex capacity,
                                                     CFDictionaryRef theDict);
CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator,
                                                 CFIndex capacity,
                                                 const CFDictionaryKeyCallBacks *keyCallBacks,
                                                 const CFDictionaryValueCallBacks *valueCallBacks);
bool CFDictionaryContainsKey(CFDictionaryRef theDict, const void *key);
const void *CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);
void CFDictionaryRemoveValue(CFMutableDictionaryRef theDict, const void *key);
void CFDictionarySetValue(CFMutableDictionaryRef theDict,
                          const void *key, const void *value);
CFIndex CFDictionaryGetCount(CFDictionaryRef theDict);
CFIndex CFArrayGetCount(CFArrayRef theArray);
const void *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
/// <CoreFoundation/CFString.h>. 0x08000100 is the real ABI value; the stub
/// only has to make the constant resolvable and distinct from the others.
enum {
    kCFStringEncodingMacRoman = 0,
    kCFStringEncodingUTF8     = 0x08000100,
};

CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr,
                                      unsigned int encoding);

/// <CoreFoundation/CFString.h>: Boolean, not bool. The return type is part of
/// the signature the real header declares, so the stub keeps it.
unsigned char CFStringGetCString(CFStringRef theString, char *buffer,
                                 CFIndex bufferSize, unsigned int encoding);

/// <CoreFoundation/CFArray.h>
typedef struct {
    CFIndex version;
    const void *(*retain)(const void *info);
    void (*release)(const void *info);
    CFStringRef (*copyDescription)(const void *info);
} CFArrayCallBacks;

extern const CFArrayCallBacks kCFTypeArrayCallBacks;
extern const CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks;
extern const CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;

CFArrayRef CFArrayCreate(CFAllocatorRef allocator, const void **values,
                         CFIndex numValues, const CFArrayCallBacks *callBacks);

/// <CoreFoundation/CFBundle.h>
typedef const struct __CFBundle *CFBundleRef;
CFBundleRef CFBundleGetMainBundle(void);
CFStringRef CFBundleGetIdentifier(CFBundleRef bundle);

CFTypeRef CFBridgingRetain(id X);
id CFBridgingRelease(CFTypeRef X);

#ifdef __cplusplus
}
#endif

#define CF_IMPLICIT_BRIDGING_ENABLED
