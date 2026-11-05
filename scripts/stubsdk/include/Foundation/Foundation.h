#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#include <objc/objc.h>
#include <objc/NSObjCRuntime.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>

// libxpc is in scope on iOS whether or not a source asks for it - v21's errors came
// from exactly that, a conflicting declaration against a header nobody included.
// The stub reproduces the situation instead of being friendlier than the SDK.
#include <xpc/xpc.h>

typedef unsigned short unichar;
typedef double NSTimeInterval;

#ifndef CGFLOAT_DEFINED
#define CGFLOAT_DEFINED 1
typedef double CGFloat;
#endif

#ifndef NSRange_defined
#define NSRange_defined 1
typedef struct { NSUInteger location; NSUInteger length; } NSRange;
#endif

#ifndef NS_ENUM
#define NS_ENUM(_type, _name) enum _name : _type _name; enum _name : _type
#endif
#ifndef NS_OPTIONS
#define NS_OPTIONS(_type, _name) enum _name : _type _name; enum _name : _type
#endif
#ifndef NS_FORMAT_FUNCTION
#define NS_FORMAT_FUNCTION(F, A)
#endif
#ifndef NS_ASSUME_NONNULL_BEGIN
#define NS_ASSUME_NONNULL_BEGIN
#define NS_ASSUME_NONNULL_END
#endif
#ifndef NS_DESIGNATED_INITIALIZER
#define NS_DESIGNATED_INITIALIZER
#endif
#ifndef NS_UNAVAILABLE
#define NS_UNAVAILABLE
#endif
#ifndef API_AVAILABLE
#define API_AVAILABLE(...)
#endif
#ifndef FOUNDATION_EXPORT
#define FOUNDATION_EXPORT extern
#endif

typedef enum {
    NSUTF8StringEncoding = 4,
} NSStringEncoding;


typedef enum {
    NSDocumentDirectory = 9,
    NSCachesDirectory = 13,
    NSApplicationSupportDirectory = 14,
    NSLibraryDirectory = 5,
} NSSearchPathDirectory;

typedef enum {
    NSUserDomainMask = 1,
    NSLocalDomainMask = 2,
    NSSystemDomainMask = 8,
    NSAllDomainsMask = 0x0ffff,
} NSSearchPathDomainMask;

enum {
    NSNotFound = 0x7fffffffffffffffL,
    NSCaseInsensitiveSearch = 1,
    NSLiteralSearch = 2,
};

#ifndef NSComparisonResult_defined
#define NSComparisonResult_defined 1
typedef NSInteger NSComparisonResult;
enum {
    NSOrderedAscending = -1,
    NSOrderedSame = 0,
    NSOrderedDescending = 1,
};
#endif

extern NSString *const NSURLErrorDomain;
enum { NSURLErrorCancelled = -999 };

typedef NSUInteger NSURLRequestCachePolicy;
enum {
    NSURLCacheStorageAllowed = 0,
    NSURLCacheStorageNotAllowed = 2,
};


#pragma mark - Forward declarations

@class NSString, NSMutableString, NSArray, NSMutableArray, NSDictionary,
       NSMutableDictionary, NSSet, NSNumber, NSData, NSMutableData, NSURL,
       NSError, NSException, NSFileManager, NSBundle, NSUserDefaults,
       NSCharacterSet, NSPropertyListSerialization, NSJSONSerialization,
       NSScanner, NSNotification, NSNotificationCenter, NSOperationQueue,
       NSThread, NSRunLoop, NSProcessInfo, NSValue, NSDate, NSLock,
       NSURLRequest, NSMutableURLRequest, NSURLResponse, NSHTTPURLResponse,
       NSURLProtocol, NSIndexSet, NSNull, NSUUID;
@protocol NSURLProtocolClient;

#pragma mark - Protocols

@protocol NSCopying
- (id)copyWithZone:(void *)zone;
@end

@protocol NSMutableCopying
- (id)mutableCopyWithZone:(void *)zone;
@end

#pragma mark - NSObject

@protocol NSFastEnumeration
- (NSUInteger)countByEnumeratingWithState:(void *)state
                                  objects:(id *)buffer
                                    count:(NSUInteger)len;
@end

#pragma mark - NSString

@interface NSString : NSObject <NSCopying, NSMutableCopying>
+ (instancetype)string;
+ (instancetype)stringWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);
+ (instancetype)stringWithUTF8String:(const char *)bytes;
+ (instancetype)stringWithContentsOfFile:(NSString *)path
                                encoding:(NSStringEncoding)enc
                                   error:(NSError **)error;
- (instancetype)initWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);
- (instancetype)initWithFormat:(NSString *)format arguments:(va_list)argList;
- (instancetype)initWithUTF8String:(const char *)bytes;
- (instancetype)initWithContentsOfFile:(NSString *)path
                              encoding:(NSStringEncoding)enc
                                 error:(NSError **)error;
@property (readonly) const char *UTF8String;
@property (readonly) const char *fileSystemRepresentation;
@property (readonly) NSUInteger length;
@property (readonly) NSInteger integerValue;
@property (readonly) int intValue;
@property (readonly) long long longLongValue;
@property (readonly) double doubleValue;
@property (readonly) float floatValue;
@property (readonly) BOOL boolValue;
@property (readonly) NSString *lastPathComponent;
@property (readonly) NSString *lowercaseString;
@property (readonly) NSString *uppercaseString;
@property (readonly) NSString *pathExtension;
@property (readonly) NSString *stringByDeletingLastPathComponent;
@property (readonly) NSString *stringByDeletingPathExtension;
@property (readonly) NSString *stringByStandardizingPath;
- (BOOL)hasPrefix:(NSString *)str;
- (BOOL)hasSuffix:(NSString *)str;
- (BOOL)containsString:(NSString *)str;
- (BOOL)isEqualToString:(NSString *)other;
- (NSString *)substringFromIndex:(NSUInteger)from;
- (NSString *)substringToIndex:(NSUInteger)to;
- (NSString *)substringWithRange:(NSRange)range;
- (NSString *)stringByAppendingPathComponent:(NSString *)str;
- (NSString *)stringByAppendingPathExtension:(NSString *)str;
- (NSString *)stringByAppendingString:(NSString *)str;
- (NSString *)stringByReplacingOccurrencesOfString:(NSString *)target
                                        withString:(NSString *)replacement;
- (NSString *)stringByTrimmingCharactersInSet:(NSCharacterSet *)set;
- (NSArray *)componentsSeparatedByString:(NSString *)separator;
- (NSRange)rangeOfString:(NSString *)searchString;
- (NSRange)rangeOfString:(NSString *)searchString options:(NSUInteger)mask;
- (unichar)characterAtIndex:(NSUInteger)index;
- (NSData *)dataUsingEncoding:(NSStringEncoding)encoding;
- (BOOL)writeToFile:(NSString *)path
         atomically:(BOOL)useAuxiliaryFile
           encoding:(NSStringEncoding)enc
              error:(NSError **)error;
- (NSComparisonResult)caseInsensitiveCompare:(NSString *)string;
- (NSComparisonResult)compare:(NSString *)string;
- (BOOL)getCString:(char *)buffer maxLength:(NSUInteger)maxBufferCount
          encoding:(NSStringEncoding)encoding;
@end


@interface NSMutableString : NSString
+ (instancetype)stringWithCapacity:(NSUInteger)capacity;
- (void)appendString:(NSString *)aString;
- (void)appendFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);
- (void)setString:(NSString *)aString;
- (void)insertString:(NSString *)aString atIndex:(NSUInteger)loc;
@end

#pragma mark - Collections

@interface NSArray<__covariant ObjectType> : NSObject <NSCopying, NSMutableCopying, NSFastEnumeration>
+ (instancetype)array;
+ (instancetype)arrayWithObject:(ObjectType)anObject;
+ (instancetype)arrayWithObjects:(const ObjectType [])objects count:(NSUInteger)cnt;
+ (instancetype)arrayWithArray:(NSArray<ObjectType> *)array;
- (NSUInteger)count;
- (ObjectType)objectAtIndex:(NSUInteger)index;
- (ObjectType)objectAtIndexedSubscript:(NSUInteger)idx;
- (ObjectType)firstObject;
- (ObjectType)lastObject;
- (BOOL)containsObject:(ObjectType)anObject;
- (NSUInteger)indexOfObject:(ObjectType)anObject;
- (NSArray<ObjectType> *)arrayByAddingObject:(ObjectType)anObject;
- (NSString *)componentsJoinedByString:(NSString *)separator;
- (NSArray<ObjectType> *)sortedArrayUsingComparator:(NSComparisonResult (^)(ObjectType, ObjectType))cmptr;
- (void)enumerateObjectsUsingBlock:(void (^)(ObjectType obj, NSUInteger idx, BOOL *stop))block;
@end

@interface NSMutableArray<ObjectType> : NSArray<ObjectType>
+ (instancetype)arrayWithCapacity:(NSUInteger)numItems;
- (void)addObject:(ObjectType)anObject;
- (void)addObjectsFromArray:(NSArray<ObjectType> *)otherArray;
- (void)removeObject:(ObjectType)anObject;
- (void)removeObjectAtIndex:(NSUInteger)index;
- (void)removeAllObjects;
- (void)insertObject:(ObjectType)anObject atIndex:(NSUInteger)index;
- (void)setObject:(ObjectType)obj atIndexedSubscript:(NSUInteger)idx;
@end

@interface NSDictionary<__covariant KeyType, __covariant ObjectType> : NSObject <NSCopying, NSMutableCopying, NSFastEnumeration>
+ (instancetype)dictionary;
+ (instancetype)dictionaryWithObject:(ObjectType)object forKey:(KeyType)key;
+ (instancetype)dictionaryWithObjects:(const ObjectType [])objects
                              forKeys:(const KeyType [])keys
                                count:(NSUInteger)cnt;
+ (instancetype)dictionaryWithDictionary:(NSDictionary *)dict;
- (NSUInteger)count;
- (ObjectType)objectForKey:(KeyType)aKey;
- (ObjectType)objectForKeyedSubscript:(KeyType)key;
- (NSArray<KeyType> *)allKeys;
- (NSArray *)allValues;
- (NSArray<KeyType> *)allKeysForObject:(ObjectType)anObject;
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)flag;
+ (instancetype)dictionaryWithContentsOfFile:(NSString *)path;
- (void)enumerateKeysAndObjectsUsingBlock:(void (^)(KeyType key, ObjectType obj, BOOL *stop))block;
@end

@interface NSMutableDictionary<KeyType, ObjectType> : NSDictionary<KeyType, ObjectType>
+ (instancetype)dictionaryWithCapacity:(NSUInteger)numItems;
- (void)setObject:(ObjectType)anObject forKey:(KeyType)aKey;
- (void)setObject:(ObjectType)obj forKeyedSubscript:(KeyType)key;
- (void)removeObjectForKey:(KeyType)aKey;
- (void)removeAllObjects;
- (void)addEntriesFromDictionary:(NSDictionary<KeyType, ObjectType> *)otherDictionary;
- (void)setDictionary:(NSDictionary<KeyType, ObjectType> *)otherDictionary;
@end

@interface NSSet<__covariant ObjectType> : NSObject <NSCopying, NSFastEnumeration>
- (NSUInteger)count;
- (BOOL)containsObject:(ObjectType)anObject;
@end

@interface NSNumber : NSObject <NSCopying>
+ (NSNumber *)numberWithBool:(BOOL)value;
+ (NSNumber *)numberWithChar:(char)value;
+ (NSNumber *)numberWithInt:(int)value;
+ (NSNumber *)numberWithUnsignedInt:(unsigned int)value;
+ (NSNumber *)numberWithLong:(long)value;
+ (NSNumber *)numberWithLongLong:(long long)value;
+ (NSNumber *)numberWithUnsignedLongLong:(unsigned long long)value;
+ (NSNumber *)numberWithInteger:(NSInteger)value;
+ (NSNumber *)numberWithUnsignedInteger:(NSUInteger)value;
+ (NSNumber *)numberWithFloat:(float)value;
+ (NSNumber *)numberWithDouble:(double)value;
@property (readonly) const char *objCType;
@property (readonly) BOOL boolValue;
@property (readonly) char charValue;
@property (readonly) int intValue;
@property (readonly) NSInteger integerValue;
@property (readonly) unsigned long long unsignedLongLongValue;
@property (readonly) long long longLongValue;
@property (readonly) float floatValue;
@property (readonly) double doubleValue;
@end

@interface NSData : NSObject <NSCopying, NSMutableCopying>
+ (instancetype)data;
+ (instancetype)dataWithBytes:(const void *)bytes length:(NSUInteger)length;
+ (instancetype)dataWithContentsOfFile:(NSString *)path;
+ (instancetype)dataWithData:(NSData *)data;
- (instancetype)initWithBytes:(const void *)bytes length:(NSUInteger)length;
@property (readonly) NSUInteger length;
@property (readonly) const void *bytes;
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile;
@end

@interface NSMutableData : NSData
+ (instancetype)dataWithCapacity:(NSUInteger)aNumItems;
- (void)appendBytes:(const void *)bytes length:(NSUInteger)length;
- (void)appendData:(NSData *)other;
@end

@interface NSCharacterSet : NSObject <NSCopying>
+ (NSCharacterSet *)whitespaceAndNewlineCharacterSet;
+ (NSCharacterSet *)whitespaceCharacterSet;
+ (NSCharacterSet *)newlineCharacterSet;
@end

#pragma mark - Errors and exceptions

@interface NSError : NSObject <NSCopying>
+ (instancetype)errorWithDomain:(NSString *)domain code:(NSInteger)code userInfo:(NSDictionary *)dict;
@property (readonly, copy) NSString *domain;
@property (readonly) NSInteger code;
@property (readonly, copy) NSDictionary *userInfo;
@property (readonly, copy) NSString *localizedDescription;
@property (readonly, copy) NSString *localizedFailureReason;
@end

@interface NSException : NSObject
+ (NSException *)exceptionWithName:(NSString *)name
                            reason:(NSString *)reason
                          userInfo:(NSDictionary *)userInfo;
- (instancetype)initWithName:(NSString *)name
                      reason:(NSString *)reason
                    userInfo:(NSDictionary *)userInfo;
- (void)raise;
+ (void)raise:(NSString *)name format:(NSString *)format, ... NS_FORMAT_FUNCTION(2, 3);
@property (readonly, copy) NSString *name;
@property (readonly, copy) NSString *reason;
@property (readonly, copy) NSDictionary *userInfo;
@property (readonly, copy) NSArray<NSString *> *callStackSymbols;
@property (readonly, copy) NSArray<NSNumber *> *callStackReturnAddresses;
@end

typedef void (*NSUncaughtExceptionHandler)(NSException *exception);
FOUNDATION_EXPORT void NSSetUncaughtExceptionHandler(NSUncaughtExceptionHandler handler);
FOUNDATION_EXPORT NSUncaughtExceptionHandler *NSGetUncaughtExceptionHandler(void);

#pragma mark - Files and bundles

@interface NSURL : NSObject <NSCopying>
+ (instancetype)fileURLWithPath:(NSString *)path;
+ (instancetype)fileURLWithPath:(NSString *)path isDirectory:(BOOL)isDir;
+ (instancetype)URLWithString:(NSString *)URLString;
@property (readonly, copy) NSString *absoluteString;
@property (readonly, copy) NSString *path;
@property (readonly, copy) NSString *lastPathComponent;
@property (readonly) BOOL isFileURL;
- (NSURL *)URLByAppendingPathComponent:(NSString *)pathComponent;
- (NSURL *)URLByAppendingPathComponent:(NSString *)pathComponent isDirectory:(BOOL)isDirectory;
- (NSURL *)URLByDeletingLastPathComponent;
@property (readonly, copy) NSURL *standardizedURL;
@end

@interface NSFileManager : NSObject
+ (NSFileManager *)defaultManager;
- (BOOL)fileExistsAtPath:(NSString *)path;
- (BOOL)isWritableFileAtPath:(NSString *)path;
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory;
- (BOOL)createDirectoryAtPath:(NSString *)path
  withIntermediateDirectories:(BOOL)createIntermediates
                   attributes:(NSDictionary *)attributes
                        error:(NSError **)error;
- (BOOL)createDirectoryAtURL:(NSURL *)url
 withIntermediateDirectories:(BOOL)createIntermediates
                  attributes:(NSDictionary *)attributes
                       error:(NSError **)error;
- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error;
- (BOOL)removeItemAtPath:(NSString *)path error:(NSError **)error;
- (BOOL)removeItemAtURL:(NSURL *)URL error:(NSError **)error;
- (NSArray<NSURL *> *)URLsForDirectory:(NSSearchPathDirectory)directory
                             inDomains:(NSSearchPathDomainMask)domainMask;
- (NSURL *)containerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier;
- (NSURL *)URLForUbiquityContainerIdentifier:(NSString *)containerIdentifier;
- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError **)error;
@property (readonly, copy) NSURL *temporaryDirectory;
@end

@interface NSBundle : NSObject
+ (NSBundle *)mainBundle;
+ (NSBundle *)bundleForClass:(Class)aClass;
+ (NSBundle *)bundleWithPath:(NSString *)path;
- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext;
- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)ext inDirectory:(NSString *)subpath;
- (id)objectForInfoDictionaryKey:(NSString *)key;
@property (readonly, copy) NSString *bundlePath;
@property (readonly, copy) NSString *bundleIdentifier;
@property (readonly, copy) NSString *executablePath;
@property (readonly, copy) NSURL *bundleURL;
@property (readonly, copy) NSURL *appStoreReceiptURL;
@end

@interface NSUserDefaults : NSObject
+ (NSUserDefaults *)standardUserDefaults;
- (instancetype)initWithSuiteName:(NSString *)suitename;
- (id)objectForKey:(NSString *)defaultName;
- (BOOL)boolForKey:(NSString *)defaultName;
- (NSInteger)integerForKey:(NSString *)defaultName;
- (double)doubleForKey:(NSString *)defaultName;
- (float)floatForKey:(NSString *)defaultName;
- (NSString *)stringForKey:(NSString *)defaultName;
- (NSArray *)arrayForKey:(NSString *)defaultName;
- (NSDictionary *)dictionaryForKey:(NSString *)defaultName;
- (NSData *)dataForKey:(NSString *)defaultName;
- (NSURL *)URLForKey:(NSString *)defaultName;
- (void)setObject:(id)value forKey:(NSString *)defaultName;
- (void)setBool:(BOOL)value forKey:(NSString *)defaultName;
- (void)setInteger:(NSInteger)value forKey:(NSString *)defaultName;
- (void)removeObjectForKey:(NSString *)defaultName;
- (NSDictionary *)dictionaryRepresentation;
- (BOOL)synchronize;
- (void)registerDefaults:(NSDictionary *)registrationDictionary;
@end

#pragma mark - Serialisation / scanning

@interface NSPropertyListSerialization : NSObject
+ (id)propertyListWithData:(NSData *)data
                   options:(NSUInteger)opt
                    format:(NSUInteger *)format
                     error:(NSError **)error;
+ (NSData *)dataWithPropertyList:(id)plist
                          format:(NSUInteger)format
                         options:(NSUInteger)opt
                           error:(NSError **)error;
+ (BOOL)propertyList:(id)plist isValidForFormat:(NSUInteger)format;
@end

@interface NSJSONSerialization : NSObject
+ (id)JSONObjectWithData:(NSData *)data options:(NSUInteger)opt error:(NSError **)error;
+ (NSData *)dataWithJSONObject:(id)obj options:(NSUInteger)opt error:(NSError **)error;
@end

@interface NSScanner : NSObject
+ (instancetype)scannerWithString:(NSString *)string;
@property (readonly) BOOL isAtEnd;
- (BOOL)scanHexLongLong:(unsigned long long *)result;
- (BOOL)scanHexInt:(unsigned int *)result;
- (BOOL)scanInteger:(NSInteger *)result;
- (BOOL)scanString:(NSString *)string intoString:(NSString **)result;
- (void)setScanLocation:(NSUInteger)location;
- (NSUInteger)scanLocation;
@property BOOL caseSensitive;
@end

#pragma mark - Notifications, queues, threading

@interface NSNotification : NSObject
@property (readonly, copy) NSString *name;
@property (readonly, retain) id object;
@property (readonly, copy) NSDictionary *userInfo;
@end

@interface NSNotificationCenter : NSObject
+ (NSNotificationCenter *)defaultCenter;
- (void)addObserver:(id)observer selector:(SEL)aSelector
               name:(NSString *)aName object:(id)anObject;
- (id)addObserverForName:(NSString *)name
                  object:(id)obj
                   queue:(NSOperationQueue *)queue
              usingBlock:(void (^)(NSNotification *note))block;
- (void)removeObserver:(id)observer;
- (void)postNotificationName:(NSString *)aName object:(id)anObject;
- (void)postNotificationName:(NSString *)aName object:(id)anObject userInfo:(NSDictionary *)aUserInfo;
@end

@interface NSOperationQueue : NSObject
+ (NSOperationQueue *)mainQueue;
+ (NSOperationQueue *)currentQueue;
- (void)addOperationWithBlock:(void (^)(void))block;
@property NSInteger maxConcurrentOperationCount;
@end

@interface NSThread : NSObject
+ (NSThread *)mainThread;
/// Real SDK: +callStackSymbols (class) and -callStackSymbols (instance) both
/// exist. The class form had been missing here, which the sources then used.
+ (NSArray<NSString *> *)callStackSymbols;
+ (NSThread *)currentThread;
+ (BOOL)isMainThread;
+ (void)sleepForTimeInterval:(NSTimeInterval)ti;
@property (readonly) BOOL isMainThread;
@property (readonly, copy) NSArray<NSString *> *callStackSymbols;
@end

@interface NSRunLoop : NSObject
+ (NSRunLoop *)mainRunLoop;
+ (NSRunLoop *)currentRunLoop;
@end

@interface NSProcessInfo : NSObject
+ (NSProcessInfo *)processInfo;
@property (readonly) int processIdentifier;
@property (readonly, copy) NSString *processName;
@property (readonly) unsigned long long physicalMemory;
@end

@interface NSValue : NSObject <NSCopying>
+ (NSValue *)valueWithPointer:(const void *)pointer;
- (void *)pointerValue;
@end

@interface NSDate : NSObject <NSCopying>
+ (instancetype)date;
+ (NSTimeInterval)timeIntervalSinceReferenceDate;
@property (readonly) NSTimeInterval timeIntervalSince1970;
@end

@interface NSLock : NSObject
- (void)lock;
- (void)unlock;
- (BOOL)tryLock;
@end

#pragma mark - URL loading

@interface NSURLRequest : NSObject <NSCopying, NSMutableCopying>
+ (instancetype)requestWithURL:(NSURL *)URL;
+ (instancetype)requestWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeout;
@property (readonly, copy) NSURL *URL;
@property (readonly, copy) NSString *HTTPMethod;
- (NSString *)valueForHTTPHeaderField:(NSString *)field;
- (id)copyWithZone:(void *)zone;
@end

@interface NSMutableURLRequest : NSURLRequest
- (void)setURL:(NSURL *)URL;
- (void)setHTTPMethod:(NSString *)method;
- (void)setValue:(NSString *)value forHTTPHeaderField:(NSString *)field;
- (void)setCachePolicy:(NSURLRequestCachePolicy)policy;
@end

@interface NSURLResponse : NSObject <NSCopying>
- (instancetype)initWithURL:(NSURL *)URL
                 MIMEType:(NSString *)MIMEType
    expectedContentLength:(NSInteger)length
         textEncodingName:(NSString *)name;
@property (readonly, copy) NSURL *URL;
@property (readonly, copy) NSString *MIMEType;
@property (readonly) long long expectedContentLength;
@end

@interface NSHTTPURLResponse : NSURLResponse
- (instancetype)initWithURL:(NSURL *)URL
                 statusCode:(NSInteger)statusCode
                HTTPVersion:(NSString *)HTTPVersion
               headerFields:(NSDictionary<NSString *, NSString *> *)headerFields;
@property (readonly) NSInteger statusCode;
@property (readonly, copy) NSDictionary *allHeaderFields;
@end

@protocol NSURLProtocolClient <NSObject>
- (void)URLProtocol:(NSURLProtocol *)protocol didReceiveResponse:(NSURLResponse *)response cacheStoragePolicy:(NSURLRequestCachePolicy)policy;
- (void)URLProtocol:(NSURLProtocol *)protocol didLoadData:(NSData *)data;
- (void)URLProtocolDidFinishLoading:(NSURLProtocol *)protocol;
- (void)URLProtocol:(NSURLProtocol *)protocol didFailWithError:(NSError *)error;
- (void)URLProtocol:(NSURLProtocol *)protocol wasRedirectedToRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse;
- (void)URLProtocol:(NSURLProtocol *)protocol didReceiveAuthenticationChallenge:(id)challenge;
@end

@interface NSURLProtocol : NSObject
+ (BOOL)canInitWithRequest:(NSURLRequest *)request;
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request;
+ (BOOL)registerClass:(Class)protocolClass;
+ (void)unregisterClass:(Class)protocolClass;
+ (id)propertyForKey:(NSString *)key inRequest:(NSURLRequest *)request;
+ (void)setProperty:(id)value forKey:(NSString *)key inRequest:(NSMutableURLRequest *)request;
+ (void)removePropertyForKey:(NSString *)key inRequest:(NSMutableURLRequest *)request;
- (instancetype)initWithRequest:(NSURLRequest *)request
                 cachedResponse:(id)cachedResponse
                         client:(id<NSURLProtocolClient>)client;
@property (readonly, copy) NSURLRequest *request;
@property (readonly, retain) id<NSURLProtocolClient> client;
- (void)startLoading;
- (void)stopLoading;
@end

#pragma mark - NSMethodSignature / NSInvocation

// Both are public Foundation, and both are what -forwardInvocation: needs. The
// stub SDK had neither until v20 needed them: the CloudKit substitute answers
// selectors it has never heard of, and the only correct way to give back a
// return value of a width you do not know is the invocation's own signature.

@interface NSMethodSignature : NSObject
+ (NSMethodSignature *)signatureWithObjCTypes:(const char *)types;
- (NSUInteger)numberOfArguments;
- (const char *)methodReturnType;
- (NSUInteger)methodReturnLength;
- (const char *)getArgumentTypeAtIndex:(NSUInteger)index;
@end

@interface NSInvocation : NSObject
+ (NSInvocation *)invocationWithMethodSignature:(NSMethodSignature *)signature;
- (NSMethodSignature *)methodSignature;
- (SEL)selector;
- (void)setTarget:(id)target;
- (void)setSelector:(SEL)selector;
- (void)getReturnValue:(void *)buffer;
- (void)setReturnValue:(void *)buffer;
- (void)invoke;
@end

#pragma mark - C functions

FOUNDATION_EXPORT NSString *NSTemporaryDirectory(void);
FOUNDATION_EXPORT NSString *NSHomeDirectory(void);
FOUNDATION_EXPORT NSArray<NSString *> *NSSearchPathForDirectoriesInDomains(NSSearchPathDirectory directory,
                                                                          NSSearchPathDomainMask domainMask,
                                                                          BOOL expandTilde);
FOUNDATION_EXPORT Class NSClassFromString(NSString *aClassName);
FOUNDATION_EXPORT NSString *NSStringFromClass(Class aClass);
FOUNDATION_EXPORT SEL NSSelectorFromString(NSString *aSelectorName);
FOUNDATION_EXPORT NSString *NSStringFromSelector(SEL aSelector);
FOUNDATION_EXPORT void NSLog(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);
FOUNDATION_EXPORT void NSLogv(NSString *format, va_list args);
FOUNDATION_EXPORT NSString *NSUserName(void);
FOUNDATION_EXPORT BOOL NSClassFromStringExists(NSString *name);
