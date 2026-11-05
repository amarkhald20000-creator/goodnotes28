//
//  GNHooks.m
//  Data-only behaviour hooks.
//
//  Everything in this file changes what the app *observes* (a preference value,
//  an identifier, an HTTP response) and never what the CPU *executes*. That is
//  the whole point: on a Distribution signed build these are the only levers
//  that cannot get the process killed.
//
//  Three hooks, all config driven and individually switchable:
//
//    Defaults   interposes -[NSUserDefaults objectForKey:] and friends, so a
//               key returns our value even after the app writes its own.
//               This is how the mock entitlement flags get injected.
//
//    SYD        SyncedDefaults decides which iCloud key-value store this
//               process belongs to from its application identifier. After a
//               re-sign that identifier is not what the app expects, which is
//               what the old anchor was trying to patch inside
//               SecTaskCreateFromSelf. Overriding it here is one ObjC message,
//               no code page involved.
//
//    URLForge   a registered NSURLProtocol, i.e. the documented Apple way to
//               serve a response without a network. Used to hand the app an
//               entitlement document it accepts.
//

#import "GNUnlock.h"

#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <string.h>

#pragma mark - 1. NSUserDefaults overrides

static NSDictionary *gDefaultsOverrides = nil;
static BOOL gDefaultsHooked = NO;

static id   (*gOrigObjectForKey)(id, SEL, NSString *);
static BOOL (*gOrigBoolForKey)(id, SEL, NSString *);
static long (*gOrigIntegerForKey)(id, SEL, NSString *);
static double (*gOrigDoubleForKey)(id, SEL, NSString *);
static float (*gOrigFloatForKey)(id, SEL, NSString *);
static id   (*gOrigStringForKey)(id, SEL, NSString *);
static id   (*gOrigArrayForKey)(id, SEL, NSString *);
static id   (*gOrigDictionaryForKey)(id, SEL, NSString *);
static id   (*gOrigDataForKey)(id, SEL, NSString *);
static id   (*gOrigURLForKey)(id, SEL, NSString *);

static id GNOverrideFor(NSString *key) {
    if (!gDefaultsOverrides || ![key isKindOfClass:[NSString class]]) return nil;
    return gDefaultsOverrides[key];
}

static id GNReplacementObjectForKey(id self, SEL _cmd, NSString *key) {
    id override = GNOverrideFor(key);
    if (override) return override;
    return gOrigObjectForKey ? gOrigObjectForKey(self, _cmd, key) : nil;
}

static BOOL GNReplacementBoolForKey(id self, SEL _cmd, NSString *key) {
    id override = GNOverrideFor(key);
    if (override) return [override respondsToSelector:@selector(boolValue)] ? [override boolValue] : NO;
    return gOrigBoolForKey ? gOrigBoolForKey(self, _cmd, key) : NO;
}

static long GNReplacementIntegerForKey(id self, SEL _cmd, NSString *key) {
    id override = GNOverrideFor(key);
    if (override) return [override respondsToSelector:@selector(integerValue)] ? [override integerValue] : 0;
    return gOrigIntegerForKey ? gOrigIntegerForKey(self, _cmd, key) : 0;
}

static double GNReplacementDoubleForKey(id self, SEL _cmd, NSString *key) {
    id override = GNOverrideFor(key);
    if (override) return [override respondsToSelector:@selector(doubleValue)] ? [override doubleValue] : 0;
    return gOrigDoubleForKey ? gOrigDoubleForKey(self, _cmd, key) : 0;
}

static float GNReplacementFloatForKey(id self, SEL _cmd, NSString *key) {
    id override = GNOverrideFor(key);
    if (override) return [override respondsToSelector:@selector(floatValue)] ? [override floatValue] : 0;
    return gOrigFloatForKey ? gOrigFloatForKey(self, _cmd, key) : 0;
}

static id GNReplacementStringForKey(id self, SEL _cmd, NSString *key) {
    id override = GNOverrideFor(key);
    if (override) return [override isKindOfClass:[NSString class]] ? override : nil;
    return gOrigStringForKey ? gOrigStringForKey(self, _cmd, key) : nil;
}

static id GNReplacementArrayForKey(id self, SEL _cmd, NSString *key) {
    id override = GNOverrideFor(key);
    if (override) return [override isKindOfClass:[NSArray class]] ? override : nil;
    return gOrigArrayForKey ? gOrigArrayForKey(self, _cmd, key) : nil;
}

static id GNReplacementDictionaryForKey(id self, SEL _cmd, NSString *key) {
    id override = GNOverrideFor(key);
    if (override) return [override isKindOfClass:[NSDictionary class]] ? override : nil;
    return gOrigDictionaryForKey ? gOrigDictionaryForKey(self, _cmd, key) : nil;
}

static id GNReplacementDataForKey(id self, SEL _cmd, NSString *key) {
    id override = GNOverrideFor(key);
    if (override) return [override isKindOfClass:[NSData class]] ? override : nil;
    return gOrigDataForKey ? gOrigDataForKey(self, _cmd, key) : nil;
}

static id GNReplacementURLForKey(id self, SEL _cmd, NSString *key) {
    id override = GNOverrideFor(key);
    if (override) {
        if ([override isKindOfClass:[NSURL class]]) return override;
        if ([override isKindOfClass:[NSString class]]) return [NSURL URLWithString:override];
        return nil;
    }
    return gOrigURLForKey ? gOrigURLForKey(self, _cmd, key) : nil;
}

static void GNInstallDefaultsHook(NSDictionary *config) {
    if (gDefaultsHooked) return;

    id enabled = config[@"Enabled"];
    if (enabled && ![enabled boolValue]) {
        GNLogC("hooks/defaults: disabled by config");
        return;
    }

    NSArray *entries = config[@"Overrides"];
    if (![entries isKindOfClass:[NSArray class]] || entries.count == 0) {
        GNLogC("hooks/defaults: no overrides configured");
        return;
    }

    NSMutableDictionary *map = [NSMutableDictionary dictionary];
    for (id entry in entries) {
        if (![entry isKindOfClass:[NSDictionary class]]) continue;
        NSString *key = entry[@"Key"];
        id value = entry[@"Value"];
        if (![key isKindOfClass:[NSString class]] || key.length == 0 || !value) continue;
        map[key] = value;
        GNLogC("hooks/defaults: %s <- %s", key.UTF8String,
               [[value description] UTF8String] ?: "?");
    }
    if (map.count == 0) return;

    gDefaultsOverrides = [map copy];

    Class defaults = [NSUserDefaults class];
    GNHookInstance(defaults, "objectForKey:", (IMP)GNReplacementObjectForKey, (IMP *)&gOrigObjectForKey);
    GNHookInstance(defaults, "boolForKey:", (IMP)GNReplacementBoolForKey, (IMP *)&gOrigBoolForKey);
    GNHookInstance(defaults, "integerForKey:", (IMP)GNReplacementIntegerForKey, (IMP *)&gOrigIntegerForKey);
    GNHookInstance(defaults, "doubleForKey:", (IMP)GNReplacementDoubleForKey, (IMP *)&gOrigDoubleForKey);
    GNHookInstance(defaults, "floatForKey:", (IMP)GNReplacementFloatForKey, (IMP *)&gOrigFloatForKey);
    GNHookInstance(defaults, "stringForKey:", (IMP)GNReplacementStringForKey, (IMP *)&gOrigStringForKey);
    GNHookInstance(defaults, "arrayForKey:", (IMP)GNReplacementArrayForKey, (IMP *)&gOrigArrayForKey);
    GNHookInstance(defaults, "dictionaryForKey:", (IMP)GNReplacementDictionaryForKey, (IMP *)&gOrigDictionaryForKey);
    GNHookInstance(defaults, "dataForKey:", (IMP)GNReplacementDataForKey, (IMP *)&gOrigDataForKey);
    GNHookInstance(defaults, "URLForKey:", (IMP)GNReplacementURLForKey, (IMP *)&gOrigURLForKey);

    gDefaultsHooked = YES;
    GNLogC("hooks/defaults: %lu key(s) intercepted", (unsigned long)map.count);
}

#pragma mark - 2. SyncedDefaults identifier

static NSString *gSYDOverride = nil;
static NSString *(*gOrigSYDIdentifier)(Class, SEL, NSString *);

static NSString *GNReplacementSYDIdentifier(Class cls, SEL _cmd, NSString *applicationIdentifier) {
    NSString *original = gOrigSYDIdentifier ? gOrigSYDIdentifier(cls, _cmd, applicationIdentifier) : nil;
    if (gSYDOverride.length) {
        GNLogC("hooks/syd: %s -> %s (app id %s)",
               (original ?: @"(nil)").UTF8String, gSYDOverride.UTF8String,
               (applicationIdentifier ?: @"(nil)").UTF8String);
        return gSYDOverride;
    }
    return original;
}

static void GNInstallSYDHook(NSDictionary *config) {
    id enabled = config[@"Enabled"];
    if (!enabled || ![enabled boolValue]) {
        GNLogC("hooks/syd: disabled by config");
        return;
    }

    Class cls = objc_getClass("SYDClientToDaemonConnection");
    if (!cls) {
        // The framework lazily maps its classes; nudge it before giving up.
        dlopen("/System/Library/PrivateFrameworks/SyncedDefaults.framework/SyncedDefaults",
               RTLD_NOW | RTLD_GLOBAL);
        cls = objc_getClass("SYDClientToDaemonConnection");
    }
    if (!cls) {
        GNLogC("hooks/syd: SYDClientToDaemonConnection not present - skipped");
        return;
    }

    SEL selector = NSSelectorFromString(@"defaultStoreIdentifierForCurrentProcessWithApplicationIdentifier:");
    Method method = class_getClassMethod(cls, selector);
    if (!method) {
        GNLogC("hooks/syd: selector missing on %s - skipped", class_getName(cls));
        return;
    }

    NSString *configured = config[@"Override"];
    if ([configured isKindOfClass:[NSString class]] && configured.length) {
        gSYDOverride = [configured copy];
    }

    gOrigSYDIdentifier = (void *)method_getImplementation(method);

    // class_replaceMethod on the metaclass, not the class: patching an inherited
    // method through the class would change the superclass for the whole process.
    Class meta = object_getClass(cls);
    if (!class_replaceMethod(meta, selector, (IMP)GNReplacementSYDIdentifier,
                             method_getTypeEncoding(method))) {
        method_setImplementation(method, (IMP)GNReplacementSYDIdentifier);
    }

    GNLogC("hooks/syd: installed (override=%s)",
           gSYDOverride.length ? gSYDOverride.UTF8String : "(pass through)");
}

#pragma mark - 3. Forged HTTP responses

static NSArray *gForgeRules = nil;

@interface GNForgeProtocol : NSURLProtocol
@end

@implementation GNForgeProtocol

+ (NSDictionary *)gn_ruleForRequest:(NSURLRequest *)request {
    if (!gForgeRules) return nil;

    NSString *url = request.URL.absoluteString;
    NSString *method = request.HTTPMethod;
    if (!url) return nil;

    for (NSDictionary *rule in gForgeRules) {
        if (![rule isKindOfClass:[NSDictionary class]]) continue;

        NSString *match = rule[@"Match"];
        if (![match isKindOfClass:[NSString class]] || match.length == 0) continue;
        if ([url rangeOfString:match options:NSCaseInsensitiveSearch].location == NSNotFound) continue;

        NSString *wantedMethod = rule[@"Method"];
        if ([wantedMethod isKindOfClass:[NSString class]] && wantedMethod.length) {
            NSString *actualMethod = method ?: @"GET";
            if ([wantedMethod caseInsensitiveCompare:actualMethod] != NSOrderedSame) continue;
        }
        return rule;
    }
    return nil;
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if (!gForgeRules) return NO;
    // Never intercept our own forged responses twice.
    if ([request valueForHTTPHeaderField:@"X-GNUnlock-Forge"] != nil) return NO;
    return [self gn_ruleForRequest:request] != nil;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSDictionary *rule = [[self class] gn_ruleForRequest:self.request];
    if (!rule) {
        [self.client URLProtocol:self didFailWithError:
            [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCancelled userInfo:nil]];
        return;
    }

    NSString *body = rule[@"Body"];
    if (![body isKindOfClass:[NSString class]]) body = @"{}";

    NSInteger status = 200;
    id statusValue = rule[@"Status"];
    if ([statusValue respondsToSelector:@selector(integerValue)]) status = [statusValue integerValue];

    NSString *contentType = rule[@"ContentType"];
    if (![contentType isKindOfClass:[NSString class]] || contentType.length == 0) {
        contentType = @"application/json";
    }

    NSData *payload = [body dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *headers = @{ @"Content-Type": contentType,
                               @"Content-Length": [NSString stringWithFormat:@"%lu",
                                                   (unsigned long)payload.length] };

    NSHTTPURLResponse *response =
        [[NSHTTPURLResponse alloc] initWithURL:self.request.URL
                                    statusCode:status
                                   HTTPVersion:@"HTTP/1.1"
                                  headerFields:headers];

    GNLogC("hooks/url: forged %ld for %s (%lu bytes)", (long)status,
           self.request.URL.absoluteString.UTF8String ?: "?",
           (unsigned long)payload.length);

    [self.client URLProtocol:self didReceiveResponse:response
          cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:payload];
    [self.client URLProtocolDidFinishLoading:self];
}

- (void)stopLoading {
}

@end

static void GNInstallURLForge(NSDictionary *config) {
    id enabled = config[@"Enabled"];
    if (!enabled || ![enabled boolValue]) {
        GNLogC("hooks/url: disabled by config");
        return;
    }

    NSArray *rules = config[@"Rules"];
    if (![rules isKindOfClass:[NSArray class]] || rules.count == 0) {
        GNLogC("hooks/url: no rules configured");
        return;
    }

    gForgeRules = [rules copy];
    [NSURLProtocol registerClass:[GNForgeProtocol class]];
    GNLogC("hooks/url: %lu rule(s) registered", (unsigned long)rules.count);
}

#pragma mark - Entry point

void GNInstallDataHooks(NSDictionary *cfg) {
    NSDictionary *hooks = cfg[@"Hooks"];
    if (![hooks isKindOfClass:[NSDictionary class]]) {
        GNLogC("hooks: no Hooks section in config");
        return;
    }

    id enabled = hooks[@"Enabled"];
    if (enabled && ![enabled boolValue]) {
        GNLogC("hooks: disabled by config");
        return;
    }

    @try {
        NSDictionary *defaults = hooks[@"Defaults"];
        if ([defaults isKindOfClass:[NSDictionary class]]) {
            GNInstallDefaultsHook(defaults);
        }

        NSDictionary *syd = hooks[@"SYDIdentifier"];
        if ([syd isKindOfClass:[NSDictionary class]]) {
            GNInstallSYDHook(syd);
        }

        NSDictionary *forge = hooks[@"URLForge"];
        if ([forge isKindOfClass:[NSDictionary class]]) {
            GNInstallURLForge(forge);
        }
    } @catch (NSException *exception) {
        GNLogC("hooks: exception %s: %s", exception.name.UTF8String ?: "?",
               exception.reason.UTF8String ?: "?");
    }
}
