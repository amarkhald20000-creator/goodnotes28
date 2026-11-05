//
//  GNResign.m
//  Re-sign compatibility layer.
//
//  A retail App Store binary that is re-signed with a third-party certificate
//  behaves differently in a handful of well understood places, and any one of
//  them is enough to make an app die during launch before the first frame:
//
//    1. Keychain  - every item is scoped to the original team's access group.
//                   With a different team the query fails with -34018
//                   (errSecMissingEntitlement), and apps that force-unwrap the
//                   result trap.
//    2. App Groups - containerURLForSecurityApplicationGroupIdentifier: returns
//                   nil, because the entitlement is gone. Force unwrap -> trap.
//    3. Signature  - the app asks the Security framework "am I still signed by
//                   me?", gets a mismatch, and refuses to start.
//    4. Receipt    - there is no App Store receipt any more, or it is invalid.
//    5. Entitlements - application-identifier / team-identifier queries return
//                   nil or somebody else's values.
//    6. UserDefaults suites - a suite backed by a missing app group comes back
//                   nil, and callers assume it cannot be nil.
//
//  Every fix below is individually switchable through the plist so a crash can
//  be bisected in one launch cycle.
//
//  How these are installed matters as much as what they do. All of the API in
//  question (SecItem*, SecStaticCode*, SecTask*) lives in the dyld shared cache,
//  i.e. inside a code signed image. Rewriting its first instruction - an inline
//  hook - makes the kernel copy the page and kills the process on the next
//  instruction fetch. That is the CODESIGNING / Invalid Page crash.
//
//  So every call here goes through GNInterposeSymbol(), which picks the safe
//  mechanism for the signature we are running under:
//
//      debug signed   -> classic inline hook (allowed, the page stays valid)
//      distribution   -> import slot rebinding, data pages only, or nothing
//
//  With a Distribution certificate the C level fixes are therefore skipped by
//  default (EnableGOTRebinding = false) and the ObjC level fixes - app groups,
//  UserDefaults suites, receipt URL - keep working, because those only touch
//  method lists.
//

#import "GNUnlock.h"

#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <string.h>

static const OSStatus kGNErrSecSuccess = 0;

#pragma mark - Config helpers

static NSDictionary *GNResignConfig(void) {
    NSDictionary *dict = GNCFGDict(@"ResignFix");
    return [dict isKindOfClass:[NSDictionary class]] ? dict : @{};
}

static BOOL GNResignOn(NSString *key, BOOL defaultValue) {
    id value = GNResignConfig()[key];
    return [value respondsToSelector:@selector(boolValue)] ? [value boolValue] : defaultValue;
}

static NSString *GNResignString(NSString *key) {
    id value = GNResignConfig()[key];
    return [value isKindOfClass:[NSString class]] ? value : nil;
}

static NSString *GNTargetBundleIdentifier(void) {
    NSString *forced = GNResignString(@"BundleID");
    if (forced.length) return forced;
    return [[NSBundle mainBundle] bundleIdentifier] ?: @"com.goodnotesapp.x";
}

static CFTypeRef GNRetainedCFValue(id value) {
    if (!value) return NULL;
    if ([value isKindOfClass:[NSNumber class]]) {
        NSNumber *number = (NSNumber *)value;
        const char *type = number.objCType;
        if (type && (strcmp(type, @encode(BOOL)) == 0 || strcmp(type, "c") == 0)) {
            return CFRetain(number.boolValue ? kCFBooleanTrue : kCFBooleanFalse);
        }
        return (CFTypeRef)CFBridgingRetain([number copy]);
    }
    if ([value isKindOfClass:[NSString class]]) {
        return (CFTypeRef)CFBridgingRetain([value copy]);
    }
    if ([value isKindOfClass:[NSArray class]]) {
        return (CFTypeRef)CFBridgingRetain([value copy]);
    }
    return NULL;
}

#pragma mark - 1. Keychain access group

static OSStatus (*gOrigSecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*gOrigSecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*gOrigSecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*gOrigSecItemDelete)(CFDictionaryRef);

static BOOL gKeychainHooked = NO;
static int  gKeychainLogBudget = 200;

static CFMutableDictionaryRef GNKeychainSanitized(CFDictionaryRef query, BOOL *changed) {
    if (!query) return NULL;
    CFMutableDictionaryRef copy = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, query);
    if (!copy) return NULL;

    BOOL didChange = NO;
    if (CFDictionaryContainsKey(copy, kSecAttrAccessGroup)) {
        CFDictionaryRemoveValue(copy, kSecAttrAccessGroup);
        didChange = YES;
    }
    if (changed) *changed = didChange;
    return copy;
}

static void GNLogKeychainCall(const char *op, CFDictionaryRef query, OSStatus status) {
    if (!GNResignOn(@"LogKeychainCalls", YES)) return;
    if (gKeychainLogBudget <= 0) return;
    gKeychainLogBudget--;

    NSString *keys = @"?";
    if (query) {
        NSArray *allKeys = [(__bridge NSDictionary *)query allKeys];
        keys = [allKeys componentsJoinedByString:@","];
    }
    GNLogC("keychain %s -> %d  keys=[%s]", op, (int)status, keys.UTF8String ?: "?");
}

static OSStatus GNReplacementSecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    BOOL changed = NO;
    CFMutableDictionaryRef sanitized = GNKeychainSanitized(query, &changed);
    OSStatus status = gOrigSecItemCopyMatching
        ? gOrigSecItemCopyMatching(sanitized ?: query, result)
        : errSecParam;
    if (sanitized) CFRelease(sanitized);

    if (status != kGNErrSecSuccess) GNLogKeychainCall("copy", query, status);
    return status;
}

static OSStatus GNReplacementSecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    BOOL changed = NO;
    CFMutableDictionaryRef sanitized = GNKeychainSanitized(attributes, &changed);
    OSStatus status = gOrigSecItemAdd
        ? gOrigSecItemAdd(sanitized ?: attributes, result)
        : errSecParam;
    if (sanitized) CFRelease(sanitized);
    if (status != kGNErrSecSuccess) GNLogKeychainCall("add", attributes, status);
    return status;
}

static OSStatus GNReplacementSecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributes) {
    BOOL changed = NO;
    CFMutableDictionaryRef cleanQuery = GNKeychainSanitized(query, &changed);
    CFMutableDictionaryRef cleanAttributes = GNKeychainSanitized(attributes, &changed);
    OSStatus status = gOrigSecItemUpdate
        ? gOrigSecItemUpdate(cleanQuery ?: query, cleanAttributes ?: attributes)
        : errSecParam;
    if (cleanQuery) CFRelease(cleanQuery);
    if (cleanAttributes) CFRelease(cleanAttributes);
    if (status != kGNErrSecSuccess) GNLogKeychainCall("update", query, status);
    return status;
}

static OSStatus GNReplacementSecItemDelete(CFDictionaryRef query) {
    BOOL changed = NO;
    CFMutableDictionaryRef sanitized = GNKeychainSanitized(query, &changed);
    OSStatus status = gOrigSecItemDelete ? gOrigSecItemDelete(sanitized ?: query) : errSecParam;
    if (sanitized) CFRelease(sanitized);
    if (status != kGNErrSecSuccess) GNLogKeychainCall("delete", query, status);
    return status;
}

static void GNInstallKeychainFix(void) {
    if (!GNResignOn(@"StripKeychainAccessGroup", YES)) {
        GNLogC("resign: keychain fix disabled by config");
        return;
    }

    gOrigSecItemCopyMatching = (__typeof__(gOrigSecItemCopyMatching))dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
    gOrigSecItemAdd          = (__typeof__(gOrigSecItemAdd))dlsym(RTLD_DEFAULT, "SecItemAdd");
    gOrigSecItemUpdate       = (__typeof__(gOrigSecItemUpdate))dlsym(RTLD_DEFAULT, "SecItemUpdate");
    gOrigSecItemDelete       = (__typeof__(gOrigSecItemDelete))dlsym(RTLD_DEFAULT, "SecItemDelete");

    if (!gOrigSecItemCopyMatching || !gOrigSecItemAdd) {
        GNLogC("resign: keychain symbols not resolvable - skipped");
        return;
    }

    BOOL ok = YES;
    ok &= GNInterposeSymbol("SecItemCopyMatching", (void *)GNReplacementSecItemCopyMatching,
                             (void **)&gOrigSecItemCopyMatching);
    ok &= GNInterposeSymbol("SecItemAdd", (void *)GNReplacementSecItemAdd,
                             (void **)&gOrigSecItemAdd);
    ok &= GNInterposeSymbol("SecItemUpdate", (void *)GNReplacementSecItemUpdate,
                             (void **)&gOrigSecItemUpdate);
    ok &= GNInterposeSymbol("SecItemDelete", (void *)GNReplacementSecItemDelete,
                             (void **)&gOrigSecItemDelete);
    gKeychainHooked = ok;
    GNLogC("resign: keychain access-group stripping %s", ok ? "installed" : "PARTIAL");
}

#pragma mark - 2. App group / ubiquity / suite fallbacks

static NSURL *(*gOrigContainerURL)(id, SEL, NSString *);
static NSURL *(*gOrigUbiquityURL)(id, SEL, NSString *);
static NSURL *(*gOrigReceiptURL)(id, SEL);

static NSURL *GNFallbackDirectory(NSString *component) {
    NSString *path = [GNDocumentsPath() stringByAppendingPathComponent:component];
    NSURL *url = [NSURL fileURLWithPath:path isDirectory:YES];
    NSError *error = nil;
    [[NSFileManager defaultManager] createDirectoryAtURL:url
                             withIntermediateDirectories:YES
                                              attributes:nil
                                                   error:&error];
    if (error) {
        GNLogC("resign: could not create fallback directory %s (%s)",
               path.UTF8String ?: "?", error.localizedDescription.UTF8String ?: "?");
    }
    return url;
}

static NSString *GNSanitizeGroupID(NSString *groupID) {
    if (!groupID.length) return @"default";
    NSMutableString *safe = [NSMutableString string];
    for (NSUInteger i = 0; i < groupID.length; i++) {
        unichar c = [groupID characterAtIndex:i];
        BOOL ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
        // %C takes unichar; the ternary promotes to int, which warns.
        [safe appendFormat:@"%C", (unichar)(ok ? c : '_')];
    }
    return safe;
}

// A hook may be useless. It may not throw into the app's call stack: an
// exception raised here is caught here and the app gets the original answer.
static NSURL *GNReplacementContainerURL(id self, SEL _cmd, NSString *groupID) {
    @try {
        NSURL *url = gOrigContainerURL ? gOrigContainerURL(self, _cmd, groupID) : nil;
        if (url) return url;

        // What to hand back when the entitlement is gone. "docs" invents a
        // directory, which is what every re-sign tool does and what an app
        // that force unwraps nil needs - but an app that *trusts* the URL and
        // reads a container that is not there gets an empty store instead of a
        // missing one, and that is a different failure. "nil" is the honest
        // answer, "home" is the app's own container. Config, not code, because
        // which one is right is a property of the app.
        NSString *mode = GNResignString(@"AppGroupFallbackMode") ?: @"docs";
        if ([mode caseInsensitiveCompare:@"nil"] == NSOrderedSame) {
            GNLogC("resign: app group '%s' unavailable -> nil (mode=nil)",
                   (groupID ?: @"(nil)").UTF8String);
            return nil;
        }
        if ([mode caseInsensitiveCompare:@"home"] == NSOrderedSame) {
            NSURL *home = [NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES];
            GNLogC("resign: app group '%s' unavailable -> %s (mode=home)",
                   (groupID ?: @"(nil)").UTF8String, home.path.UTF8String ?: "?");
            return home;
        }

        NSURL *fallback = GNFallbackDirectory([NSString stringWithFormat:@"AppGroups/%@",
                                               GNSanitizeGroupID(groupID)]);
        GNLogC("resign: app group '%s' unavailable -> %s (mode=docs)",
               (groupID ?: @"(nil)").UTF8String, fallback.path.UTF8String ?: "?");
        return fallback;
    } @catch (NSException *exception) {
        GNLogC("resign: container hook threw %s: %s",
               (exception.name ?: @"?").UTF8String, (exception.reason ?: @"?").UTF8String);
        return gOrigContainerURL ? gOrigContainerURL(self, _cmd, groupID) : nil;
    }
}

static NSURL *GNReplacementUbiquityURL(id self, SEL _cmd, NSString *containerID) {
    @try {
        NSURL *url = gOrigUbiquityURL ? gOrigUbiquityURL(self, _cmd, containerID) : nil;
        if (url) return url;

        NSURL *fallback = GNFallbackDirectory(@"iCloud");
        GNLogC("resign: ubiquity container '%s' unavailable -> %s",
               (containerID ?: @"(nil)").UTF8String, fallback.path.UTF8String ?: "?");
        return fallback;
    } @catch (NSException *exception) {
        GNLogC("resign: ubiquity hook threw %s: %s",
               (exception.name ?: @"?").UTF8String, (exception.reason ?: @"?").UTF8String);
        return nil;
    }
}

static NSURL *GNReplacementReceiptURL(id self, SEL _cmd) {
    // Off by default, and it should stay off unless you know what the app does
    // with a nil receipt. A re-signed bundle has a receipt URL whose file does
    // not exist; callers that do `try Data(contentsOf: url)` throw on a bad
    // *file*, but callers that force unwrap nil throw on a nil *URL*. Returning
    // nil is a different bug from the one it is usually meant to fix, so this
    // hook only reports what the real value was.
    @try {
        NSURL *url = gOrigReceiptURL ? gOrigReceiptURL(self, _cmd) : nil;
        GNLogC("resign: appStoreReceiptURL = %s (exists=%s)",
               url.path.UTF8String ?: "(nil)",
               (url && [[NSFileManager defaultManager] fileExistsAtPath:url.path]) ? "yes" : "no");
        return nil;
    } @catch (NSException *exception) {
        GNLogC("resign: receipt hook threw %s: %s",
               (exception.name ?: @"?").UTF8String, (exception.reason ?: @"?").UTF8String);
        return gOrigReceiptURL ? gOrigReceiptURL(self, _cmd) : nil;
    }
}

static void GNInstallContainerFixes(void) {
    if (GNResignOn(@"AppGroupFallback", YES)) {
        GNHookInstance([NSFileManager class],
                       "containerURLForSecurityApplicationGroupIdentifier:",
                       (IMP)GNReplacementContainerURL, (IMP *)&gOrigContainerURL);
    }
    if (GNResignOn(@"UbiquityFallback", NO)) {
        GNHookInstance([NSFileManager class],
                       "URLForUbiquityContainerIdentifier:",
                       (IMP)GNReplacementUbiquityURL, (IMP *)&gOrigUbiquityURL);
    }
    if (GNResignOn(@"SuiteNameFallback", YES)) {
        GNLogC("resign: SuiteNameFallback is retired in v8 - "
               "-[NSUserDefaults initWithSuiteName:] is left alone (see GNResign.m)");
    }
    if (GNResignOn(@"DisableAppStoreReceipt", NO)) {
        GNHookInstance([NSBundle class],
                       "appStoreReceiptURL",
                       (IMP)GNReplacementReceiptURL, (IMP *)&gOrigReceiptURL);
    }
}

#pragma mark - 3. Code signature validation

static OSStatus (*gOrigCheckValidity)(void *, uint32_t, void *);
static OSStatus (*gOrigCheckValidityErr)(void *, uint32_t, void *, CFErrorRef *);
static OSStatus (*gOrigSigningInformation)(void *, uint32_t, CFDictionaryRef *);

static OSStatus GNReplacementCheckValidity(void *code, uint32_t flags, void *requirement) {
    GNLogC("resign: code validity check swallowed");
    return kGNErrSecSuccess;
}

static OSStatus GNReplacementCheckValidityErr(void *code, uint32_t flags, void *requirement,
                                              CFErrorRef *error) {
    GNLogC("resign: code validity check (with errors) swallowed");
    if (error) *error = NULL;
    return kGNErrSecSuccess;
}

static OSStatus GNReplacementSigningInformation(void *code, uint32_t flags,
                                                CFDictionaryRef *info) {
    OSStatus status = gOrigSigningInformation ? gOrigSigningInformation(code, flags, info)
                                              : kGNErrSecSuccess;
    if (status != kGNErrSecSuccess || !info || !*info) return status;

    @try {
        NSMutableDictionary *dict = [(__bridge NSDictionary *)*info mutableCopy];
        if (!dict) return status;

        NSString *bundleID = GNTargetBundleIdentifier();
        NSString *teamID = GNResignString(@"TeamID");

        if (bundleID.length) dict[@"identifier"] = bundleID;
        if (teamID.length)   dict[@"teamid"] = teamID;

        CFRelease(*info);
        *info = (CFDictionaryRef)CFBridgingRetain([dict copy]);
        GNLogC("resign: signing information patched (id=%s team=%s)",
               bundleID.UTF8String ?: "?", teamID.UTF8String ?: "(unset)");
    } @catch (NSException *exception) {
        // Leave whatever the real call returned in place.
        GNLogC("resign: signing information hook threw %s: %s",
               (exception.name ?: @"?").UTF8String, (exception.reason ?: @"?").UTF8String);
    }
    return kGNErrSecSuccess;
}

static void GNInstallSignatureChecks(void) {
    if (!GNResignOn(@"BypassCodeSignatureChecks", YES)) {
        GNLogC("resign: signature check bypass disabled by config");
        return;
    }

    gOrigCheckValidity = (__typeof__(gOrigCheckValidity))dlsym(RTLD_DEFAULT, "SecStaticCodeCheckValidity");
    gOrigCheckValidityErr = (__typeof__(gOrigCheckValidityErr))dlsym(RTLD_DEFAULT, "SecStaticCodeCheckValidityWithErrors");
    gOrigSigningInformation = (__typeof__(gOrigSigningInformation))dlsym(RTLD_DEFAULT, "SecCodeCopySigningInformation");

    GNInterposeSymbol("SecStaticCodeCheckValidity",
                       (void *)GNReplacementCheckValidity, (void **)&gOrigCheckValidity);
    GNInterposeSymbol("SecStaticCodeCheckValidityWithErrors",
                       (void *)GNReplacementCheckValidityErr, (void **)&gOrigCheckValidityErr);
    GNInterposeSymbol("SecCodeCheckValidity",
                       (void *)GNReplacementCheckValidity, NULL);
    GNInterposeSymbol("SecCodeCheckValidityWithErrors",
                       (void *)GNReplacementCheckValidityErr, NULL);

    if (GNResignOn(@"ForceSigningInformation", YES)) {
        GNInterposeSymbol("SecCodeCopySigningInformation",
                           (void *)GNReplacementSigningInformation,
                           (void **)&gOrigSigningInformation);
    }
}

#pragma mark - 4. Entitlement queries

typedef void *GNSecTaskRef;

static CFTypeRef (*gOrigTaskEntitlement)(GNSecTaskRef, CFStringRef, CFErrorRef *);
static CFTypeRef (*gOrigTaskEntitlements)(GNSecTaskRef, CFArrayRef, CFErrorRef *);
static CFStringRef (*gOrigTaskSigningIdentifier)(GNSecTaskRef);

static NSDictionary *GNEntitlementOverrides(void) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];

    NSString *teamID = GNResignString(@"TeamID");
    NSString *bundleID = GNTargetBundleIdentifier();

    if (teamID.length) {
        result[@"com.apple.developer.team-identifier"] = teamID;
        if (bundleID.length) result[@"application-identifier"] = [NSString stringWithFormat:@"%@.%@", teamID, bundleID];
    }
    // Everything else comes from ResignFix.Entitlements in the plist, so the
    // set of synthesised values stays explicit and auditable.
    NSDictionary *extra = GNResignConfig()[@"Entitlements"];
    if ([extra isKindOfClass:[NSDictionary class]]) {
        [result addEntriesFromDictionary:extra];
    }
    return result;
}

static CFTypeRef GNReplacementTaskEntitlement(GNSecTaskRef task, CFStringRef entitlement,
                                              CFErrorRef *error) {
    NSString *key = (__bridge NSString *)entitlement;
    id value = GNEntitlementOverrides()[key];
    if (value) {
        return GNRetainedCFValue(value);
    }
    if (gOrigTaskEntitlement) return gOrigTaskEntitlement(task, entitlement, error);
    if (error) *error = NULL;
    return NULL;
}

static CFTypeRef GNReplacementTaskEntitlements(GNSecTaskRef task, CFArrayRef entitlements,
                                               CFErrorRef *error) {
    NSArray *requested = (__bridge NSArray *)entitlements;
    NSDictionary *overrides = GNEntitlementOverrides();
    NSMutableDictionary *result = [NSMutableDictionary dictionary];

    for (NSString *key in requested) {
        id value = overrides[key];
        if (value) {
            result[key] = value;
            continue;
        }
        if (gOrigTaskEntitlement) {
            CFTypeRef single = gOrigTaskEntitlement(task, (__bridge CFStringRef)key, NULL);
            if (single) {
                result[key] = CFBridgingRelease(single);
            }
        }
    }
    if (error) *error = NULL;
    return (CFTypeRef)CFBridgingRetain([result copy]);
}

static CFStringRef GNReplacementTaskSigningIdentifier(GNSecTaskRef task) {
    NSString *bundleID = GNTargetBundleIdentifier();
    if (bundleID.length) return (CFStringRef)CFBridgingRetain([bundleID copy]);
    if (gOrigTaskSigningIdentifier) return gOrigTaskSigningIdentifier(task);
    return NULL;
}

static void GNInstallEntitlementFix(void) {
    if (!GNResignOn(@"ForceEntitlements", YES)) {
        GNLogC("resign: entitlement override disabled by config");
        return;
    }

    gOrigTaskEntitlement = (__typeof__(gOrigTaskEntitlement))dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
    gOrigTaskEntitlements = (__typeof__(gOrigTaskEntitlements))dlsym(RTLD_DEFAULT, "SecTaskCopyValuesForEntitlements");
    gOrigTaskSigningIdentifier = (__typeof__(gOrigTaskSigningIdentifier))dlsym(RTLD_DEFAULT, "SecTaskCopySigningIdentifier");

    if (!gOrigTaskEntitlement) {
        GNLogC("resign: SecTaskCopyValueForEntitlement not available - skipped");
    } else {
        GNInterposeSymbol("SecTaskCopyValueForEntitlement",
                           (void *)GNReplacementTaskEntitlement,
                           (void **)&gOrigTaskEntitlement);
    }

    GNInterposeSymbol("SecTaskCopyValuesForEntitlements",
                       (void *)GNReplacementTaskEntitlements,
                       (void **)&gOrigTaskEntitlements);

    GNInterposeSymbol("SecTaskCopySigningIdentifier",
                       (void *)GNReplacementTaskSigningIdentifier,
                       (void **)&gOrigTaskSigningIdentifier);
}

#pragma mark - Entry point

static BOOL GNResignSectionEnabled(NSDictionary *cfg) {
    NSDictionary *resign = cfg[@"ResignFix"];
    if (![resign isKindOfClass:[NSDictionary class]]) return YES;
    id enabled = resign[@"Enabled"];
    return enabled ? [enabled boolValue] : YES;
}

void GNInstallResignContainerFixes(NSDictionary *cfg) {
    if (!GNResignSectionEnabled(cfg)) {
        GNLogC("resign: disabled by config - container fallbacks skipped");
        return;
    }
    GNLogC("resign: level 2 - container fallbacks (method lists only, no code page)");
    @try {
        GNInstallContainerFixes();
    } @catch (NSException *exception) {
        GNLogC("resign: container install threw %s: %s",
               (exception.name ?: @"?").UTF8String, (exception.reason ?: @"?").UTF8String);
    }
}

void GNInstallResignSymbolFixes(NSDictionary *cfg) {
    if (!GNResignSectionEnabled(cfg)) {
        GNLogC("resign: disabled by config - symbol interposition skipped");
        return;
    }
    GNLogC("resign: level 3 - C level interposition (keychain / SecCode / SecTask)");
    @try {
        GNInstallKeychainFix();
        GNInstallSignatureChecks();
        GNInstallEntitlementFix();
        GNLogC("resign: done (team=%s bundle=%s gotRebinding=%s)",
               (GNResignString(@"TeamID") ?: @"(unset)").UTF8String,
               GNTargetBundleIdentifier().UTF8String ?: "?",
               GNCFG(@"EnableGOTRebinding", NO) ? "on" : "off");
    } @catch (NSException *exception) {
        GNLogC("resign: symbol install threw %s: %s",
               (exception.name ?: @"?").UTF8String, (exception.reason ?: @"?").UTF8String);
    }
}
