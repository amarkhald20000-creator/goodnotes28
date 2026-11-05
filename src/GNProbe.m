//
//  GNProbe.m
//  Reads the signed process' own entitlements and container answers.
//
//  The question that has been open since v8 is: after LC Sign re-signs this
//  app, what does the process actually have? Not what the original App Store
//  binary had, not what the .entitlements file says - what the kernel and
//  securityd will answer *now*, in this process, this launch.
//
//  That is answerable without a Mac, without Xcode and without guessing, because
//  the process can interrogate itself:
//
//    SecTask copy of self        -> a task handle for this process
//    its entitlement value       -> the entitlement as signed, post-strip
//    containerURLForSecurityApplicationGroupIdentifier:
//                               -> what the app group lookup really returns
//                                  here (nil vs a URL)
//
//  The two SecTask entry points are private: not in <Security/Security.h>, not
//  in Security.tbd. v12.1 named them directly and the macOS front end rejected
//  the file before it compiled. They are resolved through GNPrivateSecTask.h
//  now - dlsym at run time, one lookup, no private declaration anywhere - and
//  every call below is a wrapper. When the symbols are absent the probe says so
//  instead of pretending, which is the rule this whole file follows.
//
//  Everything below is read-only. It installs nothing, overrides nothing, and
//  writes no preference. Its only output is log lines.
//
//  If the app group entitlement is absent from that first answer, then no hook
//  in this dylib can make the container real - the fix belongs in the signing
//  step, and every "fallback" we wrote was papering over a missing entitlement
//  with an empty directory. If the entitlement is present and the container URL
//  is still nil, that is a provisioning problem, not a code problem. Either way
//  the next launch stops being a guess.
//

#import "GNUnlock.h"
#import "GNBeacon.h"

#import "GNPrivateSecTask.h"
#import "GNEntitlementRepair.h"
#import <dispatch/dispatch.h>
#import <string.h>

/// Entitlements worth looking at for a launch-time container failure.
///
/// Ordered by how directly each one can explain an exception thrown out of a
/// dispatch_once during app initialisation.
static const char *kGNProbeEntitlements[] = {
    "com.apple.security.application-groups",          // app group container
    "keychain-access-groups",                         // -34018 on every SecItem call
    "application-identifier",                         // team + bundle identity
    "com.apple.developer.team-identifier",
    "com.apple.developer.icloud-container-identifiers", // CloudKit / ubiquity
    "com.apple.developer.icloud-services",
    "com.apple.developer.ubiquity-kvstore-identifier",
    "com.apple.developer.associated-domains",
    "get-task-allow",
    "aps-environment",
    NULL,
};

static void GNProbeLogEntitlements(void) {
    GNSecTaskHandle task = GNPrivateSecTaskCreateFromSelf();
    if (!task) {
        GNBeaconLine("probe: no task handle - cannot read this process' entitlements");
        return;
    }

    GNBeaconLine("probe: entitlements as signed in THIS process:");
    for (int i = 0; kGNProbeEntitlements[i]; i++) {
        CFStringRef key = CFStringCreateWithCString(NULL, kGNProbeEntitlements[i],
                                                    kCFStringEncodingUTF8);
        if (!key) continue;

        CFTypeRef value = GNPrivateSecTaskCopyEntitlement(task, key);
        if (value) {
            const char *text = [(__bridge id)value description].UTF8String;
            GNBeaconLine("  %-48s = %s", kGNProbeEntitlements[i], text ? text : "(?)");
            CFRelease(value);
        } else {
            GNBeaconLine("  %-48s = <ABSENT>", kGNProbeEntitlements[i]);
        }
        CFRelease(key);
    }

    CFRelease(task);
}

/// Extracts the string elements of an entitlement array so each one can be
/// handed to the container lookup.
static NSArray<NSString *> *GNProbeAppGroupsFromEntitlements(void) {
    GNSecTaskHandle task = GNPrivateSecTaskCreateFromSelf();
    if (!task) return @[];

    CFStringRef key = CFStringCreateWithCString(NULL, "com.apple.security.application-groups",
                                                kCFStringEncodingUTF8);
    NSMutableArray<NSString *> *groups = [NSMutableArray array];
    if (key) {
        CFTypeRef value = GNPrivateSecTaskCopyEntitlement(task, key);
        if (value) {
            if ([(__bridge id)value isKindOfClass:[NSArray class]]) {
                for (id entry in (__bridge NSArray *)value) {
                    if ([entry isKindOfClass:[NSString class]]) [groups addObject:entry];
                }
            }
            CFRelease(value);
        }
        CFRelease(key);
    }
    CFRelease(task);
    return groups;
}

static void GNProbeContainerLookups(void) {
    NSArray<NSString *> *groups = GNProbeAppGroupsFromEntitlements();

    if (groups.count == 0) {
        GNBeaconLine("probe: no com.apple.security.application-groups entitlement survived signing");
        GNBeaconLine("probe: -> every containerURLForSecurityApplicationGroupIdentifier: call in this");
        GNBeaconLine("probe:    process must return nil, whatever a fallback hook pretends.");
    }

    // The groups the entitlement grants, plus the one the app was built against.
    // Asking about a group we do not hold is harmless (it returns nil) and it
    // separates "not entitled" from "entitled but not provisioned".
    NSMutableArray<NSString *> *candidates = [NSMutableArray arrayWithArray:groups];
    NSString *expected = @"group.com.goodnotesapp.x";
    if (![candidates containsObject:expected]) [candidates addObject:expected];

    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *group in candidates) {
        NSURL *url = nil;
        @try {
            url = [fm containerURLForSecurityApplicationGroupIdentifier:group];
        } @catch (NSException *e) {
            GNBeaconLine("probe: container lookup for %s THREW %s: %s",
                         group.UTF8String ?: "?",
                         (e.name ?: @"?").UTF8String,
                         (e.reason ?: @"?").UTF8String);
            continue;
        }

        if (url) {
            NSNumber *writable = nil;
            @try {
                writable = @([fm isWritableFileAtPath:url.path]);
            } @catch (__unused NSException *e) {
            }
            GNBeaconLine("probe: app group %-32s -> %s (writable=%s)",
                         group.UTF8String ?: "?",
                         url.path.UTF8String ?: "?",
                         writable.boolValue ? "yes" : "no");
        } else {
            GNBeaconLine("probe: app group %-32s -> nil", group.UTF8String ?: "?");
        }
    }
}

static void GNProbeBundleFacts(void) {
    NSBundle *bundle = [NSBundle mainBundle];
    if (!bundle) {
        GNBeaconLine("probe: [NSBundle mainBundle] is nil");
        return;
    }

    GNBeaconLine("probe: bundle id : %s", (bundle.bundleIdentifier ?: @"(nil)").UTF8String);
    GNBeaconLine("probe: bundle    : %s", (bundle.bundlePath ?: @"(nil)").UTF8String);

    NSURL *receipt = bundle.appStoreReceiptURL;
    if (receipt) {
        BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:receipt.path];
        GNBeaconLine("probe: receipt   : %s (exists=%s)",
                     receipt.path.UTF8String ?: "?",
                     exists ? "yes" : "no");
    } else {
        GNBeaconLine("probe: receipt   : nil (appStoreReceiptURL returned nothing)");
    }
}

/// What an entitlement key is required to hold.
typedef enum {
    GNShapeString = 0,          // a single string
    GNShapeArrayOfStrings,      // an array, every element a string
} GNShapeWant;

static const char *GNShapeActualName(id value) {
    if (!value) return "absent";
    if ([value isKindOfClass:[NSString class]]) return "string";
    if ([value isKindOfClass:[NSArray class]]) return "array";
    if ([value isKindOfClass:[NSDictionary class]]) return "dictionary";
    if ([value isKindOfClass:[NSNumber class]]) return "number";
    if ([value isKindOfClass:[NSData class]]) return "data";
    return "other";
}

static BOOL GNShapeSatisfies(id value, GNShapeWant want) {
    if (!value) return NO;
    if (want == GNShapeString) return [value isKindOfClass:[NSString class]];

    if (![value isKindOfClass:[NSArray class]]) return NO;
    for (id entry in (NSArray *)value) {
        if (![entry isKindOfClass:[NSString class]]) return NO;
    }
    return YES;
}

/// Validates the *type* of the entitlements a re-sign is most likely to write
/// wrongly, and states the verdict in the log.
///
/// This is what v13's log needed and did not have: it printed
/// `com.apple.developer.icloud-services = *` and left the reader to know that
/// CloudKit requires an array there. A value can be present, non-empty, and
/// still be the reason the app dies on launch - so "does the key exist" is the
/// wrong question and this asks the right one.
static void GNProbeEntitlementShapes(void) {
    GNSecTaskHandle task = GNPrivateSecTaskCreateFromSelf();
    if (!task) {
        GNBeaconLine("probe: no task handle - entitlement shapes not checked");
        return;
    }

    static const struct {
        const char *key;
        GNShapeWant want;
    } checks[] = {
        { "com.apple.developer.icloud-services",             GNShapeArrayOfStrings },
        { "com.apple.developer.icloud-container-identifiers", GNShapeArrayOfStrings },
        { "com.apple.developer.ubiquity-kvstore-identifier",  GNShapeString },
        { "com.apple.security.application-groups",            GNShapeArrayOfStrings },
        { "keychain-access-groups",                           GNShapeArrayOfStrings },
        { "com.apple.developer.associated-domains",           GNShapeArrayOfStrings },
    };

    GNBeaconLine("probe: ---- entitlement types ----");
    int malformed = 0;
    int icloudMalformed = 0;

    for (size_t i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
        CFStringRef key = CFStringCreateWithCString(NULL, checks[i].key, kCFStringEncodingUTF8);
        if (!key) continue;

        CFTypeRef value = GNPrivateSecTaskCopyEntitlement(task, key);
        id object = value ? (__bridge id)value : nil;

        const char *actual = GNShapeActualName(object);
        const char *expected = checks[i].want == GNShapeString ? "string" : "array of strings";
        BOOL ok = GNShapeSatisfies(object, checks[i].want);

        if (ok) {
            GNBeaconLine("  %-48s %-14s ok", checks[i].key, actual);
        } else if (!object) {
            GNBeaconLine("  %-48s %-14s absent", checks[i].key, actual);
        } else {
            const char *text = [[object description] UTF8String];
            GNBeaconLine("  %-48s %-14s MALFORMED - CloudKit requires %s, got %s",
                         checks[i].key, actual, expected, text ? text : "?");
            malformed++;
            if (strstr(checks[i].key, "icloud") != NULL) icloudMalformed++;
        }

        if (value) CFRelease(value);
        CFRelease(key);
    }

    if (malformed == 0) {
        GNBeaconLine("probe: VERDICT: every checked entitlement has the type Apple requires");
    } else if (icloudMalformed > 0) {
        GNBeaconLine("probe: VERDICT: %d entitlement(s) malformed, %d of them iCloud.",
                     malformed, icloudMalformed);
        GNBeaconLine("probe: VERDICT: CloudKit validates these in process on first use and "
                     "raises CKException when a type is wrong - that is this launch's crash.");
        GNBeaconLine("probe: the in-process answer: %s (see the 'repair:' and 'slot:' lines).",
                     GNEntitlementSlotStatus());
        GNBeaconLine("probe: FIX (signer, not this dylib): in LC Sign's entitlements, either");
        GNBeaconLine("probe:        delete com.apple.developer.icloud-services and");
        GNBeaconLine("probe:        com.apple.developer.icloud-container-identifiers, or");
        GNBeaconLine("probe:        write them with the types Apple requires:");
        GNBeaconLine("probe:          <key>com.apple.developer.icloud-services</key>");
        GNBeaconLine("probe:          <array><string>CloudKit</string></array>");
        GNBeaconLine("probe:          <key>com.apple.developer.icloud-container-identifiers</key>");
        GNBeaconLine("probe:          <array><string>iCloud.$(CFBundleIdentifier)</string></array>");
        GNBeaconLine("probe: A bare \"*\" is the wildcard some signers inject; CloudKit reads it as "
                     "a string and refuses it. It is not a permission problem.");
    } else {
        GNBeaconLine("probe: VERDICT: %d entitlement(s) malformed - confirm the signer did not "
                     "write a scalar where an array belongs", malformed);
    }

    CFRelease(task);
}

void GNProbeSignedState(void) {
    GNBeaconLine("probe: ---- signed state of this process ----");
    GNPrivateSecTaskResolve();
    GNBeaconLine("probe: SecTask API %s",
                 GNPrivateSecTaskAvailable() ? "available (dlsym)" : "NOT available");
    @try {
        GNProbeBundleFacts();
        GNProbeLogEntitlements();
        GNProbeEntitlementShapes();
        GNProbeContainerLookups();
    } @catch (NSException *e) {
        GNBeaconLine("probe: threw %s: %s - probe aborted, nothing else affected",
                     (e.name ?: @"?").UTF8String,
                     (e.reason ?: @"?").UTF8String);
    }
    GNBeaconLine("probe: ---- end of signed state ----");
}

void GNProbeScheduledChecks(void) {
    // URLForUbiquityContainerIdentifier blocks while it talks to the ubiquity
    // daemon, which is precisely the kind of thing that must not run inside a
    // dyld constructor. Two seconds in, on a background queue, it cannot affect
    // launch - and by then it is still early enough to be in the log before any
    // interactive crash.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            @try {
                NSURL *ubiquity = [[NSFileManager defaultManager]
                                   URLForUbiquityContainerIdentifier:nil];
                GNBeaconLine("probe(delayed): ubiquity container -> %s",
                             ubiquity ? (ubiquity.path.UTF8String ?: "?") : "nil");
            } @catch (NSException *e) {
                GNBeaconLine("probe(delayed): ubiquity lookup threw %s: %s",
                             (e.name ?: @"?").UTF8String,
                             (e.reason ?: @"?").UTF8String);
            }
        }
    });
    GNBeaconLine("probe: ubiquity lookup scheduled for +2.0s (never during dyld init)");

    // The verdict on the v15 repair needs a moment of real use first: the count
    // only moves when something in the process actually asks for one of the four
    // keys, and nothing guarantees that happened before launch finished. This
    // line is the one to read when deciding whether the interposition reached
    // the caller.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        GNBeaconLine("repair(delayed): %s, %d entitlement value(s) rewritten this launch",
                     GNEntitlementRepairStatus(), GNEntitlementRepairCount());
        // v16: the interposition being armed says nothing about whether it fires.
        // These two lines are the measurement - what the slots did, and what the
        // launch-time self-test found when it called the same entitlement twice.
        GNBeaconLine("slot(delayed): %s", GNEntitlementSlotStatus());
        GNBeaconLine("slot(delayed): self-test %s", GNEntitlementSlotSelfTestText());
    });
}
