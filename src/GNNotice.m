//
//  GNNotice.m
//  On screen reporting, so a diagnosis does not need the container.
//
//  A re-signed app that dies during launch is the worst possible case for
//  logging: the file is on the device, but getting at it needs a file manager,
//  a working app, or a Mac. So the two facts that actually matter - which run
//  level the auto-bisect settled on, and what the previous launch's exception
//  was - are put on screen instead, on the *next* launch, once.
//
//  Nothing here runs during dyld init. The notification observer is registered
//  early because that is the only way to see didFinishLaunching, but the alert
//  itself is presented from the main queue seconds later, when there is a
//  window and a root view controller to present from.
//

#import "GNUnlock.h"

#import <UIKit/UIKit.h>
#import <dispatch/dispatch.h>

static const NSInteger GNNoticeMaxCharacters = 1400;

static NSString *GNReadCrashNote(void) {
    NSString *text = [NSString stringWithContentsOfFile:GNLastCrashPath()
                                               encoding:NSUTF8StringEncoding
                                                  error:NULL];
    if (!text.length) return nil;
    if (text.length <= (NSUInteger)GNNoticeMaxCharacters) return text;
    return [[text substringToIndex:(NSUInteger)GNNoticeMaxCharacters]
            stringByAppendingString:@"\n... (truncated)"];
}

static NSString *GNNoticeBody(void) {
    NSMutableString *body = [NSMutableString string];

    int level = GNRunLevel();
    int configured = (int)GNCGI(@"RunLevel", 3);
    if (level < configured) {
        [body appendFormat:@"Auto-bisect: running at level %d.\n%s\n"
                           @"A higher level died before the app finished launching.\n\n",
                           level, GNRunLevelName(level)];
    }

    int dropped = GNDroppedToLevel();
    if (dropped >= 0) {
        [body appendFormat:@"Auto-bisect: this launch caught an exception at level %d.\n"
                           @"Next launch runs at level %d (%s).\n"
                           @"Quit the app and open it again to test that level.\n\n",
                           level, dropped, GNRunLevelName(dropped)];
    }

    NSString *crash = GNReadCrashNote();
    if (crash.length) {
        [body appendString:@"Previous launch ended with:\n\n"];
        [body appendString:crash];
    }

    // The ladder is the answer to "which of our decisions was wrong", so it has
    // to be visible without pulling the container. Only shown when it is on.
    if (GNExperimentStep() >= 0) {
        [body appendFormat:@"\n\nExperiment: %@\n", GNExperimentStatus()];
    }
    return body;
}

static UIViewController *GNTopViewController(void) {
    UIApplication *application = [UIApplication sharedApplication];
    if (!application) return nil;

    UIWindow *window = application.keyWindow;
    if (!window) {
        for (UIWindow *candidate in application.windows) {
            if (candidate.isKeyWindow) { window = candidate; break; }
        }
    }
    if (!window) window = application.windows.firstObject;

    UIViewController *controller = window.rootViewController;
    while (controller.presentedViewController) {
        controller = controller.presentedViewController;
    }
    return controller;
}

static BOOL gDiagnosticScheduled = NO;

/// One presenter for both paths: a caught launch exception (from GNGuard) and
/// the generic auto-bisect / previous-crash summary (from GNShowLaunchNotice).
/// First caller wins, so the more specific report is the one that gets seen.
///
/// Presenting needs a window, and during didFinishLaunching there is none yet,
/// so this retries for ~15 seconds instead of giving up on the first attempt -
/// which is what a single fixed delay does when the app is slow to build its UI.
static void GNPresentAttempt(NSString *title, NSString *body, NSInteger attempt) {
    @try {
        UIViewController *host = GNTopViewController();
        if (!host) {
            if (attempt >= 30) {
                GNLogC("notice: no window after %ld attempts - the text stays in Documents",
                       (long)attempt);
                return;
            }
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                GNPresentAttempt(title, body, attempt + 1);
            });
            return;
        }

        UIAlertController *alert =
            [UIAlertController alertControllerWithTitle:title
                                                message:body
                                         preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Copy"
                                                 style:UIAlertActionStyleDefault
                                               handler:^(UIAlertAction *action) {
            (void)action;
            [UIPasteboard generalPasteboard].string = body;
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                 style:UIAlertActionStyleDefault
                                               handler:nil]];
        [host presentViewController:alert animated:YES completion:nil];

        GNLogC("notice: presented (%lu chars)", (unsigned long)body.length);
        // Shown once; the log keeps the text for later.
        [[NSFileManager defaultManager] removeItemAtPath:GNLastCrashPath() error:NULL];
    } @catch (NSException *exception) {
        GNLogC("notice: could not present - %s: %s",
               (exception.name ?: @"?").UTF8String,
               (exception.reason ?: @"?").UTF8String);
    }
}

void GNPresentDiagnostic(NSString *title, NSString *body) {
    if (!GNCFG(@"ShowLaunchNotice", YES)) return;
    if (!body.length) return;
    if (gDiagnosticScheduled) return;

    gDiagnosticScheduled = YES;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        GNPresentAttempt(title, body, 0);
    });
}

void GNShowLaunchNotice(void) {
    if (!GNCFG(@"ShowLaunchNotice", YES)) return;

    NSString *body = GNNoticeBody();
    if (body.length < 16) return;   // nothing to report
    GNPresentDiagnostic(@"GNUnlock", body);
}

void GNObserveLaunchCompletion(void) {
    static BOOL registered = NO;
    if (registered) return;
    registered = YES;

    @try {
        [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidFinishLaunchingNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note) {
            (void)note;
            GNSetPhase("alive");
            GNExperimentNoteSurvived();
            GNLogC("launch completed - run level %d, %s",
                   GNRunLevel(), GNExperimentStatus().UTF8String ?: "experiment off");
        }];
    } @catch (NSException *exception) {
        GNLogC("launch observer could not be registered - %s: %s",
               (exception.name ?: @"?").UTF8String,
               (exception.reason ?: @"?").UTF8String);
    }
}
