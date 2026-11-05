//
//  Stub <UIKit/UIKit.h>
//
//  Only what GNNotice.m needs: an application object, a window, a view
//  controller and an alert. The dylib does not drive UI; it shows one alert
//  with the auto-bisect result and the previous launch's exception.
//
#pragma once
#include <Foundation/Foundation.h>

typedef struct { CGFloat x, y; } CGPoint;
typedef struct { CGFloat width, height; } CGSize;
typedef struct { CGPoint origin; CGSize size; } CGRect;

extern NSString *const UIApplicationDidFinishLaunchingNotification;
extern NSString *const UIApplicationWillEnterForegroundNotification;
extern NSString *const UIApplicationDidBecomeActiveNotification;

typedef enum {
    UIAlertControllerStyleActionSheet = 0,
    UIAlertControllerStyleAlert = 1,
} UIAlertControllerStyle;

typedef enum {
    UIAlertActionStyleDefault = 0,
    UIAlertActionStyleCancel = 1,
    UIAlertActionStyleDestructive = 2,
} UIAlertActionStyle;

@class UIView, UIWindow, UIViewController, UIAlertController, UIAlertAction;

@interface UIResponder : NSObject
@end

@interface UIView : UIResponder
@property (nonatomic) CGRect frame;
@property (nonatomic) BOOL userInteractionEnabled;
@property (readonly, nonatomic) UIView *superview;
@property (readonly, nonatomic, copy) NSArray *subviews;
- (void)addSubview:(UIView *)view;
@end

@interface UIWindow : UIView
@property (nonatomic, strong) UIViewController *rootViewController;
@property (readonly, nonatomic, getter=isKeyWindow) BOOL keyWindow;
- (void)makeKeyAndVisible;
@end

@interface UIViewController : UIResponder
@property (nonatomic, strong) UIView *view;
@property (readonly, nonatomic) UIViewController *presentedViewController;
@property (readonly, nonatomic) UIViewController *presentingViewController;
@property (readonly, nonatomic) UIWindow *viewIfLoaded_DO_NOT_USE;
- (void)presentViewController:(UIViewController *)viewControllerToPresent
                     animated:(BOOL)flag
                   completion:(void (^)(void))completion;
- (void)dismissViewControllerAnimated:(BOOL)flag completion:(void (^)(void))completion;
@end

@interface UIAlertAction : NSObject
+ (instancetype)actionWithTitle:(NSString *)title
                          style:(UIAlertActionStyle)style
                        handler:(void (^)(UIAlertAction *action))handler;
@property (nonatomic, readonly) NSString *title;
@end

@interface UIAlertController : UIViewController
+ (instancetype)alertControllerWithTitle:(NSString *)title
                                 message:(NSString *)message
                          preferredStyle:(UIAlertControllerStyle)preferredStyle;
- (void)addAction:(UIAlertAction *)action;
@property (nonatomic, readonly) NSArray *actions;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *message;
@end

@interface UIPasteboard : NSObject
+ (UIPasteboard *)generalPasteboard;
@property (nonatomic, copy) NSString *string;
@end

@interface UIApplication : UIResponder
+ (UIApplication *)sharedApplication;
@property (nonatomic, assign) id delegate;
@property (nonatomic, readonly) NSArray *windows;
@property (nonatomic, readonly) UIWindow *keyWindow;
- (BOOL)openURL:(NSURL *)url;
@end

