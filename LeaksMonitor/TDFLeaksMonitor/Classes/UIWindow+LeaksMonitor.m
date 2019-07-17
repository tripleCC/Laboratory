//
//  UIWindow+LeaksMonitor.m
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/11/19.
//
#import <OCHooking/OCHooking.h>
#import "UIWindow+LeaksMonitor.h"
#import "NSObject+LeaksMonitor.h"
#import "TDFLeaksMonitor+Internal.h"

@implementation UIWindow (LeaksMonitor)
+ (void)LeaksMonitor_setup {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [OCHooking swizzleMethod:@selector(setRootViewController:) onClass:self withSwizzledSelector:@selector(LeaksMonitor_setRootViewController:)];
    });
}

- (void)LeaksMonitor_setRootViewController:(UIViewController *)rootViewController {
    if (self.rootViewController && ![self.rootViewController isEqual:rootViewController]) {
        [[TDFLeaksMonitor shared] detectLeaksForObject:self.rootViewController];
    }
    
    [self LeaksMonitor_setRootViewController:rootViewController];
}
@end
