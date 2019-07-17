//
//  UIViewController+LeaksMonitor.m
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/3/19.
//
#import <OCHooking/OCHooking.h>
#import "UIViewController+LeaksMonitor.h"
#import "UIView+LeaksMonitor.h"
#import "NSObject+LeaksMonitor.h"
#import "TDFLeaksMonitor+Internal.h"

@implementation UIViewController (LeaksMonitor)
+ (void)LeaksMonitor_setup {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [OCHooking swizzleMethod:@selector(viewDidDisappear:) onClass:self withSwizzledSelector:@selector(LeaksMonitor_viewDidDisappear:)];
    });
}

- (void)LeaksMonitor_viewDidDisappear:(BOOL)animated {
    [self LeaksMonitor_viewDidDisappear:animated];
    
    if (![self isMovingFromParentViewController] && ![self isBeingDismissed]) {
        return;
    }
    
    [[TDFLeaksMonitor shared] detectLeaksForObject:self];
}

- (void)LeaksMonitor_collectProxiesForCollector:(TDFLeakObjectProxyCollector *)collector withContext:(TDFLeakContext *)ctx {
    [super LeaksMonitor_collectProxiesForCollector:collector withContext:ctx];
    
    // 规避 presentedViewController / childViewControllers 属性不生成 ivar 的情况
    [self.childViewControllers enumerateObjectsUsingBlock:^(__kindof UIViewController * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        [obj LeaksMonitor_collectProxiesForCollector:collector withContext:LM_CTX_P(ctx, @"childViewControllers")];
    }];
    [self.presentedViewController LeaksMonitor_collectProxiesForCollector:collector withContext:LM_CTX_P(ctx, @"presentedViewController")];
    
    // 这里必须确认 viewLoaded ，否则直接调用 self.view 会触发 viewDidLoad 方法
    if (self.viewLoaded) {
        [self.view LeaksMonitor_collectProxiesForCollector:collector withContext:LM_CTX_P(ctx, @"view")];
    }
}

- (BOOL)LeaksMonitor_objectCanBeCollected {
    return YES;
}
@end
