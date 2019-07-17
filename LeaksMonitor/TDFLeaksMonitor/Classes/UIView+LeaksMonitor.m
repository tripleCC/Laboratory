//
//  UIView+LeaksMonitor.m
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/3/19.
//

#import "NSObject+LeaksMonitor.h"
#import "UIView+LeaksMonitor.h"

@implementation UIView (LeaksMonitor)
- (void)LeaksMonitor_collectProxiesForCollector:(TDFLeakObjectProxyCollector *)collector withContext:(TDFLeakContext *)ctx {
    [super LeaksMonitor_collectProxiesForCollector:collector withContext:ctx];
    
    [self.subviews LeaksMonitor_collectProxiesForCollector:collector withContext:LM_CTX_P(ctx, @"subviews")];
}

- (BOOL)LeaksMonitor_objectCanBeCollected {
    return YES;
}
@end
