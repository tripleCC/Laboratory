//
//  NSSet+LeaksMonitor.m
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/3/19.
//

#import "NSSet+LeaksMonitor.h"
#import "NSObject+LeaksMonitor.h"

@implementation NSSet (LeaksMonitor)
- (void)LeaksMonitor_collectProxiesForCollector:(TDFLeakObjectProxyCollector *)collector withContext:(TDFLeakContext *)ctx {
    [super LeaksMonitor_collectProxiesForCollector:collector withContext:ctx];
    
    [self enumerateObjectsUsingBlock:^(id  _Nonnull obj, BOOL * _Nonnull stop) {
        if ([obj conformsToProtocol:@protocol(TDFLeakObjectProxyCollectable)]) {
            [obj LeaksMonitor_collectProxiesForCollector:collector withContext:LM_CTX_D(ctx, @"contains")];
        }
    }];
}

- (BOOL)LeaksMonitor_objectCanBeCollected {
    return YES;
}

@end
