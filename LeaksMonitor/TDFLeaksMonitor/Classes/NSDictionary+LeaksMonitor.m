//
//  NSDictionary+LeaksMonitor.m
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/3/19.
//

#import "NSDictionary+LeaksMonitor.h"
#import "NSObject+LeaksMonitor.h"

@implementation NSDictionary (LeaksMonitor)
- (void)LeaksMonitor_collectProxiesForCollector:(TDFLeakObjectProxyCollector *)collector withContext:(TDFLeakContext *)ctx {
    [super LeaksMonitor_collectProxiesForCollector:collector withContext:ctx];
    
    // 字典对 key 执行 copy，原则上也要 collect ，但是考虑到 key 一般不为自定义对象，所以忽略
    [self.allValues enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        if ([obj conformsToProtocol:@protocol(TDFLeakObjectProxyCollectable)]) {
            [obj LeaksMonitor_collectProxiesForCollector:collector withContext:LM_CTX_D(ctx, @"contains")];
        }
    }];
}

- (BOOL)LeaksMonitor_objectCanBeCollected {
    return YES;
}

@end
