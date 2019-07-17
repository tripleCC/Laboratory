//
//  TDFLeakObjectProxy.m
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/3/19.
//
#import <objc/runtime.h>
#import "TDFLeakObjectProxy.h"

@implementation TDFLeakContext {
    NSMutableArray <NSString *> *_traces;
}

- (instancetype)init {
    if (self = [super init]) {
        _traces = [NSMutableArray array];
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    TDFLeakContext *context = [[self class] allocWithZone:zone];
    context->_host = _host;
    context->_traces = [_traces mutableCopy];
    return context;
}

- (void)addTraceProperty:(NSString *)property {
    NSString *trace = [NSString stringWithFormat:@"%@.%@", self.traceName, property];
    [_traces addObject:trace];
}

- (void)addTraceDescription:(NSString *)description {
    NSString *trace = [NSString stringWithFormat:@"%@(%@)", self.traceName, description];
    [_traces addObject:trace];
}

- (NSArray<NSString *> *)traces {
    return [_traces copy];
}

- (NSString *)traceName {
    return NSStringFromClass([_host class]);
}
@end

@implementation TDFLeakObjectProxy
- (instancetype)initWithTarget:(id)target host:(id)host traces:(nonnull NSArray<NSString *> *)traces {
    if (self = [super init]) {
        _target = target;
        _host = host;
        _traces = [traces arrayByAddingObject:NSStringFromClass([target class])];
    }
    return self;
}

- (BOOL)isCoveredByHost {
    // 如果 _host 不为空，并且 _host 不等于 target
    // 表示 _host 泄漏了，所以无法判断此 proxy 的 target 是否泄漏
    // 这时候使用 _host 等于 target 的 proxy 记录即可，其他的 proxy 可略过
    return _host && _host != _target;
}

- (BOOL)isLeaking {
    return !self.isCoveredByHost && _target;
}

- (NSUInteger)hash {
    return [_target hash] ^ [_host hash];
}

- (BOOL)isEqual:(TDFLeakObjectProxy *)object {
    if (![object isKindOfClass:[TDFLeakObjectProxy class]] ||
        ![_target isKindOfClass:[object.target class]] ||
        ![_host isKindOfClass:[object.host class]]) {
        return NO;
    }
    return [_target isEqual:object.target] && [_host isEqual:object.host];
}
@end

@implementation TDFLeakObjectProxyCollector {
    NSMutableSet *_proxies;
}

- (instancetype)init {
    if (self = [super init]) {
        _proxies = [NSMutableSet set];
    }
    return self;
}

- (BOOL)addProxy:(TDFLeakObjectProxy *)proxy {
    if ([_proxies containsObject:proxy]) {
        return NO;
    }
    
    [_proxies addObject:proxy];
    return YES;
}

- (NSSet *)proxies {
    return _proxies;
}
@end
