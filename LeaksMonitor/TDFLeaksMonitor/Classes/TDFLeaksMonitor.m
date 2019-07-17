//
//  TDFLeaksMonitor.m
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/2/19.
//
#include <pthread.h>
#import "TDFLeaksMonitor.h"
#import "TDFLeakObjectProxy.h"
#import "UIViewController+LeaksMonitor.h"
#import "UIWindow+LeaksMonitor.h"

@implementation TDFLeaksMonitor {
    NSMutableSet *_whiteList;
    pthread_mutex_t _delegatesLock;
    NSHashTable *_delegates;
}

+ (instancetype)shared {
    static TDFLeaksMonitor *singleton = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        singleton = [[self alloc] init];
    });
    return singleton;
}

- (instancetype)init {
    if (self = [super init]) {
        _delayMonitorInSeconds = 2.0f;
        _delegates = [NSHashTable weakObjectsHashTable];
        pthread_mutex_init(&_delegatesLock, NULL);
    }
    return self;
}

- (void)dealloc {
    pthread_mutex_destroy(&_delegatesLock);
}

- (void)start {
    [UIViewController LeaksMonitor_setup];
    [UIWindow LeaksMonitor_setup];
}

- (void)addWhiteList:(NSArray <NSString *> *)whiteList {
    [self.whiteList addObjectsFromArray:whiteList];
}

- (void)addDelegate:(id <TDFLeaksMonitorDelegate>)delegate {
    pthread_mutex_lock(&_delegatesLock);
    [_delegates addObject:delegate];
    pthread_mutex_unlock(&_delegatesLock);
}

- (void)removeDelegate:(id <TDFLeaksMonitorDelegate>)delegate {
    pthread_mutex_lock(&_delegatesLock);
    [_delegates removeObject:delegate];
    pthread_mutex_unlock(&_delegatesLock);
}

- (void)detectLeaksForObject:(id <TDFLeakObjectProxyCollectable>)object {
    @try {
        // 收集控制器关联的所有 proxy
        // 收集之后再统一处理，避免对每一个对象都进行 3s 检测
        TDFLeakObjectProxyCollector *collector = [[TDFLeakObjectProxyCollector alloc] init];
        TDFLeakContext *context = [[TDFLeakContext alloc] init];
        context.host = object;
        
        (void)[object LeaksMonitor_collectProxiesForCollector:collector withContext:context];
        
        // 检测 3s 之后，collector 中的所有 proxy 是否正常
        [self detectProxyCollector:collector];
    } @catch (NSException *exception) {
        NSLog(@"Fail to detect leaks for object %@ with exception %@", object, exception);
    }
}

- (void)detectProxyCollector:(TDFLeakObjectProxyCollector *)collector {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.delayMonitorInSeconds * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        TDFLeakObjectInfoGroup *infoGroup = [[TDFLeakObjectInfoGroup alloc] init];
        [collector.proxies enumerateObjectsUsingBlock:^(TDFLeakObjectProxy * _Nonnull obj, BOOL * _Nonnull stop) {
            if (obj.isLeaking) {
                NSString *targetName = NSStringFromClass([obj.target class]);
                if ([self.whiteList containsObject:targetName]) {
                    return;
                }
                
                [infoGroup addLeakObject:obj.target traces:obj.traces];
            }
        }];
        
        for (id <TDFLeaksMonitorDelegate> delegate in self->_delegates) {
            if ([delegate respondsToSelector:@selector(LeaksMonitorDidDetectLeakInfos:)]) {
                [delegate LeaksMonitorDidDetectLeakInfos:infoGroup];
            }
        }
    });
}

- (NSMutableSet *)whiteList {
    if (!_whiteList) {
        _whiteList = [NSMutableSet set];
    }
    
    return _whiteList;
}
@end
