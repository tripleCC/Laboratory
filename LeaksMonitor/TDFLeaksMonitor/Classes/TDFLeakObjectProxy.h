//
//  TDFLeakObjectProxy.h
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/3/19.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class TDFLeakContext;
@class TDFLeakObjectProxyCollector;

@protocol TDFLeakObjectProxyCollectable <NSObject>
/**
 收集对象及其名下的所有成员变量对应的 proxy

 @param collector 收集器，存储 proxy
 @param ctx 上下文
 */
- (void)LeaksMonitor_collectProxiesForCollector:( TDFLeakObjectProxyCollector * _Nonnull )collector withContext:( TDFLeakContext * _Nullable )ctx;

/**
 是否可被忽略，忽略后对象将不生成 proxy

 @return BOOL
 */
- (BOOL)LeaksMonitor_objectCanBeIgnored;

/**
 是否可被收集，可收集则可向对象发送
 LeaksMonitor_collectProxiesForCollector:withContext: 方法收集 proxy

 @return BOOL
 */
- (BOOL)LeaksMonitor_objectCanBeCollected;
@end

#define LM_CTX_P(ctx, pro) \
({ \
    TDFLeakContext *new = [ctx copy]; \
    new.host = self; \
    [new addTraceProperty:pro]; \
    new; \
})

#define LM_CTX_D(ctx, des) \
({ \
    TDFLeakContext *new = [ctx copy]; \
    new.host = self; \
    [new addTraceDescription:des]; \
    new; \
})

@interface TDFLeakContext : NSObject <NSCopying>
@property (weak, nonatomic) id host;
@property (copy, nonatomic, readonly) NSArray <NSString *> *traces;

- (void)addTraceProperty:(NSString *)property;
- (void)addTraceDescription:(NSString *)description;
@end

@interface TDFLeakObjectProxy : NSObject
/**
 持有 target 的对象
 host 释放后，target 应该释放
 */
@property (weak, nonatomic) id host;

/**
 被 host 持有的对象
 host 释放后，target 应该释放，如未释放，可能为泄漏
 */
@property (weak, nonatomic, readonly) id target;

@property (copy, nonatomic, readonly) NSArray <NSString *> *traces;

- (instancetype)initWithTarget:(id)target host:(id)host traces:(NSArray <NSString *> *)traces;

/**
 是否泄漏

 @return BOOL
 */
- (BOOL)isLeaking;
@end

@interface TDFLeakObjectProxyCollector : NSObject
- (NSSet <TDFLeakObjectProxy *> *)proxies;
- (BOOL)addProxy:(TDFLeakObjectProxy *)proxy;
@end


NS_ASSUME_NONNULL_END
