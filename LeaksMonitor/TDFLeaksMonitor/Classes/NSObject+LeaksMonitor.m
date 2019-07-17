//
//  NSObject+LeaksMonitor.m
//  TDFLeaksMonitor
//
//  Created by tripleCC on 7/3/19.
//

#import <objc/runtime.h>
#import <objc/message.h>
#import "NSObject+LeaksMonitor.h"
#import "TDFLeaksMonitorUtils.h"

@implementation NSObject (LeaksMonitor)

- (BOOL)LeaksMonitor_objectCanBeIgnored {
    return LMIsSystemClass(self.class);
}

- (BOOL)LeaksMonitor_objectCanBeCollected {
    return !LMIsSystemClass(self.class);
}

- (void)LeaksMonitor_collectProxiesForCollector:(TDFLeakObjectProxyCollector *)collector withContext:(TDFLeakContext *)ctx {
    // 过滤可以被忽略的类，比如系统类
    // NSTimer / CADisplayLink 等自身会泄漏的系统类通过重写此方法，使自身不被忽略
    if ([self LeaksMonitor_objectCanBeIgnored]) {
        return;
    }
    
    TDFLeakObjectProxy *proxy = [[TDFLeakObjectProxy alloc] initWithTarget:self host:ctx.host traces:ctx.traces];
    // 规避循环添加导致的死循环
    if (![collector addProxy:proxy]) {
        return;
    }
    
    NSMutableDictionary *objectMap = [NSMutableDictionary dictionary];
    Class cls = self.class;
    while (cls && !LMIsSystemClass(cls)) {
        unsigned int count = 0;
        objc_property_t *properties = class_copyPropertyList(cls, &count);
        for (unsigned int i = 0; i < count; i++) {
            objc_property_t property = properties[i];
            struct lm_objc_property mProperty = LMExpandProperty(property);
            
            // 过滤掉不是 strong / copy 的属性
            // 以及没有对应 ivar 的属性，比如 vc 的 view 属性
            // 强行通过 view 属性调用，可能会触发 viewDidLoad 导致意外的 bug
            // 所以只能放弃对关联对象等的监听
            if ((!mProperty.is_copy && !mProperty.is_strong) || mProperty.ivar_name[0] == '\0') {
                continue;
            }
            
            Ivar ivar = class_getInstanceVariable(cls, mProperty.ivar_name);
            const char *type = ivar_getTypeEncoding(ivar);
            
            // 过滤掉不是对象的 ivar
            if (type != NULL && type[0] != '@') {
                continue;
            }
            id object = object_getIvar(self, ivar);
            
            // 过滤无法调用 collect 进行收集的类，比如系统类
            // NSArray 等集合分类重写这个方法，使自身能被收集
            if ([object LeaksMonitor_objectCanBeCollected]) {
                NSString *propertyName = [NSString stringWithCString:mProperty.name encoding:NSUTF8StringEncoding];
                objectMap[propertyName] = object;
            }
        }
        free(properties);
        cls = [cls superclass];
    }
    
    [objectMap enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        if ([obj conformsToProtocol:@protocol(TDFLeakObjectProxyCollectable)]) {
            [obj LeaksMonitor_collectProxiesForCollector:collector withContext:LM_CTX_P(ctx, key)];
        }
    }];
}
@end


