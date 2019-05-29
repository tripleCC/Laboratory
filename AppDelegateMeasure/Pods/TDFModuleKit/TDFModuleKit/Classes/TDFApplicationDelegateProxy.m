//
//  TDFApplicationDelegateProxy.m
//  Aspects
//
//  Created by tripleCC on 2017/10/23.
//
@import ObjectiveC.runtime;
@import UIKit;

#import "TDFModule.h"
#import "TDFModuleManager.h"
#import "TDFApplicationDelegateProxy.h"

@implementation TDFApplicationDelegateProxy
- (Protocol *)targetProtocol {
    return @protocol(UIApplicationDelegate);
}

- (BOOL)isTargetProtocolMethod:(SEL)selector {
    unsigned int outCount = 0;
    struct objc_method_description *methodDescriptions = protocol_copyMethodDescriptionList([self targetProtocol], NO, YES, &outCount);
    
    for (int idx = 0; idx < outCount; idx++) {
        if (selector == methodDescriptions[idx].name) {
            free(methodDescriptions);
            
            return YES;
        }
    }
    free(methodDescriptions);
    
    return NO;
}

- (BOOL)respondsToSelector:(SEL)aSelector {
    if ([self.realDelegate respondsToSelector:aSelector]) {
        return YES;
    }
    
    for (TDFModule *module in [TDFModuleManager shared].modules) {
        if ([self isTargetProtocolMethod:aSelector] && [module respondsToSelector:aSelector]) {
            return YES;
        }
    }
    
    return [super respondsToSelector:aSelector];
}

- (id)forwardingTargetForSelector:(SEL)aSelector {
    if (![self isTargetProtocolMethod:aSelector] && [self.realDelegate respondsToSelector:aSelector]) {
            return self.realDelegate;
    }
    return self;
}

- (NSMethodSignature *)methodSignatureForSelector:(SEL)aSelector {
    struct objc_method_description methodDescription = protocol_getMethodDescription([self targetProtocol], aSelector, NO, YES);
    
    if (methodDescription.name == NULL && methodDescription.types == NULL) {
        return [[self class] instanceMethodSignatureForSelector:@selector(doNothing)];
    }
    
    return [NSMethodSignature signatureWithObjCTypes:methodDescription.types];;
}

- (void)forwardInvocation:(NSInvocation *)anInvocation {
    NSMutableArray *allModules = [NSMutableArray arrayWithObjects:self.realDelegate, nil];
    [allModules addObjectsFromArray:[TDFModuleManager shared].modules];
    
    // BOOL 型返回值做特殊 | 处理
    if (anInvocation.methodSignature.methodReturnType[0] == 'B') {
        BOOL realReturnValue = NO;
        
        for (TDFModule *module in allModules) {
            if ([module respondsToSelector:anInvocation.selector]) {
                [anInvocation invokeWithTarget:module];
                
                BOOL returnValue = NO;
                [anInvocation getReturnValue:&returnValue];
                
                realReturnValue = returnValue || realReturnValue;
            }
        }
        
        [anInvocation setReturnValue:&realReturnValue];
    } else {
        for (TDFModule *module in allModules) {
            if ([module respondsToSelector:anInvocation.selector]) {
                [anInvocation invokeWithTarget:module];
            }
        }
    }
}

- (void)doNothing {}
@end
