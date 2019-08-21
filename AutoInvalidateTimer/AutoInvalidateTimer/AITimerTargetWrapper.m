//
//  AITimerTargetWrapper.m
//  AutoInvalidateTimer
//
//  Created by tripleCC on 8/21/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "AITimerTargetWrapper.h"

@implementation AITimerTargetWrapper  {
    __weak id _target;
    __weak NSTimer *_timer;
}

- (instancetype)initWithTarget:(id)target {
    _target = target;
    
    return self;
}

- (NSMethodSignature *)methodSignatureForSelector:(SEL)selector {
    if (_target) {
        return [_target methodSignatureForSelector:selector];
    } else {
        return [NSObject instanceMethodSignatureForSelector:@selector(init)];
    }
}

- (void)forwardInvocation:(NSInvocation *)invocation {
    if (_target) {
        BOOL hasTimerArgument = invocation.methodSignature.numberOfArguments > 2;
        
        if (!hasTimerArgument) {
            printf("\nWarning: The selector [%s] doesn't have timer argument, you should improve it if you want to invalidate timer automatically.\n\n", [NSStringFromSelector(invocation.selector) cStringUsingEncoding:kCFStringEncodingUTF8]);
        }
        
        if (!_timer && hasTimerArgument) {
            [invocation getArgument:&_timer atIndex:2];
        }
        [invocation invokeWithTarget:_target];
        
    } else {
        [_timer invalidate];
        
        void *null = NULL;
        [invocation setReturnValue:&null];
    }
}

- (BOOL)respondsToSelector:(SEL)aSelector {
    return [_target respondsToSelector:aSelector];
}

- (BOOL)isEqual:(id)object {
    return [_target isEqual:object];
}

- (NSUInteger)hash {
    return [_target hash];
}
@end
