//
//  Subject.m
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "KeyPathSubject.h"
#import "KVOObserver.h"
#import "DisposeBag.h"

@implementation KeyPathSubject {
    __weak id _target;
    NSString *_keyPath;
    NSMutableArray *_handlers;
    KVOObserver *_observer;
}

#pragma mark - LifeCycle
- (instancetype)initWithTarget:(id)target keyPath:(NSString *)keyPath {
    if (self = [super init]) {
        _target = target;
        _keyPath = keyPath;
        _handlers = [NSMutableArray array];
        [self addObserver];
    }
    return self;
}

#pragma mark - Override
- (Disposable *)subscribe:(void (^)(id _Nonnull))block {
    if (_disposed) {
        return nil;
    }
    
    [_handlers addObject:block];
    
    return [[Disposable alloc] initWithBlock:^{
        [self->_handlers removeObject:block];
    }];
}

- (void)doNext:(id)value {
    [_target setValue:value forKeyPath:_keyPath];
}

#pragma mark - DisposableProtocol
- (void)dispose {
    [super dispose];
    [_handlers removeAllObjects];
    _observer = nil;
}

#pragma mark - Private
- (void)addObserver {
    __weak typeof(self) wself = self;
    _observer = [[KVOObserver alloc] initWithTarget:_target keyPath:_keyPath handler:^(id new, id old) {
        __strong typeof(wself) sself = wself;
        if ([new isEqual:old]) {
            return;
        }
        
        [sself doHandlers:new];
    }];
}

- (void)doHandlers:(id)value {
    for (void (^handler)(id) in self->_handlers) {
        handler(value);
    }
}

@end
