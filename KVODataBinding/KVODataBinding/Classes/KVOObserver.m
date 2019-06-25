//
//  Observer.m
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "KVOObserver.h"

@implementation KVOObserver {
    __weak id _target;
    NSString *_keyPath;
    ObserverHandler _handler;
}
- (instancetype)initWithTarget:(id)target keyPath:(NSString *)keyPath handler:(ObserverHandler)handler {
    if (self = [super init]) {
        _target = target;
        _keyPath = keyPath;
        _handler = [handler copy];
        [_target addObserver:self forKeyPath:_keyPath options:NSKeyValueObservingOptionNew | NSKeyValueObservingOptionOld | NSKeyValueObservingOptionInitial context:nil];
    }
    
    return self;
}

- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary<NSKeyValueChangeKey,id> *)change context:(void *)context {
    id new = change[NSKeyValueChangeNewKey];
    id old = change[NSKeyValueChangeOldKey];
    _handler(new, old);
}

- (void)dealloc {
    [self dispose];
}

- (void)dispose {
    [_target removeObserver:self forKeyPath:_keyPath];
}
@end
