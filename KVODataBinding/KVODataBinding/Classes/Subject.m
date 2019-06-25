//
//  Subject.m
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "Subject.h"
#import "DisposeBag.h"
#import "Observable+Binding.h"

@implementation Subject
#pragma mark - LifeCycle
- (instancetype)init {
    if (self = [super init]) {
        _disposed = NO;
    }
    return self;
}

#pragma mark - Public
- (Disposable *)bind:(id <ObserverProtocol, ObservableProtocol>)observer {
    Disposable *dis1 = [self bindTo:observer];
    Disposable *dis2 = [observer subscribe:^(id value) {
        [self doNext:value];
    }];
    return [[Disposable alloc] initWithBlock:^{
        [dis1 dispose];
        [dis2 dispose];
    }];
}

#pragma mark - ObserverProtocol
- (void)doNext:(id)value {}

#pragma mark - DisposableProtocol
- (void)dispose {
    _disposed = YES;
}
@end
