//
//  Map.m
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#import "Observable+Private.h"
#import "Observable+Map.h"
#import "DisposeBag.h"

@interface ObservableMap : Observable
- (instancetype)initWithSource:(Observable *)source mapBlock:(id(^)(id value))mapBlock;
@end

@implementation Observable(Map)
- (Observable *)map:(id(^)(id value))block {
    return [[ObservableMap alloc] initWithSource:self mapBlock:block];
}
@end

@implementation ObservableMap {
    id(^_mapBlock)(id value);
}
- (instancetype)initWithSource:(Observable *)source mapBlock:(id(^)(id value))mapBlock {
    if (self = [super init]) {
        self.source = source;
        _mapBlock = [mapBlock copy];
    }
    
    return self;
}

- (Disposable *)subscribe:(void (^)(id _Nonnull))block {
    Disposable *dis = [self.source subscribe:^(id  _Nonnull value) {
        block(self->_mapBlock(value));
    }];
    return [[Disposable alloc] initWithBlock:^{
        [dis dispose];
    }];
}
@end
