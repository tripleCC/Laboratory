//
//  Observable+Filter.m
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "Observable+Filter.h"
#import "Observable+Private.h"

@interface ObservableFilter : Observable
- (instancetype)initWithSource:(Observable *)source filterBlock:(BOOL(^)(id value))block;
@end

@implementation Observable (Filter)
- (Observable *)filter:(BOOL(^)(id value))block {
    return [[ObservableFilter alloc] initWithSource:self filterBlock:block];
}
@end

@implementation ObservableFilter {
    BOOL(^_filterBlock)(id value);
}
- (instancetype)initWithSource:(Observable *)source filterBlock:(BOOL(^)(id value))block {
    if (self = [super init]) {
        self.source = source;
        _filterBlock = [block copy];
    }
    
    return self;
}

- (Disposable *)subscribe:(void (^)(id))block {
    return [self.source subscribe:^(id value) {
        if (self->_filterBlock(value)) {
            block(value);
        }
    }];
}
@end
