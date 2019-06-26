//
//  Observable+Just.m
//  KVODataBinding
//
//  Created by tripleCC on 6/26/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "Observable+Just.h"
#import "Observable+Private.h"
#import "DisposeBag.h"

@interface ObservableJust : Observable
- (instancetype)initWithValue:(id)value;
@end

@implementation Observable (Just)
+ (Observable *)just:(id)value {
    return [[ObservableJust alloc] initWithValue:value];
}
@end

@implementation ObservableJust {
    id _value;
}
- (instancetype)initWithValue:(id)value {
    if (self = [super init]) {
        _value = value;
    }
    
    return self;
}

- (Disposable *)subscribe:(void (^)(id))block {
    block(_value);
    return [[Disposable alloc] initWithBlock:^{
        self->_value = nil;
    }];
}
@end
