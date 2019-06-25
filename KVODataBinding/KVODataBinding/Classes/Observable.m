//
//  Observable.m
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "Observable.h"

@interface Observable ()
@property (strong, nonatomic) Observable *source;
@end

@implementation Observable
- (instancetype)init {
    if (self = [super init]) {
    }
    return self;
}

- (Disposable *)subscribe:(void (^)(id value))block {
    [NSException raise:@"Abstract Method" format:@"Abstract Method"];
    return nil;
}

@end
