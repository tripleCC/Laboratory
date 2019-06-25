//
//  Observable+Binding.m
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "Observable+Binding.h"

@implementation Observable (Binding)
- (Disposable *)bindTo:(id <ObserverProtocol>)observer {
    return [self subscribe:^(id  _Nonnull value) {
        [observer doNext:value];
    }];
}
@end
