//
//  Observer.h
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN

typedef void(^ObserverHandler)(id new, id old);

@interface KVOObserver : NSObject
- (instancetype)initWithTarget:(id)target keyPath:(NSString *)keyPath handler:(ObserverHandler)handler;
@end

NS_ASSUME_NONNULL_END
