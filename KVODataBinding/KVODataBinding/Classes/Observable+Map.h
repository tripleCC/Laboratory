//
//  Map.h
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Observable.h"

NS_ASSUME_NONNULL_BEGIN

@interface Observable (Map)
- (Observable *)map:(id(^)(id value))block;
@end

NS_ASSUME_NONNULL_END
