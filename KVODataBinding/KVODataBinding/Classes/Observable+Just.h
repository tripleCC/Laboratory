//
//  Observable+Just.h
//  KVODataBinding
//
//  Created by tripleCC on 6/26/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "Observable.h"

NS_ASSUME_NONNULL_BEGIN

@interface Observable (Just)
+ (Observable *)just:(id)value;
@end

NS_ASSUME_NONNULL_END
