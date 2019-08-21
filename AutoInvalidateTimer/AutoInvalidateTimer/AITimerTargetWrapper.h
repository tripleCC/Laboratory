//
//  AITimerTargetWrapper.h
//  AutoInvalidateTimer
//
//  Created by tripleCC on 8/21/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AITimerTargetWrapper : NSProxy
- (instancetype)initWithTarget:(id)target;
@end

NS_ASSUME_NONNULL_END
