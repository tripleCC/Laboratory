//
//  WAWeakArray.h
//  WeakArray
//
//  Created by tripleCC on 8/16/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WAWeakArray<ObjectType> : NSObject <NSFastEnumeration>
- (void)addObject:(ObjectType)anObject;
- (void)removeObjectAtIndex:(NSUInteger)index;
- (void)removeObject:(ObjectType)anObject;
@end
NS_ASSUME_NONNULL_END
