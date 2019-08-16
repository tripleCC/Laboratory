//
//  CSStrongReferenceCollector.h
//  ClassStrongIvar
//
//  Created by tripleCC on 8/16/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

NS_ASSUME_NONNULL_BEGIN

@interface CSIvarInfo : NSObject
@property (copy, nonatomic, readonly) NSString *name;
@property (assign, nonatomic, readonly) ptrdiff_t offset;
@property (assign, nonatomic, readonly) NSInteger index;
@property (assign, nonatomic, readonly) Ivar ivar;
@end

@interface CSStrongReferenceCollector : NSObject
@property (weak, nonatomic, readonly) id object;
@property (copy, nonatomic, readonly) NSArray *strongReferences;
@property (copy, nonatomic, readonly) NSArray <CSIvarInfo *> *ivarInfos;
- (instancetype)initWithObject:(id)object;
@end
NS_ASSUME_NONNULL_END
