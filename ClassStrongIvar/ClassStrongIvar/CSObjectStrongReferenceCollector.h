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
@interface CSObjectStrongReferenceCollector : NSObject
@property (weak, nonatomic, readonly) id object;
@property (copy, nonatomic, readonly) NSArray *strongReferences;
@property (copy, nonatomic) BOOL (^stopForClsBlock)(Class cls);
- (instancetype)initWithObject:(id)object;
@end
NS_ASSUME_NONNULL_END
