//
//  SRBlockStrongReferenceCollector.h
//  BlockStrongReferenceObject
//
//  Created by tripleCC on 8/15/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SRLayoutItem : NSObject
@property (assign, nonatomic, readonly) unsigned int type;
@property (assign, nonatomic, readonly) NSInteger count;
@end

@interface SRCapturedLayoutInfo : NSObject
@property (copy, nonatomic, readonly) NSArray <SRLayoutItem *> *layoutItems;
@end

@interface SRBlockStrongReferenceCollector : NSObject
@property (weak, nonatomic, readonly) id block;
@property (strong, nonatomic, readonly) NSEnumerator *strongReferences;
@property (strong, nonatomic, readonly) SRCapturedLayoutInfo *blockLayoutInfo;
@property (copy, nonatomic, readonly) NSArray <SRCapturedLayoutInfo *> *blockByrefLayoutInfos;
- (instancetype)initWithBlock:(__weak id)block;
@end
NS_ASSUME_NONNULL_END
