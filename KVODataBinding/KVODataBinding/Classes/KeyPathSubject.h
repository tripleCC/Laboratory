//
//  Subject.h
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Observable.h"
#import "Protocols.h"
#import "Subject.h"

NS_ASSUME_NONNULL_BEGIN

@interface KeyPathSubject : Subject <DisposableProtocol>
- (instancetype)initWithTarget:(id)target keyPath:(NSString *)keyPath;
@end

NS_ASSUME_NONNULL_END
