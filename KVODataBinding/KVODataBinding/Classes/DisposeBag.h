//
//  DisposeBag.h
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Observable.h"
#import "Protocols.h"

NS_ASSUME_NONNULL_BEGIN

@class DisposeBag;

@interface Disposable : NSObject <DisposableProtocol>
- (instancetype)initWithBlock:(void (^ _Nonnull)(void))block;
- (void)disposedBy:(DisposeBag *)bag;
@end

@interface DisposeBag : NSObject
- (void)addDisposable:(Disposable *)dis;
@end

NS_ASSUME_NONNULL_END
