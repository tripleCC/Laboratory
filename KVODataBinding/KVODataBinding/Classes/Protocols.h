//
//  Protocols.h
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#ifndef Protocols_h
#define Protocols_h

@protocol ObserverProtocol <NSObject>
- (void)doNext:(id)value;
@end

@protocol DisposableProtocol <NSObject>
- (void)dispose;
@end

@class Disposable;
@protocol ObservableProtocol <NSObject>
- (Disposable *)subscribe:(void (^)(id value))block;
@end
#endif /* Protocols_h */
