//
//  Subject.h
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "Observable.h"

NS_ASSUME_NONNULL_BEGIN

@interface Subject : Observable <ObserverProtocol, DisposableProtocol> {
    @package
    BOOL _disposed;
}
- (Disposable *)bind:(id <ObserverProtocol, ObservableProtocol>)observer;
@end

NS_ASSUME_NONNULL_END
