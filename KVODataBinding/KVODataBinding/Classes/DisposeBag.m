//
//  DisposeBag.m
//  KVODataBinding
//
//  Created by tripleCC on 6/25/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "DisposeBag.h"


@implementation Disposable {
    void (^_block)(void);
}

- (instancetype)initWithBlock:(void (^)(void))block {
    if (self = [super init]) {
        _block = block;
    }
    return self;
}

- (void)dispose {
    _block();
}

- (void)disposedBy:(DisposeBag *)bag {
    [bag addDisposable:self];
}
@end


@implementation DisposeBag {
    NSMutableArray *_disposables;
    BOOL _disposed;
}

- (instancetype)init {
    if (self = [super init]) {
        _disposables = [NSMutableArray array];
        _disposed = NO;
    }
    return self;
}

- (void)dealloc {
    [self dispose];
}

- (void)addDisposable:(Disposable *)dis {
    if (!_disposed) {
        [_disposables addObject:dis];
    } else {
        [dis dispose];
    }
}

- (void)dispose {
    for (Disposable *dis in _disposables) {
        [dis dispose];
    }
    [_disposables removeAllObjects];
    _disposed = YES;
}
@end
