//
//  main.m
//  WeakArray
//
//  Created by tripleCC on 8/16/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

@interface WAWeakItem : NSProxy
@property (weak, nonatomic, readonly) id value;
- (instancetype)initWithValue:(id)value;
@end
@implementation WAWeakItem
- (instancetype)initWithValue:(id)value {
    _value = value;
    
    return self;
}

- (NSUInteger)hash {
    return [_value hash];
}

- (BOOL)isEqual:(id)object {
    return [_value isEqual:object];
}

- (NSString *)description {
    return [_value description];
}
@end

@interface WAReleaseHandler : NSObject
@property (copy, nonatomic, readonly) NSArray *blocks;
- (instancetype)initWithBlock:(void (^)(void))block;
@end
@implementation WAReleaseHandler {
    NSMutableArray *_blocks;
}
- (instancetype)initWithBlock:(void (^)(void))block {
    if (self = [super init]) {
        _blocks = [NSMutableArray arrayWithObject:block];
    }
    
    return self;
}

- (void)addHandler:(void (^)(void))block {
    [_blocks addObject:block];
}

- (void)dealloc {
    for (void (^block)(void) in _blocks) {
        block();
    }
}
@end

@interface NSObject (WAWeakArray)
@property (strong, nonatomic) WAReleaseHandler *wa_releaseHandler;
@end
@implementation NSObject (WAWeakArray)
- (void)setWa_releaseHandler:(WAReleaseHandler *)wa_releaseHandler {
    objc_setAssociatedObject(self, _cmd, wa_releaseHandler, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

- (WAReleaseHandler *)wa_releaseHandler {
    return objc_getAssociatedObject(self, @selector(setWa_releaseHandler:));
}
@end

@interface WAWeakArray<ObjectType> : NSObject
- (void)addObject:(ObjectType)anObject;
- (void)removeObjectAtIndex:(NSUInteger)index;
- (void)removeObject:(ObjectType)anObject;
@end
@implementation WAWeakArray {
    NSMutableArray *_array;
}

- (instancetype)init {
    if (self = [super init]) {
        _array = [NSMutableArray array];
    }
    return self;
}

- (void)addObject:(id)anObject {
    WAWeakItem *item = [[WAWeakItem alloc] initWithValue:anObject];
    
    void (^block)(void) = ^{
        @synchronized (self) { // anObject 可能在后台线程释放
            [self removeObject:item];
        }
    };
    
    WAReleaseHandler *handler = [anObject wa_releaseHandler];
    if (handler) {
        [handler addHandler:block];
    } else {
        [anObject setWa_releaseHandler:[[WAReleaseHandler alloc] initWithBlock:block]];
    }
    
    [_array addObject:item];
}

- (void)removeObject:(id)anObject {
    NSUInteger index = [_array indexOfObject:anObject];
    if (index != NSNotFound) {
        [self removeObjectAtIndex:index];
    }
}

- (void)removeObjectAtIndex:(NSUInteger)index {
    [_array removeObjectAtIndex:index];
}

- (NSString *)description {
    return [_array description];
}
@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        WAWeakArray *wa = [WAWeakArray new];
        @autoreleasepool {
            NSObject *o = [NSObject new];
            [wa addObject:o];
            [wa addObject:o];
            NSLog(@"%@", wa);
        }
        NSLog(@"%@", wa);
    }
    return 0;
}
