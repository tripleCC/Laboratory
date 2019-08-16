//
//  CSStrongReferenceCollector.m
//  ClassStrongIvar
//
//  Created by tripleCC on 8/16/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "CSStrongReferenceCollector.h"

@interface CSIvarInfo ()
@property (assign, nonatomic, readonly) BOOL isObject;

- (instancetype)initWithIvar:(Ivar)ivar;
- (id)referenceFromObject:(id)object;
@end

@implementation CSIvarInfo
- (instancetype)initWithIvar:(Ivar)ivar {
    if (self = [super init]) {
        _ivar = ivar;
        _name = @(ivar_getName(ivar));
        _offset = ivar_getOffset(ivar);
        _index = _offset / sizeof(void *);
        const char *encoding = ivar_getTypeEncoding(ivar);
        _isObject = encoding[0] == '@';
    }
    return self;
}

- (id)referenceFromObject:(id)object {
    return object_getIvar(object, _ivar);
}
@end

@implementation CSStrongReferenceCollector {
    Class _cls;
}

@synthesize strongReferences = _strongReferences;

- (instancetype)initWithObject:(id)object {
    if (self = [super init]) {
        _object = object;
        _cls = object_getClass(object);
        _ivarInfos = [self wrappedIvarList];
    }
    return self;
}

- (NSArray *)collectStrongObjectIvars {
    NSArray *objectIvars = [_ivarInfos filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(CSIvarInfo *info, NSDictionary<NSString *,id> * _Nullable bindings) {
        return info.isObject;
    }]];
    const uint8_t *layout = class_getIvarLayout(_cls);
    
    if (!layout) {
        return @[];
    }
    
    NSIndexSet *strongIvarIndexes = [self strongIvarIndexesForLayout:layout];
    NSArray *strongObjectIvars = [objectIvars filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(CSIvarInfo *info, NSDictionary<NSString *,id> * _Nullable bindings) {
        return [strongIvarIndexes containsIndex:info.index];
    }]];
    
    return strongObjectIvars;
}

- (NSIndexSet *)strongIvarIndexesForLayout:(const uint8_t *)layout {
    NSMutableIndexSet *indexes = [NSMutableIndexSet new];
    
    NSInteger strongIvarLocation = 1;
    if (_ivarInfos.count > 0) {
        strongIvarLocation = _ivarInfos.firstObject.index;
    }
    
    while (*layout != '\x00') {
        int otherIvarLength = (*layout & 0xf0) >> 4;
        int strongIvarLength = (*layout & 0xf);
        
        strongIvarLocation += otherIvarLength;
        
        [indexes addIndexesInRange:NSMakeRange(strongIvarLocation, strongIvarLength)];
        strongIvarLocation += strongIvarLength;
        
        layout++;
    }
    
    return indexes;
}

- (NSArray <CSIvarInfo *> *)wrappedIvarList {
    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList(_cls, &count);
    NSMutableArray *infos = [NSMutableArray array];
    
    for (int i = 0; i < count; i++) {
        Ivar ivar = ivars[i];
        CSIvarInfo *ivarInfo = [[CSIvarInfo alloc] initWithIvar:ivar];
        [infos addObject:ivarInfo];
    }
    
    return infos;
}

- (NSArray *)strongReferences {
    if (!_strongReferences) {
        NSMutableArray *objects = [NSMutableArray array];
        NSArray *ivars = [self collectStrongObjectIvars];
        for (CSIvarInfo *info in ivars) {
            id reference = [info referenceFromObject:_object];
            if (reference) {
                [objects addObject:reference];
            }
        }
        
        _strongReferences = objects;
    }
    
    return _strongReferences;
}
@end
