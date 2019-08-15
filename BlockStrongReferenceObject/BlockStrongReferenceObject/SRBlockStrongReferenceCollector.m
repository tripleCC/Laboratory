//
//  SRBlockStrongReferenceCollector.m
//  BlockStrongReferenceObject
//
//  Created by tripleCC on 8/15/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import "SRBlockStrongReferenceCollector.h"

enum {
    SR_BLOCK_DEALLOCATING =      (0x0001),  // runtime
    SR_BLOCK_REFCOUNT_MASK =     (0xfffe),  // runtime
    SR_BLOCK_NEEDS_FREE =        (1 << 24), // runtime
    SR_BLOCK_HAS_COPY_DISPOSE =  (1 << 25), // compiler
    SR_BLOCK_HAS_CTOR =          (1 << 26), // compiler: helpers have C++ code
    SR_BLOCK_IS_GC =             (1 << 27), // runtime
    SR_BLOCK_IS_GLOBAL =         (1 << 28), // compiler
    SR_BLOCK_USE_STRET =         (1 << 29), // compiler: undefined if !BLOCK_HAS_SIGNATURE
    SR_BLOCK_HAS_SIGNATURE  =    (1 << 30), // compiler
    SR_BLOCK_HAS_EXTENDED_LAYOUT=(1 << 31)  // compiler
};

enum {
    // Byref refcount must use the same bits as Block_layout's refcount.
    // BLOCK_DEALLOCATING =      (0x0001),  // runtime
    // BLOCK_REFCOUNT_MASK =     (0xfffe),  // runtime
    SR_BLOCK_BYREF_LAYOUT_MASK =       (0xf << 28), // compiler
    SR_BLOCK_BYREF_LAYOUT_EXTENDED =   (  1 << 28), // compiler
    SR_BLOCK_BYREF_LAYOUT_NON_OBJECT = (  2 << 28), // compiler
    SR_BLOCK_BYREF_LAYOUT_STRONG =     (  3 << 28), // compiler
    SR_BLOCK_BYREF_LAYOUT_WEAK =       (  4 << 28), // compiler
    SR_BLOCK_BYREF_LAYOUT_UNRETAINED = (  5 << 28), // compiler
    
    SR_BLOCK_BYREF_IS_GC =             (  1 << 27), // runtime
    
    SR_BLOCK_BYREF_HAS_COPY_DISPOSE =  (  1 << 25), // compiler
    SR_BLOCK_BYREF_NEEDS_FREE =        (  1 << 24), // runtime
};

typedef enum SR_BLOCK_LAYOUT {
    SR_BLOCK_LAYOUT_NON_OBJECT_BYTES = 1,    // N bytes non-objects
    SR_BLOCK_LAYOUT_NON_OBJECT_WORDS = 2,    // N words non-objects
    SR_BLOCK_LAYOUT_STRONG           = 3,    // N words strong pointers
    SR_BLOCK_LAYOUT_BYREF            = 4,    // N words byref pointers
    SR_BLOCK_LAYOUT_WEAK             = 5,    // N words weak pointers
} SRBlockLayoutType;

struct sr_block_byref {
    void *isa;
    struct sr_block_byref *forwarding;
    volatile int32_t flags; // contains ref count
    uint32_t size;
};

struct sr_block_byref_2 {
    // requires BLOCK_BYREF_HAS_COPY_DISPOSE
    void (*byref_keep)(struct sr_block_byref *dst, struct sr_block_byref *src);
    void (*byref_destroy)(struct sr_block_byref *);
};

struct sr_block_byref_3 {
    // requires BLOCK_BYREF_LAYOUT_EXTENDED
    const char *layout;
};

static void **sr_block_byref_captured(struct sr_block_byref *a_byref) {
    uint8_t *block_byref = (uint8_t *)a_byref;
    block_byref += sizeof(struct sr_block_byref);
    if (a_byref->flags & SR_BLOCK_BYREF_HAS_COPY_DISPOSE) {
        block_byref += sizeof(struct sr_block_byref_2);
    }
    return (void **)block_byref;
}

static const char *sr_block_byref_extended_layout(struct sr_block_byref *a_byref) {
    if (!(a_byref->flags & SR_BLOCK_BYREF_LAYOUT_EXTENDED)) return NULL;
    const char *layout = (char *)*sr_block_byref_captured(a_byref);
    return layout;
}

struct sr_block_descriptor_1 {
    uintptr_t reserved;
    uintptr_t size;
};

struct sr_block_descriptor_2 {
    // requires BLOCK_HAS_COPY_DISPOSE
    void (*copy)(void *dst, void *src);
    void (*dispose)(void *);
};

struct sr_block_descriptor_3 {
    // requires BLOCK_HAS_SIGNATURE
    const char *signature;
    const char *layout;     // contents depend on BLOCK_HAS_EXTENDED_LAYOUT
};

struct sr_block_layout {
    void *isa;
    volatile int32_t flags;
    int32_t reserved;
    void (*invoke)(void *, ...);
    struct sr_block_descriptor_1 *descriptor;
    char captured[0];
    /* Imported variables. */
};

static struct sr_block_descriptor_3 * _sr_block_descriptor_3(struct sr_block_layout *aBlock)
{
    if (!(aBlock->flags & SR_BLOCK_HAS_SIGNATURE)) return NULL;
    uint8_t *desc = (uint8_t *)aBlock->descriptor;
    desc += sizeof(struct sr_block_descriptor_1);
    if (aBlock->flags & SR_BLOCK_HAS_COPY_DISPOSE) {
        desc += sizeof(struct sr_block_descriptor_2);
    }
    return (struct sr_block_descriptor_3 *)desc;
}


static const char *sr_block_extended_layout(struct sr_block_layout *block) {
    if (!(block->flags & SR_BLOCK_HAS_EXTENDED_LAYOUT)) return NULL;
    struct sr_block_descriptor_3 *desc3 = _sr_block_descriptor_3(block);
    if (!desc3) return NULL;
    
    if (!desc3->layout) return "";
    return desc3->layout;
}

@interface SRLayoutItem ()
- (instancetype)initWithType:(unsigned int)type count:(NSInteger)count;
- (NSHashTable *)objectsForBeginAddress:(void *)address;
@end

@implementation SRLayoutItem{
    unsigned int _type;
    NSInteger _count;
}

- (instancetype)initWithType:(unsigned int)type count:(NSInteger)count {
    if (self = [super init]) {
        _type = type;
        _count = count;
    }
    return self;
}

- (NSHashTable *)objectsForBeginAddress:(void *)address {
    if (!address) return NULL;
    
    NSHashTable *references = [NSHashTable weakObjectsHashTable];
    uintptr_t *begin = (uintptr_t *)address;
    
    for (int i = 0; i < _count; i++, begin++) {
        id object = (__bridge id _Nonnull)(*(void **)begin);
        if (object) [references addObject:object];
    }
    return references;
};

- (NSString *)description {
    return [NSString stringWithFormat:@"type: %d, count: %ld", _type, _count];
}
@end

@interface SRCapturedLayoutInfo ()
- (void)addItemWithType:(unsigned int)type count:(NSInteger)count;
@end

@implementation SRCapturedLayoutInfo {
    NSMutableArray <SRLayoutItem *> *_layoutItems;
}
- (instancetype)init {
    if (self = [super init]) {
        _layoutItems = [NSMutableArray array];
    }
    return self;
}

+ (instancetype)infoForLayoutEncode:(const char *)layout {
    if (!layout) return nil;
    
    SRCapturedLayoutInfo *info = [SRCapturedLayoutInfo new];
    
    if ((uintptr_t)layout < (1 << 12)) {
        uintptr_t inlineLayout = (uintptr_t)layout;
        [info addItemWithType:SR_BLOCK_LAYOUT_STRONG count:(inlineLayout & 0xf00) >> 8];
        [info addItemWithType:SR_BLOCK_LAYOUT_BYREF count:(inlineLayout & 0xf0) >> 4];
        [info addItemWithType:SR_BLOCK_LAYOUT_WEAK count:inlineLayout & 0xf];
    } else {
        while (layout && *layout != '\x00') {
            unsigned int type = (*layout & 0xf0) >> 4;
            unsigned int count = (*layout & 0xf) + 1;
            
            [info addItemWithType:type count:count];
            layout++;
        }
    }
    
    return info;
}

- (NSArray <SRLayoutItem *> *)itemsForType:(unsigned int)type {
    NSPredicate *predicate = [NSPredicate predicateWithFormat:@"type = %u", type];
    return [_layoutItems filteredArrayUsingPredicate:predicate];
}

- (void)addItemWithType:(unsigned int)type count:(NSInteger)count {
    if (count <= 0) return;
    
    SRLayoutItem *item = [[SRLayoutItem alloc] initWithType:type count:count];
    [_layoutItems addObject:item];
}

- (NSArray <SRLayoutItem *> *)layoutItems {
    return [_layoutItems copy];
}

- (NSString *)description {
    NSMutableString *description = [NSMutableString stringWithString:@"\n"];
    for (SRLayoutItem *item in _layoutItems) {
        [description appendString:[NSString stringWithFormat:@"%@\n", item]];
    }
    return description;
}
@end

static void SRAddObjectsFromHashTable(NSHashTable *dst, NSHashTable *ori) {
    for (id object in ori.objectEnumerator) {
        [dst addObject:object];
    }
};

@implementation SRBlockStrongReferenceCollector {
    id _block;
    NSEnumerator *_strongReferences;
    NSMutableArray *_blockByrefLayoutInfos;
    SRCapturedLayoutInfo *_blockLayoutInfo;
}

- (instancetype)initWithBlock:(id)block {
    if (self = [super init]) {
        _block = block;
        _blockByrefLayoutInfos = [NSMutableArray array];
    }
    return self;
}

- (NSEnumerator *)exploreLayoutInfos {
    NSHashTable *objects = [self strongReferencesForBlockLayout:(__bridge void *)(_block)];
    return [objects objectEnumerator];
}

- (NSHashTable *)strongReferencesForBlockLayout:(void *)iLayout {
    if (!iLayout) return nil;
    
    struct sr_block_layout *aLayout = (struct sr_block_layout *)iLayout;
    const char *extenedLayout = sr_block_extended_layout(aLayout);
    _blockLayoutInfo = [SRCapturedLayoutInfo infoForLayoutEncode:extenedLayout];
    
    NSHashTable *references = [NSHashTable weakObjectsHashTable];
    uintptr_t *begin = (uintptr_t *)aLayout->captured;
    for (SRLayoutItem *item in _blockLayoutInfo.layoutItems) {
        switch (item.type) {
            case SR_BLOCK_LAYOUT_STRONG: {
                NSHashTable *objects = [item objectsForBeginAddress:begin];
                SRAddObjectsFromHashTable(references, objects);
                begin += item.count;
            } break;
            case SR_BLOCK_LAYOUT_BYREF: {
                for (int i = 0; i < item.count; i++, begin++) {
                    struct sr_block_byref *aByref = *(struct sr_block_byref **)begin;
                    NSHashTable *objects = [self strongReferenceForBlockByref:aByref];
                    SRAddObjectsFromHashTable(references, objects);
                }
            } break;
            case SR_BLOCK_LAYOUT_NON_OBJECT_BYTES: {
                begin = (uintptr_t *)((uintptr_t)begin + item.count);
            } break;
            default: {
                begin += item.count;
            } break;
        }
    }
    
    return references;
}

- (NSHashTable *)strongReferenceForBlockByref:(void *)iByref {
    if (!iByref) return nil;
    
    struct sr_block_byref *aByref = (struct sr_block_byref *)iByref;
    NSHashTable *references = [NSHashTable weakObjectsHashTable];
    int32_t flag = aByref->flags & SR_BLOCK_BYREF_LAYOUT_MASK;
    
    switch (flag) {
        case SR_BLOCK_BYREF_LAYOUT_STRONG: {
            void **begin = sr_block_byref_captured(aByref);
            id object = (__bridge id _Nonnull)(*(void **)begin);
            if (object) [references addObject:object];
        } break;
        case SR_BLOCK_BYREF_LAYOUT_EXTENDED: {
            const char *layout = sr_block_byref_extended_layout(aByref);
            SRCapturedLayoutInfo *info = [SRCapturedLayoutInfo infoForLayoutEncode:layout];
            [_blockByrefLayoutInfos addObject:info];
            
            uintptr_t *begin = (uintptr_t *)sr_block_byref_captured(aByref) + 1;
            for (SRLayoutItem *item in info.layoutItems) {
                switch (item.type) {
                    case SR_BLOCK_LAYOUT_NON_OBJECT_BYTES: {
                        begin = (uintptr_t *)((uintptr_t)begin + item.count);
                    } break;
                    case SR_BLOCK_LAYOUT_STRONG: {
                        NSHashTable *objects = [item objectsForBeginAddress:begin];
                        SRAddObjectsFromHashTable(references, objects);
                        begin += item.count;
                    } break;
                    default: {
                        begin += item.count;
                    } break;
                }
            }
        } break;
        default: break;
    }
    
    return references;
}

- (NSArray<SRCapturedLayoutInfo *> *)blockByrefLayoutInfos {
    if (!_blockByrefLayoutInfos) [self exploreLayoutInfos];

    return _blockByrefLayoutInfos;
}

- (SRCapturedLayoutInfo *)blockLayoutInfo {
    if (!_blockLayoutInfo) [self exploreLayoutInfos];
    
    return _blockLayoutInfo;
}

- (NSEnumerator *)strongReferences {
    if (!_strongReferences) _strongReferences = [self exploreLayoutInfos];
    
    return _strongReferences;
}
@end
