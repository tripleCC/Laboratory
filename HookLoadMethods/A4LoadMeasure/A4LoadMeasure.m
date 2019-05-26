//
//  A4LoadMeasure.m
//  A4LoadMeasure
//
//  Created by tripleCC on 5/21/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#include <objc/message.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <mach-o/getsect.h>
#import "A4LoadMeasure.h"

NSArray <LMLoadInfoWrapper *> *LMLoadInfoWappers = nil;
static NSInteger LMAllLoadNumber = 0;

@interface LMLoadInfoWrapper () {
    @package
    NSMutableArray <LMLoadInfo *> *_infos;
}
- (instancetype)initWithClass:(Class)cls;
@end

@implementation LMLoadInfoWrapper
- (instancetype)initWithClass:(Class)cls {
    if (self = [super init]) {
        _infos = [NSMutableArray array];
        _cls = cls;
    }
    return self;
}

- (void)insertLoadInfo:(LMLoadInfo *)info {
    [_infos insertObject:info atIndex:0];
}
@end

@interface LMLoadInfo () {
    @package
    SEL _sel;
    CFAbsoluteTime _start;
    CFAbsoluteTime _end;
}

- (instancetype)initWithClass:(Class)cls;
- (instancetype)initWithCategory:(Category)cat;
@end

@implementation LMLoadInfo
- (instancetype)initWithClass:(Class)cls {
    if (!cls) return nil;
    if (self = [super init]) {
        // DO NOT use cat->cls! cls may be cat->cls->isa instead
        // 对于 category ，既然无法 remapClass (私有函数) ，就直接拿 cat->cls->isa 的 name
        // 对于 class ，为了和 category 统一，直接取 meta class name
        // 由于 meta name 和 name 相同，反射时再根据 meta name 取 class
        _clsname = [NSString stringWithCString:object_getClassName(cls) encoding:NSUTF8StringEncoding];
    }
    return self;
}
- (instancetype)initWithCategory:(Category)cat {
    if (!cat) return nil;
    Class cls = (__bridge Class)((void *)cat + sizeof(char *));
    if (self = [self initWithClass:cls]) {
        _catname = [NSString stringWithCString:*(char **)cat encoding:NSUTF8StringEncoding];
    }
    return self;
}
- (CFAbsoluteTime)duration {
    return _end - _start;
}

- (NSString *)description {
    return [NSString stringWithFormat:@"%@(%@) duration: %f milliseconds", _clsname, _catname, (_end - _start) * 1000];
}
@end

static SEL getRandomLoadSelector(void);
static void printLoadInfoWappers(void);
static bool isSelfDefinedImage(const char *imageName);
static void hookAllLoadMethods(LMLoadInfoWrapper *infoWrapper);
static void swizzleLoadMethod(Class cls, Method method, LMLoadInfo *info);
static NSArray <LMLoadInfo *> *getNoLazyArray(const struct mach_header *mhdr);
static const struct mach_header **copyAllSelfDefinedImageHeader(unsigned int *outCount);
static NSArray <LMLoadInfoWrapper *> *prepareMeasureForImageHeader(const struct mach_header *mhdr);
static void *getDataSection(const struct mach_header *mhdr, const char *sectname, size_t *bytes);
static NSDictionary <NSString *, LMLoadInfoWrapper *> *groupNoLazyArray(NSArray <LMLoadInfo *> *noLazyArray);

static void *getDataSection(const struct mach_header *mhdr, const char *sectname, size_t *bytes) {
    void *data = getsectiondata((void *)mhdr, "__DATA", sectname, bytes);
    if (!data) {
        data = getsectiondata((void *)mhdr, "__DATA_CONST", sectname, bytes);
    }
    if (!data) {
        data = getsectiondata((void *)mhdr, "__DATA_DIRTY", sectname, bytes);
    }
    
    return data;
}

static bool isSelfDefinedImage(const char *imageName) {
    return !strstr(imageName, "/Developer/Platforms/") &&
        !strstr(imageName, "/System/Library/") &&
        !strstr(imageName, "/usr/lib/");
}

static const struct mach_header **copyAllSelfDefinedImageHeader(unsigned int *outCount) {
    unsigned int imageCount = _dyld_image_count();
    unsigned int count = 0;
    const struct mach_header **mhdrList = NULL;
    
    if (imageCount > 0) {
        mhdrList = (const struct mach_header **)malloc(sizeof(struct mach_header *) * imageCount);
        for (unsigned int i = 0; i < imageCount; i++) {
            const char *imageName = _dyld_get_image_name(i);
            if (isSelfDefinedImage(imageName)) {
                const struct mach_header *mhdr = _dyld_get_image_header(i);
                mhdrList[count++] = mhdr;
            }
        }
        mhdrList[count] = NULL;
    }
    
    if (outCount) *outCount = count;
    
    return mhdrList;
}

__unused static const struct mach_header *getImageHeaderForName(const char *name) {
    unsigned int count = _dyld_image_count();
    for (unsigned int i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (!strcmp(name, imageName)) {
            return _dyld_get_image_header(i);
        }
    }
    return NULL;
}

static SEL getRandomLoadSelector(void) {
    return NSSelectorFromString([NSString stringWithFormat:@"_lh_hooking_%x_load", arc4random()]);
}

static NSArray <LMLoadInfo *> *getNoLazyArray(const struct mach_header *mhdr) {
    NSMutableArray *noLazyArray = [NSMutableArray new];
    unsigned long bytes = 0;
    Class *clses = (Class *)getDataSection(mhdr, "__objc_nlclslist", &bytes);
    for (unsigned int i = 0; i < bytes / sizeof(Class); i++) {
        LMLoadInfo *info = [[LMLoadInfo alloc] initWithClass:clses[i]];
        [noLazyArray addObject:info];
    }
    
    bytes = 0;
    Category *cats = getDataSection(mhdr, "__objc_nlcatlist", &bytes);
    for (unsigned int i = 0; i < bytes / sizeof(Category); i++) {
        LMLoadInfo *info = [[LMLoadInfo alloc] initWithCategory:cats[i]];
        [noLazyArray addObject:info];
    }
    
    return noLazyArray;
}

static NSDictionary <NSString *, LMLoadInfoWrapper *> *groupNoLazyArray(NSArray <LMLoadInfo *> *noLazyArray) {
    NSMutableDictionary *noLazyMap = [NSMutableDictionary dictionary];
    for (LMLoadInfo *info in noLazyArray) {
        LMLoadInfoWrapper *infoWrapper = noLazyMap[info.clsname];
        if (!infoWrapper) {
            Class cls = objc_getClass([info.clsname cStringUsingEncoding:NSUTF8StringEncoding]);
            infoWrapper = [[LMLoadInfoWrapper alloc] initWithClass:cls];
        }
        [infoWrapper insertLoadInfo:info];
        noLazyMap[info.clsname] = infoWrapper;
    }
    
    return noLazyMap;
}

static void printLoadInfoWappers(void) {
    NSMutableArray *infos = [NSMutableArray array];
    for (LMLoadInfoWrapper *infoWrapper in LMLoadInfoWappers) {
        [infos addObjectsFromArray:infoWrapper.infos];
    }
    NSSortDescriptor *descriptor = [NSSortDescriptor sortDescriptorWithKey:@"duration" ascending:NO];
    [infos sortUsingDescriptors:@[descriptor]];
    
    CFAbsoluteTime totalDuration = 0;
    for (LMLoadInfo *info in infos) {
        totalDuration += info.duration;
    }
    printf("\n\t\t\t\t\t\t\tTotal load time: %f milliseconds", totalDuration * 1000);
    for (LMLoadInfo *info in infos) {
        NSString *clsname = [NSString stringWithFormat:@"%@", info.clsname];
        if (info.catname) clsname = [NSString stringWithFormat:@"%@(%@)", clsname, info.catname];
        printf("\n%40s load time: %f milliseconds", [clsname cStringUsingEncoding:NSUTF8StringEncoding], info.duration * 1000);
    }
    printf("\n");
}

__unused static void replaceLoadImplementation(Method method, LMLoadInfo *info) {
    // The selector is not available as a parameter to this block
    IMP hookImp = imp_implementationWithBlock(^(Class cls){
        info->_start = CFAbsoluteTimeGetCurrent();
        ((void (*)(Class, SEL))objc_msgSend)(cls, @selector(load));
        info->_end = CFAbsoluteTimeGetCurrent();
        if (!--LMAllLoadNumber) printLoadInfoWappers();
    });
    
    method_setImplementation(method, hookImp);
}

static void swizzleLoadMethod(Class cls, Method method, LMLoadInfo *info) {
retry:
    do {
        SEL hookSel = getRandomLoadSelector();
        Class metaCls = object_getClass(cls);
        IMP hookImp = imp_implementationWithBlock(^ {
            info->_start = CFAbsoluteTimeGetCurrent();
            ((void (*)(Class, SEL))objc_msgSend)(cls, hookSel);
            info->_end = CFAbsoluteTimeGetCurrent();
            if (!--LMAllLoadNumber) printLoadInfoWappers();
        });
        
        BOOL didAddMethod = class_addMethod(metaCls, hookSel, hookImp, method_getTypeEncoding(method));
        if (!didAddMethod) goto retry;
        
        info->_sel = hookSel;
        Method hookMethod = class_getInstanceMethod(metaCls, hookSel);
        method_exchangeImplementations(method, hookMethod);
    } while(0);
}

static void hookAllLoadMethods(LMLoadInfoWrapper *infoWrapper) {
    unsigned int count = 0;
    Class metaCls = object_getClass(infoWrapper.cls);
    Method *methodList = class_copyMethodList(metaCls, &count);
    for (unsigned int i = 0, j = 0; i < count; i++) {
        Method method = methodList[i];
        SEL sel = method_getName(method);
        const char *name = sel_getName(sel);
        if (!strcmp(name, "load")) {
            LMLoadInfo *info = nil;
            if (j > infoWrapper.infos.count - 1) {
                info = [[LMLoadInfo alloc] initWithClass:infoWrapper.cls];
                [infoWrapper insertLoadInfo:info];
                LMAllLoadNumber++;
            } else {
                info = infoWrapper.infos[j];
            }
            ++j;
            swizzleLoadMethod(infoWrapper.cls, method, info);
        }
    }
    free(methodList);
}

static NSArray <LMLoadInfoWrapper *> *prepareMeasureForImageHeader(const struct mach_header *mhdr) {
    NSArray <LMLoadInfo *> *infos = getNoLazyArray(mhdr);
    NSDictionary <NSString *, LMLoadInfoWrapper *> *groupedInfos = groupNoLazyArray(infos);
    
    LMAllLoadNumber += infos.count;
    for (NSString *clsname in groupedInfos.allKeys) {
        LMLoadInfoWrapper *infoWrapper = groupedInfos[clsname];
        hookAllLoadMethods(infoWrapper);
    }
    
    return groupedInfos.allValues;
}

__attribute__((constructor)) static void LoadMeasure_Initializer(void) {
    unsigned int count = 0;
    const struct mach_header **mhdrList = copyAllSelfDefinedImageHeader(&count);
    NSMutableArray <LMLoadInfoWrapper *> *allInfoWappers = [NSMutableArray array];
    
    for (unsigned int i = 0; i < count; i++) {
        const struct mach_header *mhdr = mhdrList[i];
        NSArray <LMLoadInfoWrapper *> *infoWrappers = prepareMeasureForImageHeader(mhdr);
        [allInfoWappers addObjectsFromArray:infoWrappers];
    }
    
    free(mhdrList);
    LMLoadInfoWappers = allInfoWappers;
}
