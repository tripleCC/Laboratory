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

// copy from objc-runtime-new.h
struct lm_method_t {
    SEL name;
    const char *types;
    IMP imp;
};

struct lm_method_list_t {
    uint32_t entsizeAndFlags;
    uint32_t count;
    struct lm_method_t first;
};

struct lm_category_t {
    const char *name;
    Class cls;
    struct lm_method_list_t *instanceMethods;
    struct lm_method_list_t *classMethods;
    // ignore others
};

static IMP cat_getLoadMethodImp(Category cat) {
    struct lm_method_list_t *list_info = ((struct lm_category_t *)cat)->classMethods;
    if (!list_info) return NULL;
    
    struct lm_method_t *method_list = &list_info->first;
    uint32_t count = list_info->count;
    for (int i = 0; i < count; i++) {
        struct lm_method_t method =  method_list[i];
        const char *name = sel_getName(method.name);
        if (0 == strcmp(name, "load")) {
            return method.imp;
        }
    }
    
    return nil;
}

static Class cat_getClass(Category cat) {
    return ((struct lm_category_t *)cat)->cls;
}

static const char *cat_getName(Category cat) {
    return ((struct lm_category_t *)cat)->name;
}



@interface LMLoadInfo () {
    @package
    SEL _nSEL;
    IMP _oIMP;
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
    Class cls = cat_getClass(cat);
    if (self = [self initWithClass:cls]) {
        _catname = [NSString stringWithCString:cat_getName(cat) encoding:NSUTF8StringEncoding];
        _oIMP = cat_getLoadMethodImp(cat);
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


@interface LMLoadInfoWrapper () {
    @package
    NSMutableDictionary <NSNumber *, LMLoadInfo *> *_infoMap;
}
- (instancetype)initWithClass:(Class)cls;
- (void)addLoadInfo:(LMLoadInfo *)info;
- (LMLoadInfo *)findLoadInfoByImp:(IMP)imp;
- (LMLoadInfo *)findClassLoadInfo;
@end

@implementation LMLoadInfoWrapper
- (instancetype)initWithClass:(Class)cls {
    if (self = [super init]) {
        _infoMap = [NSMutableDictionary dictionary];
        _cls = cls;
    }
    return self;
}

- (void)addLoadInfo:(LMLoadInfo *)info {
    _infoMap[@((uintptr_t)info->_oIMP)] = info;
}

- (LMLoadInfo *)findLoadInfoByImp:(IMP)imp {
    return _infoMap[@((uintptr_t)imp)];
}

- (LMLoadInfo *)findClassLoadInfo {
    for (LMLoadInfo *info in _infoMap.allValues) {
        if (!info.catname) {
            return info;
        }
    }
    return nil;
}

- (NSArray<LMLoadInfo *> *)infos {
    return _infoMap.allValues;
}
@end


static SEL getRandomLoadSelector(void);
static void printLoadInfoWappers(void);
static bool shouldRejectClass(NSString *name);
static bool isSelfDefinedImage(const char *imageName);
static void hookAllLoadMethods(LMLoadInfoWrapper *infoWrapper);
static void swizzleLoadMethod(Class cls, Method method, LMLoadInfo *info);
static NSArray <LMLoadInfo *> *getNoLazyArray(const struct mach_header *mhdr);
static const struct mach_header **copyAllSelfDefinedImageHeader(unsigned int *outCount);
static void *getDataSection(const struct mach_header *mhdr, const char *sectname, size_t *bytes);

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
    return !strstr(imageName, "/Xcode.app/") &&
    !strstr(imageName, "/Library/PrivateFrameworks/") &&
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

static bool shouldRejectClass(NSString *name) {
    if (!name) return true;
    NSArray *rejectClses = @[@"__ARCLite__"];
    return [rejectClses containsObject:name];
}

static NSArray <LMLoadInfo *> *getNoLazyArray(const struct mach_header *mhdr) {
    NSMutableArray *noLazyArray = [NSMutableArray new];
    unsigned long bytes = 0;
    Category *cats = getDataSection(mhdr, "__objc_nlcatlist", &bytes);
    for (unsigned int i = 0; i < bytes / sizeof(Category); i++) {
        LMLoadInfo *info = [[LMLoadInfo alloc] initWithCategory:cats[i]];
        if (!shouldRejectClass(info.clsname)) [noLazyArray addObject:info];
    }
    
    bytes = 0;
    Class *clses = (Class *)getDataSection(mhdr, "__objc_nlclslist", &bytes);
    for (unsigned int i = 0; i < bytes / sizeof(Class); i++) {
        LMLoadInfo *info = [[LMLoadInfo alloc] initWithClass:clses[i]];
        if (!shouldRejectClass(info.clsname)) [noLazyArray addObject:info];
    }
    
    return noLazyArray;
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
    IMP imp = method_getImplementation(method);
    // The selector is not available as a parameter to this block
    IMP hookImp = imp_implementationWithBlock(^(Class cls){
        info->_start = CFAbsoluteTimeGetCurrent();
        imp();
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
        
        info->_nSEL = hookSel;
        Method hookMethod = class_getInstanceMethod(metaCls, hookSel);
        method_exchangeImplementations(method, hookMethod);
    } while(0);
}

static void hookAllLoadMethods(LMLoadInfoWrapper *infoWrapper) {
    unsigned int count = 0;
    Class metaCls = object_getClass(infoWrapper.cls);
    Method *methodList = class_copyMethodList(metaCls, &count);
    for (unsigned int i = 0; i < count; i++) {
        Method method = methodList[i];
        SEL sel = method_getName(method);
        const char *name = sel_getName(sel);
        if (!strcmp(name, "load")) {
            IMP imp = method_getImplementation(method);
            LMLoadInfo *info = [infoWrapper findLoadInfoByImp:imp];
            if (!info) {
                info = [infoWrapper findClassLoadInfo];
                if (!info) continue;
            }
            
            swizzleLoadMethod(infoWrapper.cls, method, info);
        }
    }
    free(methodList);
}

NSDictionary <NSString *, LMLoadInfoWrapper *> *prepareMeasureForMhdrList(const struct mach_header **mhdrList, unsigned int  count) {
    NSMutableDictionary <NSString *, LMLoadInfoWrapper *> *wrapperMap = [NSMutableDictionary dictionary];
    for (unsigned int i = 0; i < count; i++) {
        const struct mach_header *mhdr = mhdrList[i];
        NSArray <LMLoadInfo *> *infos = getNoLazyArray(mhdr);
        
        LMAllLoadNumber += infos.count;
        
        for (LMLoadInfo *info in infos) {
            LMLoadInfoWrapper *infoWrapper = wrapperMap[info.clsname];
            if (!infoWrapper) {
                Class cls = objc_getClass([info.clsname cStringUsingEncoding:NSUTF8StringEncoding]);
                infoWrapper = [[LMLoadInfoWrapper alloc] initWithClass:cls];
                wrapperMap[info.clsname] = infoWrapper;
            }
            [infoWrapper addLoadInfo:info];
        }
    }
    return wrapperMap;
}

__attribute__((constructor)) static void LoadMeasure_Initializer(void) {
    CFAbsoluteTime begin = CFAbsoluteTimeGetCurrent();
    unsigned int count = 0;
    const struct mach_header **mhdrList = copyAllSelfDefinedImageHeader(&count);
    NSDictionary <NSString *, LMLoadInfoWrapper *> *groupedWrapperMap = prepareMeasureForMhdrList(mhdrList, count);
    
    for (NSString *clsname in groupedWrapperMap.allKeys) {
        hookAllLoadMethods(groupedWrapperMap[clsname]);
    }
    
    free(mhdrList);
    LMLoadInfoWappers = groupedWrapperMap.allValues;
    
    CFAbsoluteTime end = CFAbsoluteTimeGetCurrent();
    printf("\n\t\t\t\t\tLoad Measure Initializer Time: %f milliseconds\n", (end - begin) * 1000);
}
