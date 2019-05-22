//
//  LoadHook.m
//  HookFramework
//
//  Created by tripleCC on 5/21/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#include <objc/message.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <mach-o/getsect.h>
#import "LoadHook.h"

NSArray <LHLoadInfoWrapper *> *LHLoadInfoWappers = nil;
static NSInteger LHAllLoadNumber = 0;

@interface LHLoadInfo () {
    @package
    SEL _sel;
    CFAbsoluteTime _start;
    CFAbsoluteTime _end;
}

- (instancetype)initWithClass:(Class)cls;
- (instancetype)initWithCategory:(Category)cat;
@end

@interface LHLoadInfoWrapper () {
    @package
    NSMutableArray <LHLoadInfo *> *_infos;
}
- (instancetype)initWithClass:(Class)cls;
@end

@implementation LHLoadInfoWrapper
- (instancetype)initWithClass:(Class)cls {
    if (self = [super init]) {
        _infos = [NSMutableArray array];
        _cls = cls;
    }
    return self;
}

- (void)insertLoadInfo:(LHLoadInfo *)info {
    [_infos insertObject:info atIndex:0];
}
@end

@implementation LHLoadInfo
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

static const struct mach_header *getImageHeaderForName(const char *name) {
    unsigned int count = _dyld_image_count();
    for (unsigned int i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (!strcmp(name, imageName)) {
            return _dyld_get_image_header(i);
        }
    }
    return NULL;
}

static SEL randomLoadSelector(void) {
    return NSSelectorFromString([NSString stringWithFormat:@"_lh_hooking_%x_load", arc4random()]);
}

static NSArray <LHLoadInfo *> *getNoLazyArray(const struct mach_header *mhdr) {
    NSMutableArray *noLazyArray = [NSMutableArray new];
    unsigned long bytes = 0;
    Class *clses = (Class *)getDataSection(mhdr, "__objc_nlclslist", &bytes);
    for (unsigned int i = 0; i < bytes / sizeof(Class); i++) {
        LHLoadInfo *info = [[LHLoadInfo alloc] initWithClass:clses[i]];
        [noLazyArray addObject:info];
    }
    
    bytes = 0;
    Category *cats = getDataSection(mhdr, "__objc_nlcatlist", &bytes);
    for (unsigned int i = 0; i < bytes / sizeof(Category); i++) {
        LHLoadInfo *info = [[LHLoadInfo alloc] initWithCategory:cats[i]];
        [noLazyArray addObject:info];
    }
    
    return noLazyArray;
}

static NSDictionary <NSString *, LHLoadInfoWrapper *> *groupNoLazyArray(NSArray <LHLoadInfo *> *noLazyArray) {
    NSMutableDictionary *noLazyMap = [NSMutableDictionary dictionary];
    for (LHLoadInfo *info in noLazyArray) {
        LHLoadInfoWrapper *infoWrapper = noLazyMap[info.clsname];
        if (!infoWrapper) {
            Class cls = objc_getClass([info.clsname cStringUsingEncoding:NSUTF8StringEncoding]);
            infoWrapper = [[LHLoadInfoWrapper alloc] initWithClass:cls];
        }
        [infoWrapper insertLoadInfo:info];
        noLazyMap[info.clsname] = infoWrapper;
    }
    
    return noLazyMap;
}

static void printLoadInfoWappers(void) {
    NSMutableArray *infos = [NSMutableArray array];
    for (LHLoadInfoWrapper *infoWrapper in LHLoadInfoWappers) {
        [infos addObjectsFromArray:infoWrapper.infos];
    }
    NSSortDescriptor *descriptor = [NSSortDescriptor sortDescriptorWithKey:@"duration" ascending:NO];
    [infos sortUsingDescriptors:@[descriptor]];
    
    CFAbsoluteTime totalDuration = 0;
    for (LHLoadInfo *info in infos) {
        totalDuration += info.duration;
    }
    printf("\n\t\t\tTotal load time: %f milliseconds", totalDuration * 1000);
    for (LHLoadInfo *info in infos) {
        NSString *clsname = [NSString stringWithFormat:@"%@", info.clsname];
        if (info.catname) clsname = [NSString stringWithFormat:@"%@(%@)", clsname, info.catname];
        printf("\n%30s load time: %f milliseconds", [clsname cStringUsingEncoding:NSUTF8StringEncoding], info.duration * 1000);
    }
    printf("\n");
}

static void swizzleLoadMethod(Class cls, Method method, LHLoadInfo *info) {
retry:
    do {
        SEL hookSel = randomLoadSelector();
        Class metaCls = object_getClass(cls);
        IMP hookImp = imp_implementationWithBlock(^ {
            info->_start = CFAbsoluteTimeGetCurrent();
            ((void (*)(Class, SEL))objc_msgSend)(cls, hookSel);
            info->_end = CFAbsoluteTimeGetCurrent();
            if (!--LHAllLoadNumber) printLoadInfoWappers();
        });
        
        BOOL didAddMethod = class_addMethod(metaCls, hookSel, hookImp, method_getTypeEncoding(method));
        if (!didAddMethod) goto retry;
        
        info->_sel = hookSel;
        Method hookMethod = class_getInstanceMethod(metaCls, hookSel);
        method_exchangeImplementations(method, hookMethod);
    } while(0);
}

static void hookAllLoadMethods(LHLoadInfoWrapper *infoWrapper) {
    unsigned int count = 0;
    Class metaCls = object_getClass(infoWrapper.cls);
    Method *methodList = class_copyMethodList(metaCls, &count);
    for (unsigned int i = 0; i < count; i++) {
        Method method = methodList[i];
        SEL sel = method_getName(method);
        const char *name = sel_getName(sel);
        if (!strcmp(name, "load")) {
            LHLoadInfo *info = nil;
            if (i > infoWrapper.infos.count - 1) {
                info = [[LHLoadInfo alloc] initWithClass:infoWrapper.cls];
                [infoWrapper insertLoadInfo:info];
                LHAllLoadNumber++;
            } else {
                info = infoWrapper.infos[i];
            }
            swizzleLoadMethod(infoWrapper.cls, method, info);
        }
    }
    free(methodList);
}

__attribute__((constructor)) void LoadHook_Initializer(void) {
    const char *main = [[NSBundle mainBundle].executablePath cStringUsingEncoding:NSUTF8StringEncoding];
    const struct mach_header *mhdr = getImageHeaderForName(main);
    NSArray <LHLoadInfo *> *infos = getNoLazyArray(mhdr);
    LHAllLoadNumber = infos.count;
    NSDictionary <NSString *, LHLoadInfoWrapper *> *groupedInfos = groupNoLazyArray(infos);
    for (NSString *clsname in groupedInfos.allKeys) {
        LHLoadInfoWrapper *infoWrapper = groupedInfos[clsname];
        hookAllLoadMethods(infoWrapper);
    }
    LHLoadInfoWappers = groupedInfos.allValues;
}
