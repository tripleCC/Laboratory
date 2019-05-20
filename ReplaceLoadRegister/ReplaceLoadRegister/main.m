//
//  main.m
//  ReplaceLoadRegister
//
//  Created by tripleCC on 5/20/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <objc/runtime.h>

//================= 通过 load 自动注册 ===========//
// 这种方式推荐在以下情况使用：
// 1. 使用 replaceModules 时，就需要知道所有注册类
// 2. 需要在 load 时就添加所有注册类，比如 TDFModuleKit

static NSMutableArray *modules = nil;
@interface LoadBase : NSObject
+ (void)registerLoad;
@end
@implementation LoadBase
+ (void)registerLoad {
    if (!modules) {
        modules = [NSMutableArray array];
    }
    [modules addObject:self];
}
@end

@interface LoadBaseA : LoadBase
@end
@implementation LoadBaseA
+ (void)load {
    [self registerLoad]; // 通过 load 自动注册
}
@end
@interface LoadBaseB : LoadBase
@end
@implementation LoadBaseB
+ (void)load {
    [self registerLoad]; // 通过 load 自动注册
}
@end

//================= 通过编译写入 section 自动注册 ===========//
// 这种方式推荐在以下情况使用：
// 1. 使用 replaceModules 时，就需要知道所有注册类
// 2. 不需要在 load 时就添加所有注册类，比如 ReplaceLoadBase 可以不用子 load 中调用 loadModules

static NSMutableArray *replaceModules = nil;

#define registerModule(m) static char *tbv_module_##m __attribute((used, section("__DATA, __tbv_modulelist"))) = #m;

@interface ReplaceLoadBase : NSObject
+ (void)loadModules;
@end
@implementation ReplaceLoadBase
+ (void)load {
    // 如果需要系统帮忙执行这个操作，不过会有启动性能问题
    [self loadModules];
}

+ (void)loadModules {
    if (!replaceModules) {
        replaceModules = [NSMutableArray array];
    }
    
    Dl_info info = {0};
    // 这里局限于主静态库，动态库拥有自己的偏移
    Method m = class_getClassMethod(self, _cmd);
    IMP imp = method_getImplementation(m);
    int result = dladdr(imp, &info);   // 拿到函数所在 image
    if (!result) return;
    
    struct mach_header *mhdr = (struct mach_header *)info.dli_fbase;
    unsigned long bytes = 0;
    char **clssName = (char **)getsectiondata((void *)mhdr, "__DATA", "__tbv_modulelist", &bytes);
    for (unsigned int i = 0; i < bytes / sizeof(char *); i++) {
        char *clsName = clssName[i];
        Class cls = objc_getClass(clsName);
        [replaceModules addObject:cls];
    }
}
@end

registerModule(ReplaceLoadBaseA)
@interface ReplaceLoadBaseA : ReplaceLoadBase
@end
@implementation ReplaceLoadBaseA
@end

registerModule(ReplaceLoadBaseB)
@interface ReplaceLoadBaseB : ReplaceLoadBase
@end
@implementation ReplaceLoadBaseB
@end

int main(int argc, const char * argv[]) {
    for (Class module in modules) {
        NSLog(@"%@", module);
    }
    NSLog(@"==========================");
    for (Class module in replaceModules) {
        NSLog(@"%@", module);
    }
    return 0;
}
