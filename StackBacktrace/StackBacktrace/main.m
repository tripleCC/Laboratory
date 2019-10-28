//
//  main.m
//  StackBacktrace
//
//  Created by tripleCC on 9/5/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#import <Foundation/Foundation.h>

#include <mach-o/arch.h>
#include <mach-o/loader.h>

#include <dlfcn.h>
#include <mach-o/dyld.h>

void listImages(void) {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        printf("%d: %p\t%s\t(slide: %ld)\n", i , _dyld_get_image_header(i), _dyld_get_image_name(i), _dyld_get_image_vmaddr_slide(i));
    }
}

void addCallback(const struct mach_header *mh, intptr_t vmaddr_slide) {
    Dl_info info;
    dladdr(mh, &info);
    printf("Callback invoked for image: %p %s (slide: %ld)\n", mh, info.dli_fname, vmaddr_slide);
}

//__thread int i = 1;

//void test() {
//
//}

int main(int argc, const char * argv[]) {
    listImages();
    
    _dyld_register_func_for_add_image(addCallback);
    
    DYLD_INTERPOSE();
    @autoreleasepool {
//        test();
        // insert code here...
//        NXArchInfo *archInfo = NXGetLocalArchInfo();
//        NXArchInfo *allArchInfo = NXGetAllArchInfos();
//
//        while (allArchInfo && allArchInfo->description) {
//            printf("%s\n", allArchInfo->name);
//            allArchInfo++;
//        }
//        NSLog(@"Hello, World!");
    }
    return 0;
}
