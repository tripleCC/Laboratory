//
//  PrintLoadableClsAndCat.c
//  PrintLoadableClsAndCat
//
//  Created by tripleCC on 5/20/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#include "PrintLoadableClsAndCat.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <objc/runtime.h>

static void *_pl_get_data_section(const struct mach_header *mhdr, const char *sectname, size_t *bytes) {
    void *data = getsectiondata((void *)mhdr, "__DATA", sectname, bytes);
    if (!data) {
        data = getsectiondata((void *)mhdr, "__DATA_CONST", sectname, bytes);
    }
    if (!data) {
        data = getsectiondata((void *)mhdr, "__DATA_DIRTY", sectname, bytes);
    }
    
    return data;
}

void pl_print_loadable_clss_and_cats(void *func) {
    Dl_info info = {0};
    int result = dladdr(func, &info);   // 拿到函数所在 image
    if (!result) return;
    
    struct mach_header *mhdr = (struct mach_header *)info.dli_fbase;
    
    unsigned long bytes = 0;
    Class *clss = _pl_get_data_section(mhdr, "__objc_nlclslist", &bytes);
    for (unsigned int i = 0; i < bytes / sizeof(Class); i++) {
        printf("%s\n", object_getClassName((id)clss[i]));
    }
    
    bytes = 0;
    Category *cats = _pl_get_data_section(mhdr, "__objc_nlcatlist", &bytes);
    for (unsigned int i = 0; i < bytes / sizeof(Category); i++) {
        Category cat = cats[i];
        Class cls = (Class)((void *)cat + sizeof(char *));
        // DO NOT use cat->cls! cls may be cat->cls->isa instead
        printf("%s(%s)\n", object_getClassName((id)cls), *((char **)cat));
    }
}
