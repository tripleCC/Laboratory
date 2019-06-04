//
//  main.m
//  UnusedClassAndMethod
//
//  Created by tripleCC on 5/30/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#import <Foundation/Foundation.h>

#ifndef __LP64__
typedef struct mach_header headerType;
#else
typedef struct mach_header_64 headerType;
#endif


void *copyBytes(FILE *file, long offset, size_t size) {
    void *buffer = calloc(1, size);
    fseek(file, offset, SEEK_SET);
    fread(buffer, size, 1, file);
    return buffer;
}

uint32_t readMagic(FILE *file) {
    uint32_t *bytes = copyBytes(file, 0, sizeof(uint32_t));
    uint32_t magic = *bytes;
    free(bytes);
    return magic;
}

bool isMagic64(uint32_t magic) {
    return magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
}

bool shouldSwapBytes(uint32_t magic) {
    return magic == MH_MAGIC || magic == MH_CIGAM;
}

void readMachHeader(FILE *file) {
    int size = sizeof(headerType);
    headerType *mhdr = (headerType *)calloc(1, size);
//    readBytes(file, 0, size, mhdr);
//
//
//    size_t bytes = 0;
    
//
//
//    NSMutableArray *methnames = [NSMutableArray array];
//    char *methname = (char *)getsectiondata((void *)mhdr, "__TEXT", "__objc_methname", &bytes);
//    unsigned long readBytes = 0;
//    while (bytes > readBytes) {
//        [methnames addObject:[NSString stringWithCString:methname + readBytes encoding:NSUTF8StringEncoding]];
//        readBytes += strlen(methname + readBytes) + 1;
//    }
//
//    char **sels = getDataSection((void *)mhdr, "__objc_selrefs", &bytes);
//    for (unsigned int i = 0; i < bytes / sizeof(char *); i++) {
//        [methnames removeObject:[NSString stringWithCString:sels[i] encoding:NSUTF8StringEncoding]];
//    }
//
//    [methnames enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
//        NSLog(@"%@", obj);
//    }];

}

#include <mach-o/swap.h>
int main(int argc, const char * argv[]) {
//    @autoreleasepool {
        // insert code here...
    FILE *file = fopen("/Users/songruiwang/Desktop/RestApp", "r");
//        uint32_t magic = readMagic(file);
//        bool is64 = isMagic64(magic);
//        bool isSwap = shouldSwapBytes(magic);
    struct mach_header_64 *mhdr = copyBytes(file, 0, sizeof(struct mach_header_64));
//        if (isSwap) {
//            swap_mach_header_64(mhdr, NX_UnknownByteOrder);
//        }
    uint32_t offset = sizeof(struct mach_header_64);
    
    NSMutableDictionary *pointerMap = [NSMutableDictionary dictionary];
    NSMutableDictionary *refpointerMap = [NSMutableDictionary dictionary];
    NSMutableDictionary *nlpointerMap = [NSMutableDictionary dictionary];
    NSMutableDictionary *classMap = [NSMutableDictionary dictionary];
    NSMutableDictionary *refclassMap = [NSMutableDictionary dictionary];
    NSMutableDictionary *nlclassMap = [NSMutableDictionary dictionary];
    NSMutableDictionary *cstringMap = [NSMutableDictionary dictionary];
    NSMutableDictionary *selrefpointerMap = [NSMutableDictionary dictionary];
    NSMutableDictionary *selrefMap = [NSMutableDictionary dictionary];
    
    for (int i = 0; i < mhdr->ncmds; i++) {
        struct load_command *cmd = copyBytes(file, offset, sizeof(struct load_command));
//            printf("%u\n", cmd->cmd);
        if (cmd->cmd == LC_SYMTAB) {
            struct symtab_command *sym = copyBytes(file, offset, sizeof(struct symtab_command));
            struct nlist_64 *nlist = copyBytes(file, sym->symoff, sizeof(struct nlist_64) * sym->nsyms);
            const char *string = copyBytes(file, sym->stroff, sym->strsize);
            
            for (int i = 0; i < sym->nsyms; i++) {
                NSNumber *pointer = @(nlist[i].n_value);
                if (strlen(string + nlist[i].n_un.n_strx) > 0) {
                    NSString *key = [NSString stringWithCString:string + nlist[i].n_un.n_strx encoding:NSUTF8StringEncoding];
                    printf("%s\n", string + nlist[i].n_un.n_strx);
                    if (key) {
                        if (pointerMap[pointer]) {
                            classMap[key] = @"";
                        }
                        if (refpointerMap[pointer]) {
                            refclassMap[key] = @"";
                        }
                        if (nlpointerMap[pointer]) {
                            nlclassMap[key] = @"";
                        }
                        if (selrefpointerMap[pointer]) {
                            selrefMap[key] = @"";
                        }
                    }
                }
            }
            free(sym);
            free(nlist);
            free((void *)string);
        }
        
        if (cmd->cmd == LC_SEGMENT_64) {
//                printf("%s\n", cmd64->segname);
            struct segment_command_64 *cmd64 = copyBytes(file, offset, sizeof(struct segment_command_64));
            struct section_64 *secs = copyBytes(file, offset + sizeof(struct segment_command_64), cmd64->cmdsize - sizeof(struct segment_command_64));
            
            if (!strcmp(cmd64->segname, "__TEXT")) {
                for (int i = 0; i < cmd64->nsects; i++) {
                    struct section_64 sec = secs[i];
//                        printf("%s %s\n", sec.sectname, sec.segname);
                    // 通过反射生成的类
                    if (!strcmp(sec.sectname, "__cstring")) {
                        char *cstrings = copyBytes(file, sec.offset, sec.size);
                        unsigned long readBytes = 0;
                        while (sec.size > readBytes) {
                            char *target = cstrings + readBytes;
                            size_t targetSize = strlen(target);
                            if (targetSize > 0) {
                                NSString *ostring = [NSString stringWithCString:target encoding:NSUTF8StringEncoding];
                                if (ostring.length > 0) {
                                    cstringMap[ostring] = @"";
                                }
                            }
                            readBytes += targetSize + 1;
                        }
                        free(cstrings);
                    }
                }
            }
            
            if (!strcmp(cmd64->segname, "__DATA")) {
                for (int i = 0; i < cmd64->nsects; i++) {
                    struct section_64 sec = secs[i];
                    if (strstr(sec.sectname, "__objc_selrefs")) {
                        uintptr_t *pointers = copyBytes(file, sec.offset, sec.size);
                        for (int i = 0 ; i < sec.size / sizeof(uintptr_t); i++) {
                            NSNumber *pointer = [NSNumber numberWithInteger:pointers[i]];
                            selrefpointerMap[pointer] = @"";
                        }
                        free(pointers);
                    }
//                        printf("%s %s\n", sec.sectname, sec.segname);
                    if (strstr(sec.sectname, "__objc_classlist")) {
                        uintptr_t *pointers = copyBytes(file, sec.offset, sec.size);
                        for (int i = 0 ; i < sec.size / sizeof(uintptr_t); i++) {
                            NSNumber *pointer = [NSNumber numberWithInteger:pointers[i]];
                            pointerMap[pointer] = @"";
                        }
                        free(pointers);
                    }
                    // “使用的类”
                    if (strstr(sec.sectname, "__objc_classrefs")) {\
                        uintptr_t *pointers = copyBytes(file, sec.offset, sec.size);
                        for (int i = 0 ; i < sec.size / sizeof(uintptr_t); i++) {
                            NSNumber *pointer = [NSNumber numberWithInteger:pointers[i]];
                            refpointerMap[pointer] = @"";
                        }
                        free(pointers);
                    }
                    // “抽象类”
                    if (strstr(sec.sectname, "__objc_superrefs")) {\
                        uintptr_t *pointers = copyBytes(file, sec.offset, sec.size);
                        for (int i = 0 ; i < sec.size / sizeof(uintptr_t); i++) {
                            NSNumber *pointer = [NSNumber numberWithInteger:pointers[i]];
                            refpointerMap[pointer] = @"";
                        }
                        free(pointers);
                    }
                    // 自注册类
                    if (strstr(sec.sectname, "__objc_nlclslist")) {
                        uintptr_t *pointers = copyBytes(file, sec.offset, sec.size);
                        for (int i = 0 ; i < sec.size / sizeof(uintptr_t); i++) {
                            NSNumber *pointer = [NSNumber numberWithInteger:pointers[i]];
                            nlpointerMap[pointer] = @"";
                        }
                        free(pointers);
                    }
                }
            }
            
            free(cmd64);
            free(secs);
        }
        offset += cmd->cmdsize;
    }
    
    free(mhdr);
    fclose(file);
    
//    }
    NSMutableDictionary *unusedClassesMap = [NSMutableDictionary dictionary];

    [classMap enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        if ([key hasSuffix:@"Cell"]) {
            NSString *okey = [key stringByReplacingOccurrencesOfString:@"Cell" withString:@"Item"];
            if (!refclassMap[key] && !refclassMap[okey] && !nlclassMap[key]) {
                unusedClassesMap[key] = @"";
            }
        } else {
            if (!refclassMap[key] && !nlclassMap[key]) {
                unusedClassesMap[key] = @"";
            }
        }
    }];
    
    [cstringMap enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        NSString *clsName = [NSString stringWithFormat:@"_OBJC_CLASS_$_%@", key];
        unusedClassesMap[clsName] = nil;
    }];
    NSArray *unusedClasses = [unusedClassesMap.allKeys sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray *finalUnusedClasses = [NSMutableArray array];
    for (NSString *cls in unusedClasses) {
        if ([cls hasPrefix:@"_OBJC_CLASS_$_PodsDummy_"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_Target_"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_UM"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_RCT"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_TSCENTER"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_IFly"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_Ali"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_XG"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_WX"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_JPUSH"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$__"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_UI"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_NS"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_TDFLA"] ||
            [cls hasPrefix:@"_OBJC_CLASS_$_YY"]
            ) {
            continue;
        }
//        [finalUnusedClasses addObject:cls];
        [finalUnusedClasses addObject:[cls stringByReplacingOccurrencesOfString:@"_OBJC_CLASS_$_" withString:@""]];
    }
    
    NSLog(@"%@", finalUnusedClasses);
    NSLog(@"%ld", finalUnusedClasses.count);
    
    return 0;
}
