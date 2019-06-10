//
//  main.c
//  FindUnusedImport
//
//  Created by tripleCC on 6/4/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include "hash_table.h"
#include "list.h"
#include "thread_pool.h"

static const unsigned long gMaxFileNumber = 1024 * 20;
static const char *const gHeaderFileExtname = ".h";
static const char *const gFileExtname[] = {
    gHeaderFileExtname,
    ".m",
    ".pch",
//    "modulemap" 有伞头文件
};

typedef struct {
    char name[NAME_MAX];
    char path[PATH_MAX];
} ObjcFile;

typedef struct {
    ObjcFile files[gMaxFileNumber];
    unsigned int next;
    pthread_mutex_t lock;
} FileList;


void findFiles(const char *root, FileList *fileList, bool (*filter)(const char*));
static inline bool hasObjcExtname(const char *file);
static inline bool hasObjcHeaderExtname(const char *file);
static inline bool hasExtname(const char *str, const char *extname);

static FileList gHeaderFiles = {
    { 0 },
    0,
    PTHREAD_MUTEX_INITIALIZER
};

static FileList gObjcFiles = {
    { 0 },
    0,
    PTHREAD_MUTEX_INITIALIZER
};

typedef struct {
    size_t length;
    char keyword[15];
} fui_keyword_info;


static fui_keyword_info g_require_infos[] = {
    { 0, "#import" },
    { 0, "#include" }
};
bool is_header_required(const char *content, unsigned long length, const char *name);
void init_keyword_infos(fui_keyword_info *infos, size_t size);

void free_list(const char *key, void *value) {
    fui_list_free((fui_list_ref)value);
}

void *check_file(void *argv) {
    ObjcFile *file = argv;
    int fd = open(file->path, O_RDONLY);
    if (fd < 0) return NULL;
    
    off_t length = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char *contents = malloc(length);
    if (!contents) return NULL;
    puts(file->name);
    if (read(fd, contents, length)) {
        for (int j = 0; j < gHeaderFiles.next; j++) {
            char *name = gHeaderFiles.files[j].name;
            
            if (!strncmp(name, file->name, strlen(name) - 2))
                continue;
            if (is_header_required(contents, length, name)) {
                
//                fui_list_ref value = NULL;
//                fui_hash_table_get(hash, gHeaderFiles.files[j].path, (void **)&value);
//                if (!value) {
//                    fui_list_ref list = fui_list_allocate();
//                    fui_list_add(list, gObjcFiles.files[i].path);
//                    fui_hash_table_add(hash, gHeaderFiles.files[j].path, list);
//                } else {
//                    fui_list_add(value, gObjcFiles.files[i].path);
//                }
                
            }
        }
    }
    free(contents);
    close(fd);
    
    return NULL;
}

int main(int argc, const char * argv[]) {

    fui_thread_pool_ref pool = thread_pool_init();
    
    init_keyword_infos(g_require_infos, sizeof(g_require_infos));
    fui_hash_table_ref hash = fui_hash_table_allocate();
    
//    char *root = "/Users/songruiwang/Work/TDF/TDFNavigationBarKit/TDFNavigationBarKit/Classes";
    char *root = "/Users/songruiwang/Work/TDF/restapp/RestApp";
    findFiles(root, &gHeaderFiles, hasObjcHeaderExtname);
    findFiles(root, &gObjcFiles, hasObjcExtname);
    
    for (int i = 0; i < gObjcFiles.next; i++) {
        thread_pool_add_task(pool, check_file, &gObjcFiles.files[i]);
    }
    thread_pool_wait(pool);
    
    fui_hash_table_foreach(hash, free_list);
    fui_hash_table_free(hash);
    thread_pool_destroy(pool);
//
    return 0;
}

//if (*content == '\n') {
//    content++;
//    while (*content == ' ' || *content == '\t') content++;
//    if (strncmp(content, "//", 2)) {
//        content += 2;
//        while (*content++ == '\n');
//    }
//}

//'#' ' '

void init_keyword_infos(fui_keyword_info *infos, size_t size) {
    for (int i = 0; i < size / sizeof(fui_keyword_info); i++) {
        fui_keyword_info *info = &infos[i];
        info->length = strlen(info->keyword);
    }
}

bool is_header_required(const char *content, unsigned long length, const char *name) {
    bool match_require = false;
    bool start_require = false;
    size_t name_length = strlen(name);
    const char *content_end = content + length;
    unsigned int require_infos_count = sizeof(g_require_infos) / sizeof(fui_keyword_info);
    
    do {
        // match # for keyword
        while (content < content_end && *content != '#') {
            // if match @interface @class @implementation @protocol ..., return false
            if (start_require &&
                *content == '@' &&
                *(content - 1) == '\n')
                return false;
            content++;
        }
        start_require = true;

        // match import keyword in line
        for (int i = 0; i < require_infos_count; i++) {
            fui_keyword_info info = g_require_infos[i];
            if (content < content_end - info.length &&
                !strncmp(content, info.keyword, info.length)) {
                content += info.length;
                match_require = true;
                break;
            }
        }
        
        if (!match_require) {
            content++;
            continue;
        }
        
        // match file name in line
        while (content < content_end && *content != '\n') {
            while (*content == ' ' || *content == '\t') content++;
            if (!strncmp(content, name, name_length)) {
                char left = *(content - 1);
                char right = *(content + name_length);
                if ((left == '/' && right == '>') ||
                    (left == '<' && right == '>') ||
                    (left == '"' && right == '"'))
                    return true;
            }
            content++;
        }
        match_require = false;
    } while (content < content_end);
    
    return false;
}

void findFiles(const char *root, FileList *fileList, bool (*filter)(const char*)) {
    struct dirent *ent = NULL;
    DIR *dir = opendir(root);
    
    if (!dir) return;
    
    while (NULL != (ent = readdir(dir))) {
        if (!strncmp(ent->d_name, ".", 1)) continue;
        
        switch (ent->d_type) {
            case DT_DIR: {
                char path[PATH_MAX] = { 0 };
                snprintf(path, sizeof(path), "%s/%s", root, ent->d_name);
                findFiles(path, fileList, filter);
            } break;
            case DT_REG: {
                if (filter && filter(ent->d_name)) {
                    ObjcFile *file = &fileList->files[fileList->next++];
                    memcpy(file->name, ent->d_name, strlen(ent->d_name));
                    snprintf(file->path, sizeof(file->path), "%s/%s", root, ent->d_name);
                }
            } break;
            default: break;
        }
    }
    
    closedir(dir);
}

static bool hasObjcHeaderExtname(const char *file) {
    return hasExtname(file, gHeaderFileExtname);
}

static bool hasObjcExtname(const char *file) {
    for (int i = 0; i < sizeof(gFileExtname) / sizeof(char *) - 1; i++) {
        if (hasExtname(file, gFileExtname[i])) {
            return true;
        }
    }
    return false;
}

static inline bool hasExtname(const char *file, const char *extname) {
    if (!file || !extname) return false;
    
    size_t fsize = strlen(file);
    size_t esize = strlen(extname);
    if (esize > fsize) return false;

    return !strcmp(file + fsize - esize, extname);
}
