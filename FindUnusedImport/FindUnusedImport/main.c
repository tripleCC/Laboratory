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

static const char *const g_header_file_extname = ".h";
static const char *const g_file_extname[] = {
    g_header_file_extname,
    ".m",
    ".pch",
//    "modulemap" 有伞头文件
};

typedef struct {
    char name[NAME_MAX];
    char path[PATH_MAX];
} objc_file;

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

fui_hash_table_ref map;
pthread_mutex_t map_lock = PTHREAD_MUTEX_INITIALIZER;
fui_thread_pool_ref pool;
fui_list_ref headers;
fui_list_ref objc_files;

struct file_check_context {
    objc_file *file;
    char *contents;
    unsigned long length;
};

void header_foreach(void *value, void *ctx) {
    struct file_check_context *context = ctx;
    objc_file *file = context->file;
    char *contents = context->contents;
    unsigned long length = context->length;
    objc_file *header = value;
    
    if (strlen(header->name) == strlen(file->name) &&
        !strncmp(header->name, file->name, strlen(header->name) - 2))
        return;
    
    if (is_header_required(contents, length, header->name)) {
        fui_list_ref value = NULL;
        pthread_mutex_lock(&map_lock);
        fui_hash_table_get(map, header->path, (void **)&value);
        if (!value) {
            fui_list_ref list = fui_list_allocate();
            fui_list_add(list, file->path);
            fui_hash_table_add(map, header->path, list);
        } else {
            fui_list_add(value, file->path);
        }
        pthread_mutex_unlock(&map_lock);
    }
    
}

void *check_file(void *argv) {
    objc_file *file = argv;
    
    int fd = open(file->path, O_RDONLY);
    if (fd < 0) return NULL;
    
    off_t length = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    char *contents = malloc(length);
    if (!contents) return NULL;
    
//    printf("%s \n", file->path);
    
    if (read(fd, contents, length)) {
        struct file_check_context *ctx = malloc(sizeof(struct file_check_context));
        ctx->file = file;
        ctx->contents = contents;
        ctx->length = length;
        
        fui_list_foreach(headers, header_foreach, ctx);
        free(ctx);
    }
    free(contents);
    close(fd);
    
    return NULL;
}

void find_files_with_filter(const char *root, fui_list_ref list, bool (*filter)(const char* )) {
    struct dirent *ent = NULL;
    DIR *dir = opendir(root);
    
    if (!dir) return;
    
    while (NULL != (ent = readdir(dir))) {
        if (!strncmp(ent->d_name, ".", 1)) continue;
        
        switch (ent->d_type) {
            case DT_DIR: {
                char path[PATH_MAX] = { 0 };
                snprintf(path, sizeof(path), "%s/%s", root, ent->d_name);
                find_files_with_filter(path, list, filter);
            } break;
            case DT_REG: {
                if (filter && filter(ent->d_name)) {
                    objc_file *file = calloc(1, sizeof(objc_file));
                    memcpy(file->name, ent->d_name, strlen(ent->d_name));
                    snprintf(file->path, sizeof(file->path), "%s/%s", root, ent->d_name);
                    fui_list_add(list, file);
                }
            } break;
            default: break;
        }
    }
    
    closedir(dir);
}

static inline bool has_extname(const char *file, const char *extname) {
    if (!file || !extname) return false;
    
    size_t fsize = strlen(file);
    size_t esize = strlen(extname);
    if (esize > fsize) return false;
    
    return !strcmp(file + fsize - esize, extname);
}

static bool has_objc_header_extname(const char *file) {
    return has_extname(file, g_header_file_extname);
}

static bool has_objc_extname(const char *file) {
    for (int i = 0; i < sizeof(g_file_extname) / sizeof(char *) - 1; i++) {
        if (has_extname(file, g_file_extname[i])) {
            return true;
        }
    }
    return false;
}

void objc_file_foreach(void *value, void *ctx) {
    thread_pool_add_task(pool, check_file, value);
}

int count = 0;
void print_unused_import(void *value, void *ctx) {
    fui_hash_table_ref map = ctx;
    fui_list_ref list = NULL;
    objc_file *file = value;
    fui_hash_table_get(map, file->path, (void **)&list);
    if (!list) {
        count++;
        printf("%s\n", file->name);
    }
}

int main(int argc, const char * argv[]) {
    char *root = "/Users/songruiwang/Work/TDF/restapp/RestApp";
    
    struct stat path_stat;
    stat(root, &path_stat);
    if (!S_ISDIR(path_stat.st_mode)) {
        printf("\"%s\" isn't an available directory.\n", root);
        return -1;
    }
    
    headers = fui_list_allocate();
    objc_files = fui_list_allocate();
    pool = thread_pool_init();
    map = fui_hash_table_allocate();
    
    find_files_with_filter(root, headers, has_objc_header_extname);
    find_files_with_filter(root, objc_files, has_objc_extname);
    
    init_keyword_infos(g_require_infos, sizeof(g_require_infos));
    fui_list_foreach(objc_files, objc_file_foreach, NULL);
    
    thread_pool_wait(pool);
    
    fui_list_foreach(headers, print_unused_import, map);
    
    printf("%d\n", count);
    printf("%d\n", fui_list_get_number(headers));
    fui_hash_table_foreach(map, free_list);
    fui_hash_table_free(map);
    fui_list_free(headers);
    fui_list_free(objc_files);
    thread_pool_destroy(pool);

    
    return 0;
}

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
