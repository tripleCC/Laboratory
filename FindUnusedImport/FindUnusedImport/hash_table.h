//
//  hash.h
//  FindUnusedImport
//
//  Created by tripleCC on 6/6/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#ifndef hash_h
#define hash_h

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FUI_TABLE_MISSING       = -3,
    FUI_TABLE_FULL          = -2,
    FUI_TABLE_OUT_OF_MEMORY = -1,
    FUI_TABLE_SUCCESS       = 0,
} fui_table_operate_status;
    
typedef struct fui_hash_table *fui_hash_table_ref;
typedef void (fui_hash_table_foreach_func)(const char *key, void *value);
    
extern fui_hash_table_ref
fui_hash_table_allocate(void);

void
fui_hash_table_free(fui_hash_table_ref t);

extern fui_table_operate_status
fui_hash_table_add(fui_hash_table_ref t, const char *key, void *value);

extern fui_table_operate_status
fui_hash_table_get(fui_hash_table_ref t, const char *key, void **value);

extern fui_table_operate_status
fui_hash_table_remove(fui_hash_table_ref t, const char *key);

extern void
fui_hash_table_foreach(fui_hash_table_ref t, fui_hash_table_foreach_func each);

#ifdef __cplusplus
}
#endif

#endif /* hash_h */
