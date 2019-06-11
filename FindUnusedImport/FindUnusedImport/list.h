//
//  list.h
//  FindUnusedImport
//
//  Created by tripleCC on 6/6/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#ifndef list_h
#define list_h

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fui_list *fui_list_ref;
typedef void (fui_list_foreach_func)(void *value, void *context);
    
extern fui_list_ref
fui_list_allocate(void);

extern void
fui_list_add(fui_list_ref l, void *value);

extern void
fui_list_get(fui_list_ref l, unsigned int i, void **value);

extern void
fui_list_remove(fui_list_ref l, unsigned int i);
    
extern unsigned int
fui_list_get_number(fui_list_ref l);
    
extern void
fui_list_free(fui_list_ref l);
    
extern void
fui_list_foreach(fui_list_ref l, fui_list_foreach_func each, void *context);
#ifdef __cplusplus
}
#endif

#endif /* list_h */
