//
//  thread_pool.h
//  FindUnusedImport
//
//  Created by tripleCC on 6/8/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//

#ifndef thread_pool_h
#define thread_pool_h

#include <stdio.h>

typedef struct fui_thread_pool *fui_thread_pool_ref;

extern fui_thread_pool_ref
thread_pool_init(void);

extern int
thread_pool_add_task(fui_thread_pool_ref p, void *(*func)(void *argv), void *argv);

extern void
thread_pool_wait(fui_thread_pool_ref p);

extern void
thread_pool_destroy(fui_thread_pool_ref p);

#endif /* thread_pool_h */
