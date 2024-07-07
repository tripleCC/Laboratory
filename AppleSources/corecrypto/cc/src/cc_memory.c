/* Copyright (c) (2020-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_memory.h"

/* Workspace debugging. */

#if CC_ALLOC_DEBUG
struct ws_dbg {
    const void *p;
    const char *file;
    int line;
    const char *func;
} g_ws_dbg;

void cc_ws_alloc_debug(CC_UNUSED const void *p, CC_UNUSED const char *file, CC_UNUSED int line, CC_UNUSED const char *func)
{
    // Contract for some client is to have a single malloc at a time
    cc_try_abort_if(g_ws_dbg.p != NULL, "multiple workspaces not allowed");
    g_ws_dbg = (struct ws_dbg){ p, file, line, func };
}

void cc_ws_free_debug(CC_UNUSED const void *p)
{
    // Contract for some client is to have a single malloc at a time
    cc_try_abort_if(g_ws_dbg.p != p, "multiple workspaces not allowed");
    g_ws_dbg = (struct ws_dbg){};
}
#endif // CC_ALLOC_DEBUG

/* Generic heap malloc() and free() functions. */
#if CC_EXTERN_MALLOC

extern void *cc_malloc(size_t size);
extern void cc_free(void *p, size_t size);

#elif CC_MALLOC_ABORT

void *cc_malloc(CC_UNUSED size_t size)
{
    cc_try_abort("malloc disallowed in this environment");
    return NULL;
}

void cc_free(CC_UNUSED void *p, CC_UNUSED size_t size)
{

}

#elif CC_KERNEL

#include <IOKit/IOLib.h>
#include <kern/debug.h>
#include <vm/pmap.h>

// AEA is used to encrypt coredumps when a panic occurs. *When
// a panic occurs we cannot take locks or allocate memory*. To
// support this usecase, we'll create a static buffer to be used
// as a workspace when we are paniced. The following functions
// are utilized with ccec_cp_256() and from those we approximate
// the amount of necessary memory (all `n` is expressed below with
// a unit size of 64 bits):
//
// 1. ccec_x963_import_pub
//    workspace n = 68
// 2. ccec_generate_key
//    workspace n = 152
// 3. ccecdh_compute_shared_secret
//    workspace n = 104
//
// This implies a total of 1216 bytes. To give some room for error
// and future modifications (i.e. usage of ccec_cp_521()), we'll set
// the value to 4096.

#define PANIC_SCRATCH_BUFFER_SIZE 4096
static unsigned char panic_scratch_buffer[PANIC_SCRATCH_BUFFER_SIZE];
static int panic_scratch_buffer_lock = 0;

CC_INLINE
void *cc_malloc(size_t size)
{
    if (panic_active()) {
        cc_abort_if(size > PANIC_SCRATCH_BUFFER_SIZE, "Panic context cc_malloc trying to allocate larger than PANIC_SCRATCH_BUFFER_SIZE");
        cc_abort_if(panic_scratch_buffer_lock == 1, "Panic context cc_malloc trying to allocate twice from panic_scratch_buffer");

        panic_scratch_buffer_lock = 1;
        return &panic_scratch_buffer[0];
    }

    if (pmap_in_ppl()) {
        cc_abort_if(size > PAGE_SIZE, "PPL cc_malloc trying to allocate larger than PAGE_SIZE");

        return pmap_claim_reserved_ppl_page();
    } else {
        return IOMallocData(size);
    }
}

void cc_free(void *p, size_t size)
{
    if (panic_active()) {
        panic_scratch_buffer_lock = 0;
        return;
    }

    if (pmap_in_ppl()) {
        cc_abort_if(size > PAGE_SIZE, "PPL cc_free trying to free larger than PAGE_SIZE");

        pmap_free_reserved_ppl_page(p);
    } else {
        IOFreeData(p, size);
    }
}

#elif CC_USE_HEAP_FOR_WORKSPACE

#include <stdlib.h>

CC_INLINE
void *cc_malloc(size_t size)
{
    return malloc(size);
}

void cc_free(void *p, size_t size CC_UNUSED)
{
    free(p);
}

#else // !CC_USE_HEAP_FOR_WORKSPACE

CC_INLINE void *cc_malloc(CC_UNUSED size_t size) {
    return NULL;
}

void cc_free(CC_UNUSED void *p, CC_UNUSED size_t size)
{

}

#endif // !CC_KERNEL

void *cc_malloc_clear(size_t s)
{
    void *p = cc_malloc(s);
    if (p) {
        cc_memset(p, 0, s);
    }
    return p;
}

/* Generic workspace functions. */

cc_unit* cc_ws_alloc(cc_ws_t ws, cc_size n)
{
    cc_unit *mem = (cc_unit *)ws->ctx + ws->offset;
    ws->offset += n;
    cc_try_abort_if(ws->offset > ws->nunits, "alloc ws");
    return mem;
}

void cc_ws_free(cc_ws_t ws)
{
    cc_try_abort_if(ws->offset > ws->nunits, "free ws");
    ccn_clear(ws->nunits, ws->ctx);
    cc_free(ws->ctx, ccn_sizeof_n(ws->nunits));
    ws->nunits = ws->offset = 0;
    ws->ctx = NULL;
}

/* Stack-based workspace functions. */

void cc_ws_free_stack(cc_ws_t ws)
{
    cc_try_abort_if(ws->offset > ws->nunits, "free ws");
    ccn_clear(ws->nunits, ws->ctx);
    ws->nunits = ws->offset = 0;
    ws->ctx = NULL;
}

/* Null workspace functions. */

void cc_ws_free_null(CC_UNUSED cc_ws_t ws)
{

}
