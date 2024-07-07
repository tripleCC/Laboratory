/* Copyright (c) (2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#if defined(_WIN32)
#include "crypto_test_rng.h"
#include"testmore.h"
#include <windows.h>
#include <stdint.h>
#define MAX_THREAD 30

static SYNCHRONIZATION_BARRIER barrier;
int test_rng_win(struct ccrng_state* rng)
{
    int rc=1;
    struct gen_thread_data res[MAX_THREAD];
    HANDLE threads[MAX_THREAD];
    
    InitializeSynchronizationBarrier(&barrier, MAX_THREAD, -1);
    
	uint64_t *results = malloc(sizeof(uint64_t)*THREAD_RESULT_ARRAY_LEN*MAX_THREAD); //yes, it can overflow
    memset(results, -1, sizeof(uint64_t)*THREAD_RESULT_ARRAY_LEN*MAX_THREAD);
    for (int i=0; i<MAX_THREAD; i++) {
        res[i].results = results+i*THREAD_RESULT_ARRAY_LEN;
        res[i].rng = rng;
        res[i].status = -1;
        res[i].barrier = &barrier;
        
        threads[i] = winthread_create(gen_routine, res+i);
        rc = threads[i] != NULL;
        ok_or_goto(rc, "Cannot create thread", out);
    }
    
    WaitForMultipleObjects(MAX_THREAD, threads, TRUE, INFINITE);
    DeleteSynchronizationBarrier(&barrier);
    rc &= find_duplicate_uint64(results, THREAD_RESULT_ARRAY_LEN*MAX_THREAD);
    ok(rc==1, "test rng failed");
out:           
    return rc;
}
#endif
