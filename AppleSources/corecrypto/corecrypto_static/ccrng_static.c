/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "cc_absolute_time.h"
#include "ccrng_priv.h"
#include "ccrng_getentropy.h"
#include "ccrng_process.h"

#if CC_DARWIN && !CC_BUILT_FOR_TESTING

#include <pthread.h>
#include <time.h>

static struct ccrng_state rng_ctx;
static ccrng_process_ctx_t process_rng_ctx;

static int
generate(CC_UNUSED struct ccrng_state *ctx,
         size_t nbytes,
         void *rand)
{
    int err = ccrng_generate(&process_rng_ctx, nbytes, rand);
    cc_abort_if(err != CCERR_OK, "Failed to generate random");
    return CCERR_OK;
}

static uint64_t
get_time_nsec(void)
{
    struct timespec t;
    int err = clock_gettime(CLOCK_MONOTONIC, &t);
    cc_abort_if(err != 0, "clock_gettime()");

    return ((uint64_t)t.tv_sec * CC_NSEC_PER_SEC) + (uint64_t)t.tv_nsec;
}

static void
atfork_prepare(void)
{
    int err = ccrng_process_atfork_prepare(&process_rng_ctx);
    cc_abort_if(err != CCERR_OK, "ccrng_process_atfork_prepare");
}

static void
atfork_parent(void)
{
    int err = ccrng_process_atfork_parent(&process_rng_ctx);
    cc_abort_if(err != CCERR_OK, "ccrng_process_atfork_parent");
}

static void
atfork_child(void)
{
    int err = ccrng_process_atfork_child(&process_rng_ctx);
    cc_abort_if(err != CCERR_OK, "ccrng_process_atfork_child");
}

static void
init(void)
{
    int err = ccrng_process_init(&process_rng_ctx,
                                 get_time_nsec,
                                 &ccrng_getentropy);
    cc_abort_if(err != CCERR_OK, "ccrng_process_init");

    err = pthread_atfork(atfork_prepare,
                         atfork_parent,
                         atfork_child);
    cc_abort_if(err != 0, "pthread_atfork");

    rng_ctx.generate = generate;
}

struct ccrng_state *
ccrng_prng(int *error)
{
    CC_ENSURE_DIT_ENABLED

    static pthread_once_t init_pred = PTHREAD_ONCE_INIT;
    pthread_once(&init_pred, init);

    if (error) {
        *error = CCERR_OK;
    }

    return &rng_ctx;
}

struct ccrng_state *
ccrng(int *error)
{
    return ccrng_prng(error);
}

struct ccrng_state *
ccrng_trng(int *error)
{
    CC_ENSURE_DIT_ENABLED

    if (error) {
        *error = CCERR_NOT_SUPPORTED;
    }

    return NULL;
}

#endif // CC_DARWIN
