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
#include <time.h>
#include "cc_dylib.h"
#include "ccrng_priv.h"
#include "ccrng_getentropy.h"
#include "ccrng_process.h"

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
    return clock_gettime_nsec_np(CLOCK_MONOTONIC);
}

static void
init(CC_UNUSED void *arg)
{
    int err = ccrng_process_init(&process_rng_ctx,
                                 get_time_nsec,
                                 &ccrng_getentropy);
    cc_abort_if(err != CCERR_OK, "ccrng_process_init");

    rng_ctx.generate = generate;
}

#include <os/once_private.h>

struct ccrng_state *
ccrng_prng(int *error)
{
    CC_ENSURE_DIT_ENABLED

    static os_once_t init_pred;
    os_once(&init_pred, NULL, init);

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

void
ccrng_atfork_prepare(void)
{
    int err = ccrng_process_atfork_prepare(&process_rng_ctx);
    cc_abort_if(err != CCERR_OK, "ccrng_process_atfork_prepare");
}

void
ccrng_atfork_parent(void)
{
    int err = ccrng_process_atfork_parent(&process_rng_ctx);
    cc_abort_if(err != CCERR_OK, "ccrng_process_atfork_parent");
}

void
ccrng_atfork_child(void)
{
    int err = ccrng_process_atfork_child(&process_rng_ctx);
    cc_abort_if(err != CCERR_OK, "ccrng_process_atfork_child");
}
