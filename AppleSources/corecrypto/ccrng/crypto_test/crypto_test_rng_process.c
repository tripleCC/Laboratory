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

#include "testmore.h"
#include "ccrng_process.h"
#include "ccrng_zero.h"
#include "crypto_test_rng.h"

static uint64_t
get_time_zero(void)
{
    return 0;
}

void
process_rng_test(void)
{
    diag("Start process RNG tests");

    ccrng_process_ctx_t process_rng_ctx;
    int err = ccrng_process_init(&process_rng_ctx,
                                 get_time_zero,
                                 &ccrng_zero);
    is(err, CCERR_OK, "ccrng_process_init");

    uint8_t random[32];
    err = ccrng_generate(&process_rng_ctx, sizeof(random), random);
    is(err, CCERR_OK, "ccrng_process ccrng_generate");

    ccrng_schedule_action_t action;

    action = ccrng_schedule_read(&process_rng_ctx.schedule_flag_ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_CONTINUE, "ccrng_process fork flag default");

    // Simulate the parent side of a process fork

    err = ccrng_process_atfork_prepare(&process_rng_ctx);
    is(err, CCERR_OK, "ccrng_process_atfork_prepare");

    err = ccrng_process_atfork_parent(&process_rng_ctx);
    is(err, CCERR_OK, "ccrng_process_atfork_prepare");

    action = ccrng_schedule_read(&process_rng_ctx.schedule_flag_ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_process fork flag parent");

    // Simulate the child side of a process fork

    err = ccrng_process_atfork_prepare(&process_rng_ctx);
    is(err, CCERR_OK, "ccrng_process_atfork_prepare");

    err = ccrng_process_atfork_child(&process_rng_ctx);
    is(err, CCERR_OK, "ccrng_process_atfork_prepare");

    action = ccrng_schedule_read(&process_rng_ctx.schedule_flag_ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_process fork flag child");

    diag("End process RNG tests");
}

void process_rng_test(void);
