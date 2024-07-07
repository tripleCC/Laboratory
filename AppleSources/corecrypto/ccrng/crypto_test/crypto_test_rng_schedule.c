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
#include "ccrng_schedule.h"
#include "crypto_test_rng.h"
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccsha2.h>

static void
schedule_atomic_flag_test(void)
{
    ccrng_schedule_atomic_flag_ctx_t ctx;
    ccrng_schedule_action_t action;

    ccrng_schedule_atomic_flag_init(&ctx);

    // Initially, the flag is unset
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_CONTINUE, "ccrng_schedule_atomic_flag (flag unset)");

    // After setting it, the schedule recommends "must reseed"
    ccrng_schedule_atomic_flag_set(&ctx);
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_schedule_atomic_flag (flag set)");

    // Simulate reseed
    ccrng_schedule_notify_reseed(&ctx.schedule_ctx);

    // The flag is unset again
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_CONTINUE, "ccrng_schedule_atomic_flag (flag unset again)");
}

static uint64_t time_sim;

static uint64_t
get_time_sim(void)
{
    return time_sim;
}

static void
schedule_timer_test(void)
{
    ccrng_schedule_timer_ctx_t ctx;
    ccrng_schedule_action_t action;

    // Initialize the schedule with a simulated timer and a reseed
    // interval of 2
    ccrng_schedule_timer_init(&ctx,
                              get_time_sim,
                              2);

    // Initially, no time has elapsed
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_CONTINUE, "ccrng_schedule_timer (zero time)");

    // After some (but not enough) time passes, the schedule still
    // recommends "continue"
    time_sim += 1;
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_CONTINUE, "ccrng_schedule_timer (some time)");

    // After more time passes, the schedule recommends "must reseed"
    time_sim += 1;
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_schedule_timer (interval time)");

    // Simulate reseed
    ccrng_schedule_notify_reseed(&ctx.schedule_ctx);

    // No time has elapsed; we "continue" again
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_CONTINUE, "ccrng_schedule_timer (zero time again)");

    // A period of time greater than the interval passes; the schedule
    // recommends "must reseed"
    time_sim += 5;
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_schedule_timer (greater than interval time)");
}

typedef struct {
    ccrng_schedule_ctx_t schedule_ctx;
    uint64_t nreseeds;
} schedule_reseed_counter_t;

static ccrng_schedule_action_t
schedule_reseed_counter_read(CC_UNUSED ccrng_schedule_ctx_t *schedule_ctx)
{
    return CCRNG_SCHEDULE_CONTINUE;
}

static void
schedule_reseed_counter_notify_reseed(ccrng_schedule_ctx_t *schedule_ctx)
{
    schedule_reseed_counter_t *ctx = (schedule_reseed_counter_t *)schedule_ctx;
    ctx->nreseeds += 1;
}

static const ccrng_schedule_info_t
schedule_reseed_counter_info = {
    .read = schedule_reseed_counter_read,
    .notify_reseed = schedule_reseed_counter_notify_reseed,
};

static void
schedule_tree_test(void)
{
    ccrng_schedule_constant_ctx_t continue_ctx;
    ccrng_schedule_constant_ctx_t try_reseed_ctx;
    ccrng_schedule_constant_ctx_t must_reseed_ctx;

    ccrng_schedule_tree_ctx_t ctx;
    ccrng_schedule_action_t action;

    ccrng_schedule_constant_init(&continue_ctx,
                                 CCRNG_SCHEDULE_CONTINUE);
    ccrng_schedule_constant_init(&try_reseed_ctx,
                                 CCRNG_SCHEDULE_TRY_RESEED);
    ccrng_schedule_constant_init(&must_reseed_ctx,
                                 CCRNG_SCHEDULE_MUST_RESEED);

    // In all cases, the schedule forwards the more urgent
    // recommendation from its two sub-schedules

    ccrng_schedule_tree_init(&ctx,
                             &continue_ctx.schedule_ctx,
                             &try_reseed_ctx.schedule_ctx);
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_TRY_RESEED, "ccrng_schedule_tree (continue, try reseed)");

    ccrng_schedule_tree_init(&ctx,
                             &try_reseed_ctx.schedule_ctx,
                             &continue_ctx.schedule_ctx);
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_TRY_RESEED, "ccrng_schedule_tree (try reseed, continue)");

    ccrng_schedule_tree_init(&ctx,
                             &continue_ctx.schedule_ctx,
                             &must_reseed_ctx.schedule_ctx);
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_schedule_tree (continue, must reseed)");

    ccrng_schedule_tree_init(&ctx,
                             &must_reseed_ctx.schedule_ctx,
                             &continue_ctx.schedule_ctx);
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_schedule_tree (must reseed, continue)");

    ccrng_schedule_tree_init(&ctx,
                             &try_reseed_ctx.schedule_ctx,
                             &must_reseed_ctx.schedule_ctx);
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_schedule_tree (try reseed, must reseed)");

    ccrng_schedule_tree_init(&ctx,
                             &must_reseed_ctx.schedule_ctx,
                             &try_reseed_ctx.schedule_ctx);
    action = ccrng_schedule_read(&ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_schedule_tree (must reseed, try reseed)");

    // On reseed notifications, the schedule notifies both of its
    // sub-schedules

    schedule_reseed_counter_t reseed_counter_left_ctx = {
        .schedule_ctx = {
            .info = &schedule_reseed_counter_info,
        },
        .nreseeds = 0,
    };
    schedule_reseed_counter_t reseed_counter_right_ctx = {
        .schedule_ctx = {
            .info = &schedule_reseed_counter_info,
        },
        .nreseeds = 0,
    };

    ccrng_schedule_tree_init(&ctx,
                             &reseed_counter_left_ctx.schedule_ctx,
                             &reseed_counter_right_ctx.schedule_ctx);

    // Simulate reseed and check counters
    ccrng_schedule_notify_reseed(&ctx.schedule_ctx);
    is(reseed_counter_left_ctx.nreseeds, 1, "ccrng_schedule_tree (notify reseed left)");
    is(reseed_counter_right_ctx.nreseeds, 1, "ccrng_schedule_tree (notify reseed right)");
}

static void
schedule_drbg_test(void)
{
    struct ccdrbg_info drbg_info = { 0 };
    struct ccdrbg_nisthmac_custom drbg_custom = {
        .di = ccsha256_di(),
        .strictFIPS = 1,
    };
    ccdrbg_factory_nisthmac(&drbg_info, &drbg_custom);


    uint8_t drbg_state[160];
    cc_clear(sizeof(drbg_state), drbg_state);

    struct ccdrbg_state *drbg_ctx = (struct ccdrbg_state *)drbg_state;

    uint8_t seed[32] = { 0 };

    int err;

    err = ccdrbg_init(&drbg_info,
                      drbg_ctx,
                      sizeof(seed),
                      seed,
                      0,
                      NULL,
                      0,
                      NULL);
    is(err, CCERR_OK, "ccrng_schedule_drbg ccdrbg_init");

    ccrng_schedule_drbg_ctx_t schedule_ctx;
    ccrng_schedule_drbg_init(&schedule_ctx,
                             &drbg_info,
                             drbg_ctx);

    ccrng_schedule_action_t action;

    action = ccrng_schedule_read(&schedule_ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_CONTINUE, "ccrng_schedule_drbg (drbg init)");

    // This forces the reseed counter to the max value
    ccdrbg_done(&drbg_info, drbg_ctx);

    action = ccrng_schedule_read(&schedule_ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_schedule_drbg (drbg done)");

    err = ccdrbg_init(&drbg_info,
                      drbg_ctx,
                      sizeof(seed),
                      seed,
                      0,
                      NULL,
                      0,
                      NULL);
    is(err, CCERR_OK, "ccrng_schedule_drbg ccdrbg_init (again)");

    ccrng_schedule_notify_reseed(&schedule_ctx.schedule_ctx);

    action = ccrng_schedule_read(&schedule_ctx.schedule_ctx);
    is(action, CCRNG_SCHEDULE_CONTINUE, "ccrng_schedule_drbg (drbg init again)");
}

static ccrng_schedule_action_t static_action;

static ccrng_schedule_action_t
schedule_static_action_read(CC_UNUSED ccrng_schedule_ctx_t *schedule_ctx)
{
    return static_action;
}

static void
schedule_static_action_notify_reseed(CC_UNUSED ccrng_schedule_ctx_t *schedule_ctx)
{

}

static const ccrng_schedule_info_t
schedule_static_action_info = {
    .read = schedule_static_action_read,
    .notify_reseed = schedule_static_action_notify_reseed,
};

static void
schedule_must_reseed_test(void)
{
    ccrng_schedule_ctx_t ctx = {
        .info = &schedule_static_action_info
    };
    ccrng_schedule_action_t action;

    // After recommending "must reseed", all schedule implementations
    // will continue to do so until they are notified of a reseed

    // Initially, we get an explicit "must reseed" recommendation
    static_action = CCRNG_SCHEDULE_MUST_RESEED;
    action = ccrng_schedule_read(&ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_schedule (explicit must reseed)");

    // Despite setting the static action to "continue", we get an
    // implicit "must reseed" recommendation because no reseed has
    // occurred to clear it
    static_action = CCRNG_SCHEDULE_CONTINUE;
    action = ccrng_schedule_read(&ctx);
    is(action, CCRNG_SCHEDULE_MUST_RESEED, "ccrng_schedule (implicit must reseed)");

    // Simulate reseed
    ccrng_schedule_notify_reseed(&ctx);

    // After the reseed, we get an explicit "continue" recommendation
    action = ccrng_schedule_read(&ctx);
    is(action, CCRNG_SCHEDULE_CONTINUE, "ccrng_schedule (continue after reseed)");
}

void
schedule_test(void)
{
    diag("Start RNG schedule tests");

    schedule_atomic_flag_test();

    schedule_timer_test();

    schedule_tree_test();

    schedule_drbg_test();

    schedule_must_reseed_test();

    diag("End RNG schedule tests");
}
