/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrng_schedule.h>

static void
ccrng_schedule_init(const ccrng_schedule_info_t *info,
                    ccrng_schedule_ctx_t *ctx)
{
    ctx->info = info;
    ctx->must_reseed = false;
}

ccrng_schedule_action_t
ccrng_schedule_read(ccrng_schedule_ctx_t *ctx)
{
    if (ctx->must_reseed) {
        // If we had previously set the must-reseed flag and it has
        // not been cleared by a reseed notification, this implies
        // that a reseed attempt failed. In the context of a scheduler
        // that recommends "must reseed", this usually means there is
        // some catastrophic programming error, and the program should
        // abort.
        //
        // In case the program does not abort, we force the schedule
        // to repeat its recommendation until the reseed is successful
        // (or until the program crashes). Assuming the RNG respects
        // the recommendation, this also guarantees it will not
        // generate any random values until it can reseed.
        return CCRNG_SCHEDULE_MUST_RESEED;
    }

    const ccrng_schedule_info_t *info = ctx->info;
    ccrng_schedule_action_t action = info->read(ctx);

    ctx->must_reseed = (action == CCRNG_SCHEDULE_MUST_RESEED);
    return action;
}

void
ccrng_schedule_notify_reseed(ccrng_schedule_ctx_t *ctx)
{
    ctx->must_reseed = false;

    const ccrng_schedule_info_t *info = ctx->info;
    info->notify_reseed(ctx);
}

static void
ccrng_schedule_ignore_notify_reseed(CC_UNUSED ccrng_schedule_ctx_t *schedule_ctx)
{

}

static ccrng_schedule_action_t
ccrng_schedule_atomic_flag_read(ccrng_schedule_ctx_t *schedule_ctx)
{
    ccrng_schedule_atomic_flag_ctx_t *ctx = (ccrng_schedule_atomic_flag_ctx_t *)schedule_ctx;
    return atomic_exchange_explicit(&ctx->flag, CCRNG_SCHEDULE_CONTINUE, memory_order_relaxed);
}

static const ccrng_schedule_info_t
ccrng_schedule_atomic_flag_info = {
    .read = ccrng_schedule_atomic_flag_read,
    .notify_reseed = ccrng_schedule_ignore_notify_reseed,
};

void ccrng_schedule_atomic_flag_init(ccrng_schedule_atomic_flag_ctx_t *ctx)
{
    ccrng_schedule_init(&ccrng_schedule_atomic_flag_info, &ctx->schedule_ctx);
    atomic_store_explicit(&ctx->flag, CCRNG_SCHEDULE_CONTINUE, memory_order_relaxed);
}

void
ccrng_schedule_atomic_flag_set(ccrng_schedule_atomic_flag_ctx_t *ctx)
{
    atomic_store_explicit(&ctx->flag, CCRNG_SCHEDULE_MUST_RESEED, memory_order_relaxed);
}

static ccrng_schedule_action_t
ccrng_schedule_constant_read(ccrng_schedule_ctx_t *schedule_ctx)
{
    ccrng_schedule_constant_ctx_t *ctx = (ccrng_schedule_constant_ctx_t *)schedule_ctx;
    return ctx->action;
}

static const ccrng_schedule_info_t
ccrng_schedule_constant_info = {
    .read = ccrng_schedule_constant_read,
    .notify_reseed = ccrng_schedule_ignore_notify_reseed,
};

void ccrng_schedule_constant_init(ccrng_schedule_constant_ctx_t *ctx,
                                  ccrng_schedule_action_t action)
{
    ccrng_schedule_init(&ccrng_schedule_constant_info, &ctx->schedule_ctx);
    ctx->action = action;
}

static ccrng_schedule_action_t
ccrng_schedule_timer_read(ccrng_schedule_ctx_t *schedule_ctx)
{
    ccrng_schedule_timer_ctx_t *ctx = (ccrng_schedule_timer_ctx_t *)schedule_ctx;
    uint64_t time_delta = ctx->get_time() - ctx->last_reseed_time;

    if (time_delta >= ctx->reseed_interval) {
        return CCRNG_SCHEDULE_MUST_RESEED;
    } else {
        return CCRNG_SCHEDULE_CONTINUE;
    }
}

static void
ccrng_schedule_timer_notify_reseed(ccrng_schedule_ctx_t *schedule_ctx)
{
    ccrng_schedule_timer_ctx_t *ctx = (ccrng_schedule_timer_ctx_t *)schedule_ctx;
    ctx->last_reseed_time = ctx->get_time();
}

static const ccrng_schedule_info_t
ccrng_schedule_timer_info = {
    .read = ccrng_schedule_timer_read,
    .notify_reseed = ccrng_schedule_timer_notify_reseed,
};

void ccrng_schedule_timer_init(ccrng_schedule_timer_ctx_t *ctx,
                               uint64_t (*get_time)(void),
                               uint64_t reseed_interval)
{
    ccrng_schedule_init(&ccrng_schedule_timer_info, &ctx->schedule_ctx);
    ctx->get_time = get_time;
    ctx->reseed_interval = reseed_interval;
    ctx->last_reseed_time = get_time();
}

static ccrng_schedule_action_t
ccrng_schedule_tree_read(ccrng_schedule_ctx_t *schedule_ctx)
{
    ccrng_schedule_tree_ctx_t *ctx = (ccrng_schedule_tree_ctx_t *)schedule_ctx;
    return CC_MAX(ccrng_schedule_read(ctx->left),
                  ccrng_schedule_read(ctx->right));
}

static void
ccrng_schedule_tree_notify_reseed(ccrng_schedule_ctx_t *schedule_ctx)
{
    ccrng_schedule_tree_ctx_t *ctx = (ccrng_schedule_tree_ctx_t *)schedule_ctx;
    ccrng_schedule_notify_reseed(ctx->left);
    ccrng_schedule_notify_reseed(ctx->right);
}

static const ccrng_schedule_info_t
ccrng_schedule_tree_info = {
    .read = ccrng_schedule_tree_read,
    .notify_reseed = ccrng_schedule_tree_notify_reseed,
};

void
ccrng_schedule_tree_init(ccrng_schedule_tree_ctx_t *ctx,
                         ccrng_schedule_ctx_t *left,
                         ccrng_schedule_ctx_t *right)
{
    ccrng_schedule_init(&ccrng_schedule_tree_info, &ctx->schedule_ctx);
    ctx->left = left;
    ctx->right = right;
}

static ccrng_schedule_action_t
ccrng_schedule_drbg_read(ccrng_schedule_ctx_t *schedule_ctx)
{
    ccrng_schedule_drbg_ctx_t *ctx = (ccrng_schedule_drbg_ctx_t *)schedule_ctx;
    const struct ccdrbg_info *drbg_info = ctx->drbg_info;
    struct ccdrbg_state *drbg_ctx = ctx->drbg_ctx;

    if (ccdrbg_must_reseed(drbg_info, drbg_ctx)) {
        return CCRNG_SCHEDULE_MUST_RESEED;
    } else {
        return CCRNG_SCHEDULE_CONTINUE;
    }
}

static const ccrng_schedule_info_t
ccrng_schedule_drbg_info = {
    .read = ccrng_schedule_drbg_read,
    .notify_reseed = ccrng_schedule_ignore_notify_reseed,
};

void ccrng_schedule_drbg_init(ccrng_schedule_drbg_ctx_t *ctx,
                              const struct ccdrbg_info *drbg_info,
                              struct ccdrbg_state *drbg_ctx)
{
    ccrng_schedule_init(&ccrng_schedule_drbg_info, &ctx->schedule_ctx);
    ctx->drbg_info = drbg_info;
    ctx->drbg_ctx = drbg_ctx;
}
