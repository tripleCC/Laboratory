/* Copyright (c) (2018-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include "cc_macros.h"
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccaes.h>
#include "ccrng_fortuna.h"

#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>

#include "cc_internal.h"
#include "ccmode_internal.h"
#include "ccrng_fortuna_internal.h"

static int generate(struct ccrng_state *rng,
                    size_t nbytes,
                    void *out)
{
    return ccrng_fortuna_generate((struct ccrng_fortuna_ctx *)rng,
                                  nbytes,
                                  out);
}

void ccrng_fortuna_init(struct ccrng_fortuna_ctx *ctx,
                        ccrng_fortuna_getentropy getentropy,
                        void *getentropy_arg)

{
    cc_clear(sizeof(*ctx), ctx);

    cc_lock_init(&ctx->lock, "ccrng_fortuna");

    ctx->generate = generate;

    ctx->getentropy = getentropy;
    ctx->getentropy_arg = getentropy_arg;
}

const static uint8_t zeros[CCRNG_FORTUNA_GENERATE_MAX_NBYTES] = { 0 };

int ccrng_fortuna_generate(struct ccrng_fortuna_ctx *ctx, size_t nbytes, void *out)
{
    if (nbytes > CCRNG_FORTUNA_GENERATE_MAX_NBYTES) {
        cc_abort("ccrng_fortuna_generate: Maximum request size exceeded");
    }

    int err = CCERR_RNG_NOT_SEEDED;

    const struct ccmode_ctr *aes256ctr_info = ccaes_ctr_crypt_mode();
    ccctr_ctx_decl(aes256ctr_info->size, aes256ctr_ctx);

    CC_LOCK_LOCK(&ctx->lock);

    if (!ctx->seeded) {
        goto out;
    }

    ccctr_init(aes256ctr_info, aes256ctr_ctx, sizeof(ctx->key), ctx->key, ctx->ctr);
    ccctr_update(aes256ctr_info, aes256ctr_ctx, sizeof(ctx->key), zeros, ctx->key);

    ccctr_update(aes256ctr_info, aes256ctr_ctx, nbytes, zeros, out);

    inc_uint(ctx->ctr + 4, 8);

    err = CCERR_OK;

 out:
    CC_LOCK_UNLOCK(&ctx->lock);

    ccctr_ctx_clear(aes256ctr_info->size, aes256ctr_ctx);
    return err;
}

static void schedule(struct ccrng_fortuna_ctx *ctx, int *pool_in, int *pool_out)
{
    CC_LOCK_ASSERT(&ctx->lock);

    *pool_in = (int)ctx->sched.pool_idx;
    ctx->sched.pool_idx += 1;
    ctx->sched.pool_idx %= CCRNG_FORTUNA_NPOOLS;

    *pool_out = -1;

    if (*pool_in == 0) {
        ctx->sched.reseed_sched += 1;
        *pool_out = (int)cc_ffs64((int64_t)ctx->sched.reseed_sched);
    }
}

static void addentropy(struct ccrng_fortuna_ctx *ctx, int pool_idx, size_t entropy_nbytes, const void *entropy, uint32_t nsamples)
{
    CC_LOCK_ASSERT(&ctx->lock);

    if (pool_idx == -1) {
        return;
    }

    const struct ccdigest_info *sha256_info = ccsha256_di();
    ccdigest_di_decl(sha256_info, sha256_ctx);

    struct ccrng_fortuna_pool_ctx *pool = ctx->pools + pool_idx;

    ccdigest_init(sha256_info, sha256_ctx);

    const uint8_t label[] = CCRNG_FORTUNA_LABEL(CCRNG_FORTUNA_OP_ADDENTROPY);
    ccdigest_update(sha256_info, sha256_ctx, sizeof(label), label);

    uint8_t id[sizeof(uint32_t)];
    cc_store32_be((uint32_t) pool_idx, id);
    ccdigest_update(sha256_info, sha256_ctx, sizeof(id), id);

    ccdigest_update(sha256_info, sha256_ctx, sizeof(pool->data), pool->data);

    uint64_t rand;
    (void)cc_rdrand(&rand);
    rand = CC_H2BE64(rand);
    ccdigest_update(sha256_info, sha256_ctx, sizeof(rand), &rand);

    ccdigest_update(sha256_info, sha256_ctx, entropy_nbytes, entropy);

    ccdigest_final(sha256_info, sha256_ctx, pool->data);

    pool->nsamples += nsamples;
    pool->nsamples_max = CC_MAX(pool->nsamples_max, pool->nsamples);
    ctx->addentropy_nsamples_max = CC_MAX(ctx->addentropy_nsamples_max, nsamples);

    ccdigest_di_clear(sha256_info, sha256_ctx);
    cc_clear(sizeof(rand), &rand);
}

static bool schedreseed(struct ccrng_fortuna_ctx *ctx, int pool_idx)
{
    CC_LOCK_ASSERT(&ctx->lock);

    if (pool_idx == -1) {
        return false;
    }

    const struct ccdigest_info *sha256_info = ccsha256_di();
    ccdigest_di_decl(sha256_info, sha256_ctx);

    ccdigest_init(sha256_info, sha256_ctx);

    const uint8_t label[] = CCRNG_FORTUNA_LABEL(CCRNG_FORTUNA_OP_SCHEDRESEED);
    ccdigest_update(sha256_info, sha256_ctx, sizeof(label), label);

    uint64_t sched = CC_H2BE64(ctx->sched.reseed_sched);
    ccdigest_update(sha256_info, sha256_ctx, sizeof(sched), &sched);

    ccdigest_update(sha256_info, sha256_ctx, sizeof(ctx->key), ctx->key);

    uint32_t nsamples = 0;
    for (int i = 0; i < pool_idx; i += 1) {
        struct ccrng_fortuna_pool_ctx *pool = ctx->pools + i;

        ccdigest_update(sha256_info, sha256_ctx, sizeof(pool->data), pool->data);
        cc_clear(sizeof(pool->data), pool->data);

        nsamples += pool->nsamples;
        pool->nsamples = 0;
        pool->ndrains += 1;
    }

    ccdigest_final(sha256_info, sha256_ctx, ctx->key);
    ccdigest_di_clear(sha256_info, sha256_ctx);

    if (nsamples >= 1024) {
        ctx->seeded = true;
    }

    ctx->nreseeds += 1;
    ctx->schedreseed_nsamples_max = CC_MAX(ctx->schedreseed_nsamples_max, nsamples);

    return ctx->seeded;
}

static void reset(struct ccrng_fortuna_ctx *ctx)
{
    ctx->seeded = false;

    ctx->nreseeds = 0;
    ctx->schedreseed_nsamples_max = 0;
    ctx->addentropy_nsamples_max = 0;

    for (int i = 0; i < CCRNG_FORTUNA_NPOOLS; i += 1) {
        struct ccrng_fortuna_pool_ctx *pool = ctx->pools + i;
        pool->nsamples = 0;
        pool->ndrains = 0;
        pool->nsamples_max = 0;
    }

    ctx->sched.reseed_sched = 0;
    ctx->sched.pool_idx = 0;
}

bool ccrng_fortuna_refresh(struct ccrng_fortuna_ctx *ctx)
{
    bool reseeded = false;

    if (!CC_LOCK_TRYLOCK(&ctx->lock)) {
        return reseeded;
    }

    uint8_t entropy[64];
    size_t entropy_nbytes = sizeof(entropy);

    int32_t nsamples = ctx->getentropy(&entropy_nbytes, entropy, ctx->getentropy_arg);
    if (nsamples > 0) {
        int pool_in, pool_out;

        schedule(ctx, &pool_in, &pool_out);
        addentropy(ctx, pool_in, entropy_nbytes, entropy, (uint32_t)nsamples);
        reseeded = schedreseed(ctx, pool_out);
    } else if (nsamples < 0) {
        reset(ctx);
    }

    CC_LOCK_UNLOCK(&ctx->lock);

    cc_clear(entropy_nbytes, entropy);

    return reseeded;
}
