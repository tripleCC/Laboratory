/* Copyright (c) (2021,2023) Apple Inc. All rights reserved.
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
#include "testbyteBuffer.h"

#if (CCENTROPY == 0)
entryPoint(ccentropy_tests, "ccentropy")
#else

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_sequence.h>
#include <corecrypto/ccentropy.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include "cc_lock.h"

static
void ccentropy_rng_tests(void)
{
    ccentropy_rng_ctx_t ctx;
    ccentropy_ctx_t *ent_ctx = &ctx.entropy_ctx;
    uint8_t seed[32];

    struct ccrng_sequence_state rng;
    uint8_t rng_seq = 0;
    is(ccrng_sequence_init(&rng, sizeof(rng_seq), &rng_seq),
       CCERR_OK,
       "ccrng_sequence_init");

    is(ccentropy_rng_init(&ctx, (struct ccrng_state *)&rng),
       CCERR_OK,
       "ccentropy_rng_init");

    uint32_t entropy_sample = 23;
    bool seed_ready;
    is(ccentropy_add_entropy(ent_ctx, 1, sizeof(entropy_sample), &entropy_sample, &seed_ready),
       CCERR_NOT_SUPPORTED,
       "ccentropy_rng_add_entropy");

    is(seed_ready, false, "ccentropy_rng_add_entropy (seed_ready)");

    is(ccentropy_get_seed(ent_ctx, sizeof(seed), seed),
       CCERR_OK,
       "ccentropy_rng_get_seed (success)");
}

typedef struct ccentropy_digest_vector {
    int id;
    int err;
    const struct ccdigest_info *(*digest_info)(void);
    uint32_t seed_nsamples;
    size_t sample_nbytes;
    uint32_t add_nsamples;
    uint32_t nadds;
} ccentropy_digest_vector_t;

static
ccentropy_digest_vector_t entropy_digest_vectors[] = {
    #include "entropy_digest_vectors.inc"
};

static
void ccentropy_digest_tests(void)
{
    ccentropy_digest_ctx_t ctx;
    ccentropy_ctx_t *ent_ctx = &ctx.entropy_ctx;
    uint8_t seed[MAX_DIGEST_OUTPUT_SIZE + 1];

    for (size_t i = 0; i < CC_ARRAY_LEN(entropy_digest_vectors); i += 1) {
        ccentropy_digest_vector_t *vector = &entropy_digest_vectors[i];

        const struct ccdigest_info *digest_info = vector->digest_info();
        is(ccentropy_digest_init(&ctx, digest_info, vector->seed_nsamples),
           CCERR_OK,
           "ccentropy_digest_init");

        for (uint32_t j = 0; j < vector->nadds; j += 1) {
            is(ccentropy_get_seed(ent_ctx, digest_info->output_size, seed),
               CCERR_OUT_OF_ENTROPY,
               "ccentropy_digest_get_seed (out of entropy, still adding entropy) (vector %d)",
               vector->id);

            size_t add_nbytes = vector->add_nsamples * vector->sample_nbytes;
            void *entropy = malloc(add_nbytes);
            bool seed_ready;

            is(ccentropy_add_entropy(ent_ctx,
                                     vector->add_nsamples,
                                     add_nbytes,
                                     entropy,
                                     &seed_ready),
               CCERR_OK,
               "ccentropy_digest_add_entropy (success) (vector %d)",
               vector->id);

            is(seed_ready,
               vector->add_nsamples * (j + 1) >= vector->seed_nsamples,
               "ccentropy_digest_add_entropy (seed_ready) (vector %d)",
               vector->id);

            free(entropy);
        }

        is(ccentropy_get_seed(ent_ctx, sizeof(seed), seed),
           CCERR_CRYPTO_CONFIG,
           "ccentropy_digest_get_seed (seed_max_nbytes exceeded) (vector %d)",
           vector->id);

        is(ccentropy_get_seed(ent_ctx, digest_info->output_size, seed),
           vector->err,
           "ccentropy_digest_get_seed (vector result) (vector %d)",
           vector->id);

        is(ccentropy_get_seed(ent_ctx, digest_info->output_size, seed),
           CCERR_OUT_OF_ENTROPY,
           "ccentropy_digest_get_seed (out of entropy, after getting seed) (vector %d)",
           vector->id);
    }
}

static int null_get_seed(CC_UNUSED ccentropy_ctx_t *ctx,
                         CC_UNUSED size_t seed_nbytes,
                         CC_UNUSED void *seed)
{
    return CCERR_OUT_OF_ENTROPY;
}

static
void ccentropy_list_tests(void)
{
    ccentropy_list_ctx_t ctx;
    ccentropy_ctx_t *ent_ctx = &ctx.entropy_ctx;
    uint8_t seed[32];

    ccentropy_ctx_t *ent_sources[2];

    ccentropy_info_t ent_null_info = {
        .get_seed = null_get_seed
    };
    ccentropy_ctx_t ent_null_ctx = {
        .info = &ent_null_info
    };

    ccentropy_rng_ctx_t ent_rng_ctx;

    struct ccrng_sequence_state rng;
    uint8_t rng_seq = 0;
    is(ccrng_sequence_init(&rng, sizeof(rng_seq), &rng_seq),
       CCERR_OK,
       "ccrng_sequence_init");

    is(ccentropy_rng_init(&ent_rng_ctx, (struct ccrng_state *)&rng),
       CCERR_OK,
       "ccentropy_rng_init");

    ent_sources[0] = &ent_null_ctx;
    ent_sources[1] = &ent_rng_ctx.entropy_ctx;

    is(ccentropy_list_init(&ctx, 1, ent_sources),
       CCERR_OK,
       "ccentropy_list_init ([null] sources)");

    is(ccentropy_get_seed(ent_ctx, sizeof(seed), seed),
       CCERR_OUT_OF_ENTROPY,
       "ccentropy_list_get_seed ([null] sources)");

    is(ccentropy_list_init(&ctx, 2, ent_sources),
       CCERR_OK,
       "ccentropy_list_init ([null, rng] sources)");

    is(ccentropy_get_seed(ent_ctx, sizeof(seed), seed),
       CCERR_OK,
       "ccentropy_list_get_seed ([null, rng] sources)");

    ent_sources[0] = &ent_rng_ctx.entropy_ctx;

    is(ccentropy_list_init(&ctx, 1, ent_sources),
       CCERR_OK,
       "ccentropy_list_init ([rng] sources)");

    is(ccentropy_get_seed(ent_ctx, sizeof(seed), seed),
       CCERR_OK,
       "ccentropy_list_get_seed ([rng] sources)");

    bool seed_ready;
    is(ccentropy_add_entropy(ent_ctx, 1, sizeof(seed), seed, &seed_ready),
       CCERR_NOT_SUPPORTED,
       "ccentropy_list_add_entropy");

    is(seed_ready, false, "ccentropy_list_add_entropy (seed_ready)");
}

static int inner_err;

static
int inner_func(void)
{
    return inner_err;
}

static
void ccentropy_lock_tests(void)
{
    ccentropy_lock_ctx_t ctx;
    ccentropy_ctx_t *ent_ctx = &ctx.entropy_ctx;
    uint8_t seed[32];

    ccentropy_info_t inner_info = {
        .get_seed = (ccentropy_get_seed_fn_t)inner_func,
        .add_entropy = (ccentropy_add_entropy_fn_t)inner_func,
        .reset = (ccentropy_reset_fn_t)inner_func,
    };
    ccentropy_ctx_t inner_ctx = {
        .info = &inner_info
    };

    cc_lock_ctx_t lock_ctx;
    is(cc_lock_init(&lock_ctx, "ccentropy_lock_tests"),
       CCERR_OK,
       "cc_lock_init");

    is(ccentropy_lock_init(&ctx,
                           &inner_ctx,
                           &lock_ctx),
       CCERR_OK,
       "ccentropy_lock_init");

    inner_err = 23;
    is(ccentropy_get_seed(ent_ctx, sizeof(seed), seed),
       inner_err,
       "ccentropy_lock_get_seed");

    inner_err = 42;
    bool seed_ready;
    is(ccentropy_add_entropy(ent_ctx,
                             0,
                             sizeof(seed),
                             seed,
                             &seed_ready),
       inner_err,
       "ccentropy_lock_add_entropy");

    is(seed_ready, false, "ccentropy_lock_add_entropy (seed_ready)");

    inner_err = 57;
    is(ccentropy_reset(ent_ctx),
       inner_err,
       "ccentropy_lock_reset");
}


int ccentropy_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(191203);

    ccentropy_rng_tests();
    ccentropy_digest_tests();
    ccentropy_list_tests();
    ccentropy_lock_tests();

    return 1;
}
#endif
