/* Copyright (c) (2020-2022) Apple Inc. All rights reserved.
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
#include "crypto_test_rng.h"
#include "cc_debug.h"
#include "ccrng_fortuna.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccsha2.h>
#include "cc_absolute_time.h"
#include "testmore.h"
#include "cc_priv.h"

#include <setjmp.h>
#include <unistd.h>

#include "ccshadow.h"

enum {
      OP_INIT,
      OP_REFRESH,
      OP_GENERATE
};

struct fortuna_pool_diag {
    uint64_t nsamples;
    uint64_t ndrains;
    uint64_t nsamples_max;
};

struct fortuna_vector {
    unsigned id;
    const char *note;
    unsigned nops;
    uint64_t nreseeds;
    uint64_t schedreseed_nsamples_max;
    uint64_t addentropy_nsamples_max;
    struct fortuna_pool_diag pools[CCRNG_FORTUNA_NPOOLS];
    const struct fortuna_op **ops;
};

struct fortuna_op {
    unsigned id;
    unsigned kind;
    bool abort;
};

struct fortuna_op_init {
    struct fortuna_op hd;
    unsigned max_ngens;
    ccrng_fortuna_getentropy getentropy;
};

struct fortuna_gen {
    unsigned gen_idx;
    uint8_t key[32];
};

struct fortuna_op_refresh {
    struct fortuna_op hd;
    int32_t entropy_nsamples;
    uint64_t rand;
    struct {
        bool reseed;
        uint64_t sched;
        const uint8_t key[32];
        unsigned pool_idx;
        struct {
            const uint8_t data[32];
            uint64_t nsamples;
        } pools[32];
    } out;
};

struct fortuna_op_generate {
    struct fortuna_op hd;
    int err;
    size_t rand_nbytes;
    struct {
        const uint8_t rand[512];
        const uint8_t key[32];
        const uint8_t ctr[16];
    } out;
};

struct kat_ctx {
    struct ccrng_fortuna_ctx ctx;
    bool reseed;
    uint8_t rand[512];
    int gen_err;
};

static jmp_buf env;

static void cc_abort_longjmp(CC_UNUSED const char *msg)
{
    longjmp(env, 1);
}

static uint64_t rand_static;
static bool cc_rdrand_static(uint64_t *rand)
{
    *rand = rand_static;
    return true;
}

static int32_t entropy_nsamples_static = 1024;

static int32_t get_entropy_all_ones(size_t *entropy_nbytes, void *entropy, void *arg)
{
    (void) arg;
    uint8_t *eb = (uint8_t *) entropy;
    for (size_t i = 0; i < *entropy_nbytes; i++) {
        eb[i] = 0x01;
    }
    return entropy_nsamples_static;
}

static void process_init(struct kat_ctx *kat_ctx, const struct fortuna_op *op)
{
    const struct fortuna_op_init *o = (const struct fortuna_op_init *)op;
    ccrng_fortuna_init(&kat_ctx->ctx, o->getentropy, NULL);
}

static void verify_init(struct kat_ctx *kat_ctx, const struct fortuna_op *op)
{
    (void) kat_ctx;
    (void) op;
}

static void process_refresh(struct kat_ctx *kat_ctx, const struct fortuna_op *op)
{
    const struct fortuna_op_refresh *o = (const struct fortuna_op_refresh *)op;
    rand_static = o->rand;
    entropy_nsamples_static = o->entropy_nsamples;
    
    uint64_t old_sched = kat_ctx->ctx.sched.reseed_sched;
    ccrng_fortuna_refresh(&kat_ctx->ctx);
    uint64_t new_sched = kat_ctx->ctx.sched.reseed_sched;
    
    kat_ctx->reseed = old_sched != new_sched;
}

static void verify_refresh(struct kat_ctx *kat_ctx, const struct fortuna_op *op)
{
    const struct fortuna_op_refresh *o = (const struct fortuna_op_refresh *)op;
    struct ccrng_fortuna_ctx *ctx = &kat_ctx->ctx;

    is(ctx->sched.pool_idx, o->out.pool_idx, "refresh pool_idx");
    for (unsigned i = 0; i < CCRNG_FORTUNA_NPOOLS; i += 1) {
        is(ctx->pools[i].nsamples, o->out.pools[i].nsamples, "refresh nsamples");
        ok_memcmp(ctx->pools[i].data, o->out.pools[i].data, sizeof(o->out.pools[i].data), "refresh data");
    }

    // We need to catch when we were reset during a reseed, hence the or
    ok((kat_ctx->reseed == o->out.reseed) || !ctx->seeded, "refresh reseed");
    ok_memcmp(ctx->key, o->out.key, sizeof(o->out.key), "refresh key");
}

static void process_generate(struct kat_ctx *kat_ctx, const struct fortuna_op *op)
{
    const struct fortuna_op_generate *o = (const struct fortuna_op_generate *)op;
    int err = ccrng_fortuna_generate(&kat_ctx->ctx, o->rand_nbytes, kat_ctx->rand);
    kat_ctx->gen_err = err;
}

static void verify_generate(struct kat_ctx *kat_ctx, const struct fortuna_op *op)
{
    const struct fortuna_op_generate *o = (const struct fortuna_op_generate *)op;

    ok(kat_ctx->gen_err == o->err, "generate rand return code");
    
    if (kat_ctx->gen_err == CCERR_OK) {
        ok_memcmp(kat_ctx->rand, o->out.rand, o->rand_nbytes, "generate rand");
        ok_memcmp(kat_ctx->ctx.key, o->out.key, sizeof(kat_ctx->ctx.key), "generate key (%d)", o->hd.id);
        ok_memcmp(kat_ctx->ctx.ctr, o->out.ctr, sizeof(kat_ctx->ctx.ctr), "generate ctr");
    }
}

typedef void (*process_fn_t)(struct kat_ctx *, const struct fortuna_op *);
typedef void (*verify_fn_t)(struct kat_ctx *, const struct fortuna_op *);

static bool diag_eq(const struct ccrng_fortuna_ctx *ctx1, const struct fortuna_vector *vec)
{
    bool eq = true;
    
    eq &= ctx1->nreseeds == vec->nreseeds;
    eq &= ctx1->schedreseed_nsamples_max == vec->schedreseed_nsamples_max;
    eq &= ctx1->addentropy_nsamples_max == vec->addentropy_nsamples_max;

    for (unsigned i = 0; i < CCRNG_FORTUNA_NPOOLS; i += 1) {
        eq &= ctx1->pools[i].nsamples == vec->pools[i].nsamples;
        eq &= ctx1->pools[i].ndrains == vec->pools[i].ndrains;
        eq &= ctx1->pools[i].nsamples_max == vec->pools[i].nsamples_max;
    }

    return eq;
}

#if !CC_LINUX && !defined(_MSC_VER) && !defined(__clang_analyzer__)
#include "../test_vectors/ccrng_fortuna_kat.inc"
static void ccfortuna_test_kat(const struct fortuna_vector *vec)
{
    struct kat_ctx kat_ctx;
    process_fn_t process_fns[] = {
                                  process_init,
                                  process_refresh,
                                  process_generate
    };
    verify_fn_t verify_fns[] = {
                                verify_init,
                                verify_refresh,
                                verify_generate
    };

    cc_clear(sizeof(kat_ctx), &kat_ctx);
    cc_abort_mock = cc_abort_longjmp;
    cc_rdrand_mock = cc_rdrand_static;

    for (unsigned i = 0; i < vec->nops; i += 1) {
        const struct fortuna_op *op = vec->ops[i];

        if (setjmp(env)) {
            ok(op->abort, "erroneous abort");
            goto cleanup;
        }

        // Reset ephemeral bits of state

        kat_ctx.reseed = false;
        cc_clear(sizeof(kat_ctx.rand), kat_ctx.rand);

        // Process vector
        process_fns[op->kind](&kat_ctx, op);

        // Verify results

        ok(!op->abort, "no abort");
        if (op->abort) {
            goto cleanup;
        }

        verify_fns[op->kind](&kat_ctx, op);
    }

    ok(diag_eq(&kat_ctx.ctx, vec), "incorrect diagnostics");

 cleanup:
    cc_abort_mock = NULL;
    cc_rdrand_mock = NULL;
}
#endif // !CC_LINUX && !defined(_MSC_VER) && !defined(__clang_analyzer__)

#if CC_TSAN
#include <pthread.h>

static struct ccrng_fortuna_ctx tsan_rng;

static int32_t ccrng_fortuna_getentropy_tsan(size_t *entropy_nbytes, void *entropy, void *arg)
{
    (void) arg;
    memset(entropy, 0x00, *entropy_nbytes);
    return 2048;
}

static void *fortuna_tsan_thread_generate(void *arg) {
    (void) arg;
    uint8_t generate[32] = {0};
    for (int i = 0; i < 10000; i++) {
        ccrng_fortuna_generate(&tsan_rng, sizeof(generate), generate);
    }
    return NULL;
}

static void *fortuna_tsan_thread_refresh(void *arg) {
    (void) arg;
    for (int i = 0; i < 10000; i++) {
        ccrng_fortuna_refresh(&tsan_rng);
    }
    return NULL;
}


static void fortuna_tsan_test() {
    cc_rdrand_mock = cc_rdrand_static;
    rand_static = 1234;
    ccrng_fortuna_init(&tsan_rng, ccrng_fortuna_getentropy_tsan, NULL);
    
    pthread_t t_generate, t_refresh;
    
    pthread_create(&t_generate, NULL, fortuna_tsan_thread_generate, NULL);
    pthread_create(&t_refresh, NULL, fortuna_tsan_thread_refresh, NULL);
    
    pthread_join(t_generate, NULL);
    pthread_join(t_refresh, NULL);
    cc_rdrand_mock = NULL;
}

#endif

int fortuna_test_kat(void) {
#if !CC_LINUX && !defined(_MSC_VER) && !defined(__clang_analyzer__)
    diag("Start Fortuna KAT Tests");
    
    for (unsigned i = 0; i < CC_ARRAY_LEN(test_vectors); i += 1) {
        ccfortuna_test_kat(test_vectors[i]);
    }
    
    diag("End Fortuna KAT Tests");
#endif
    
#if CC_TSAN
    diag("Starting Fortuna TSAN Tests");
    fortuna_tsan_test();
    diag("Finished Fortuna TSAN Tests");
#endif

    return 0;
}
