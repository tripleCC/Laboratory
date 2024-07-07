/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccperf.h"
#include <corecrypto/cckyber.h>
#include "cckem_internal.h"

static double perf_cckem_generate_key(size_t loops, const struct cckem_info *info)
{
    cckem_full_ctx_decl(info, ctx);
    cckem_full_ctx_init(ctx, info);

    perf_start();
    while (loops--) {
        int status = cckem_generate_key(ctx, rng);
        if (status)
            abort();
    }
    return perf_seconds();
}

static double perf_cckem_encapsulate(size_t loops, const struct cckem_info *info)
{
    uint8_t ek[cckem_encapsulated_key_nbytes_info(info)];
    uint8_t k[cckem_shared_key_nbytes_info(info)];

    cckem_full_ctx_decl(info, ctx);
    cckem_full_ctx_init(ctx, info);

    cckem_generate_key(ctx, rng);
    cckem_pub_ctx_t pubctx = cckem_public_ctx(ctx);

    perf_start();
    while (loops--) {
        int status = cckem_encapsulate(pubctx, cckem_encapsulated_key_nbytes_info(info), ek, cckem_shared_key_nbytes_info(info), k, rng);
        if (status)
            abort();
    }
    return perf_seconds();
}

static double perf_cckem_decapsulate(size_t loops, const struct cckem_info *info)
{
    uint8_t ek[cckem_encapsulated_key_nbytes_info(info)];
    uint8_t k_encaps[cckem_shared_key_nbytes_info(info)];
    uint8_t k_decaps[cckem_shared_key_nbytes_info(info)];

    cckem_full_ctx_decl(info, ctx);
    cckem_full_ctx_init(ctx, info);

    cckem_generate_key(ctx, rng);
    cckem_pub_ctx_t pubctx = cckem_public_ctx(ctx);
    cckem_encapsulate(pubctx, cckem_encapsulated_key_nbytes_info(info), ek, cckem_shared_key_nbytes_info(info), k_encaps, rng);

    perf_start();
    while (loops--) {
        int status = cckem_decapsulate(ctx, cckem_encapsulated_key_nbytes_info(info), ek, cckem_shared_key_nbytes_info(info), k_decaps);
        if (status)
            abort();
    }
    return perf_seconds();
}

#define _TEST(_x)                      \
    {                                  \
        .name = #_x, .func = perf_##_x \
    }
static struct cckem_perf_test {
    const char *name;
    double (*func)(size_t loops, const struct cckem_info *info);
} cckem_perf_tests[] = {
    _TEST(cckem_generate_key),
    _TEST(cckem_encapsulate),
    _TEST(cckem_decapsulate),
};

static double perf_cckem(size_t loops, size_t *sig_id, const void *arg)
{
    const struct cckem_perf_test *test = arg;

    const struct cckem_info *info = NULL;
    if (*sig_id == 768) {
        info = cckem_kyber768();
    } else if (*sig_id == 1024) {
        info = cckem_kyber1024();
    } else {
        abort();
    }

    return test->func(loops, info);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_cckem(int argc, char *argv[])
{
    F_GET_ALL(family, cckem);
    static const size_t sig_ids[] = { 768, 1024 };
    F_SIZES_FROM_ARRAY(family, sig_ids);

    return &family;
}
