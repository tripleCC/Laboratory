/* Copyright (c) (2019,2021) Apple Inc. All rights reserved.
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
#include "cc_priv.h"
#include <corecrypto/ccvrf.h>

static double perf_ccvrf_test_prove(size_t loops, size_t nbytes)
{
    uint8_t message[nbytes];
    memset(message, 0xFE, nbytes);

    struct ccvrf ctx;
    ccvrf_factory_irtfdraft03_default(&ctx);
    uint8_t secretkey[ccvrf_sizeof_secret_key(&ctx)];
    memset(secretkey, 0xFE, ccvrf_sizeof_secret_key(&ctx));

    uint8_t proof[ccvrf_sizeof_proof(&ctx)];

    perf_start();
    do {
        int result = ccvrf_prove(&ctx, sizeof(secretkey), secretkey, sizeof(message), message, sizeof(proof), proof);
        if (result != CCERR_OK) abort();
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_ccvrf_test_proof_to_hash(size_t loops, size_t nbytes)
{
    uint8_t message[nbytes];
    memset(message, 0xFE, nbytes);

    struct ccvrf ctx;
    ccvrf_factory_irtfdraft03_default(&ctx);
    uint8_t secretkey[ccvrf_sizeof_secret_key(&ctx)];
    memset(secretkey, 0xFE, ccvrf_sizeof_secret_key(&ctx));

    uint8_t proof[ccvrf_sizeof_proof(&ctx)];
    uint8_t hash[ccvrf_sizeof_hash(&ctx)];

    int result = ccvrf_prove(&ctx, sizeof(secretkey), secretkey, sizeof(message), message, sizeof(proof), proof);
    
    perf_start();
    do {
        result |= ccvrf_proof_to_hash(&ctx, sizeof(proof), proof, sizeof(hash), hash);
        if (result != CCERR_OK) abort();
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_ccvrf_test_verify(size_t loops, size_t nbytes)
{
    uint8_t message[nbytes];
    memset(message, 0xFE, nbytes);

    struct ccvrf ctx;
    ccvrf_factory_irtfdraft03_default(&ctx);
    uint8_t secretkey[ccvrf_sizeof_secret_key(&ctx)];
    memset(secretkey, 0xFE, ccvrf_sizeof_secret_key(&ctx));

    uint8_t proof[ccvrf_sizeof_proof(&ctx)];
    uint8_t pk[ccvrf_sizeof_public_key(&ctx)];
    ccvrf_derive_public_key(&ctx, ccvrf_sizeof_secret_key(&ctx), secretkey, ccvrf_sizeof_public_key(&ctx), pk);
    int result = ccvrf_prove(&ctx, sizeof(secretkey), secretkey, sizeof(message), message, sizeof(proof), proof);
    if (result != CCERR_OK) cc_abort("ccvrf_prove failed");

    perf_start();
    do {
        result = ccvrf_verify(&ctx, sizeof(pk), pk, sizeof(message), message, sizeof(proof), proof);
        if (result != CCERR_OK) abort();
    } while (--loops != 0);

    return perf_seconds();
}

#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct ccvrf_perf_test {
    const char *name;
    double (*func)(size_t loops, cc_size n);
} ccvrf_perf_tests[] = {
    _TEST(ccvrf_test_prove),
    _TEST(ccvrf_test_proof_to_hash),
    _TEST(ccvrf_test_verify),
};

static double perf_ccvrf(size_t loops, size_t *psize, const void *arg)
{
    const struct ccvrf_perf_test *test = arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccvrf(int argc, char *argv[])
{
    F_GET_ALL(family, ccvrf);
    static const size_t group_nbytes[] = { 32, 64, 128, 256, 512, 1024 };
    F_SIZES_FROM_ARRAY(family, group_nbytes);
    family.size_kind = ccperf_size_bytes;
    return &family;
}
