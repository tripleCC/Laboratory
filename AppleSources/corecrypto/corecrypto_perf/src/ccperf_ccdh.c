/* Copyright (c) (2014-2016,2018-2020,2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdh.h>
#include <corecrypto/ccdh_gp.h>

#define _TEST(_x)     { .name = "ccdh_gp_" #_x, .gp=ccdh_gp_ ## _x}
#define _TEST_SRP(_x) { .name = "ccsrp_gp_" #_x, .gp=ccsrp_gp_ ## _x}
static struct ccdh_perf_test {
    const char *name;
    ccdh_const_gp_t(*gp)(void);
} ccdh_perf_tests[] = {
    _TEST(apple768),
    _TEST(rfc5114_MODP_1024_160),
    _TEST(rfc5114_MODP_2048_224),
    _TEST(rfc5114_MODP_2048_256),
    _TEST(rfc3526group05),
    _TEST(rfc3526group14),
    _TEST(rfc3526group15),
    _TEST(rfc3526group16),
    _TEST(rfc3526group17),
    _TEST(rfc3526group18),
    _TEST_SRP(rfc5054_1024),
    _TEST_SRP(rfc5054_2048),
    _TEST_SRP(rfc5054_3072),
    _TEST_SRP(rfc5054_4096),
    _TEST_SRP(rfc5054_8192),
};

static struct ccdh_full_ctx * gkey=NULL;

static void update_gkey(ccdh_const_gp_t gp) {

    if (gkey==NULL
        || (ccn_cmp(ccdh_gp_n(gp),ccdh_gp_prime(gp),ccdh_gp_prime(ccdh_ctx_gp(gkey))))
        || (ccn_cmp(ccdh_gp_n(gp),ccdh_gp_g(gp),ccdh_gp_g(ccdh_ctx_gp(gkey))))
        ) {
        gkey = realloc(gkey, ccdh_full_ctx_size(ccdh_ccn_size(gp)));
        int status=ccdh_generate_key(gp, rng, gkey);
        if (status) cc_abort("Failure in ccdh_generate_key");
    }
}

static double perf_ccdh_generate_key(size_t loops, cc_size *pnbits, const void *arg)
{
    const struct ccdh_perf_test* test=arg;
    ccdh_const_gp_t gp=test->gp();
    *pnbits=ccdh_gp_prime_bitlen(gp);
    const cc_size n = ccdh_gp_n(gp);
    const size_t s = ccn_sizeof_n(n);
    ccdh_full_ctx_decl(s, alice);

    perf_start();
    do {
        int status = ccdh_generate_key(gp, rng, alice);
        if (status) cc_abort("Failure in ccdh_generate_key");
    } while (--loops != 0);
    return perf_seconds();
}


static double perf_ccdh_compute_shared_secret(size_t loops, cc_size *pnbits CC_UNUSED, const void *arg)
{
    const struct ccdh_perf_test* test=arg;
    ccdh_const_gp_t gp=test->gp();
    *pnbits=ccdh_gp_prime_bitlen(gp);
    const cc_size n = ccdh_gp_n(gp);
    const size_t s = ccn_sizeof_n(n);
    ccdh_full_ctx_decl(s, bob);
    size_t original_len = s;
    size_t tmp_len=s;
    uint8_t tmp[s];

    update_gkey(test->gp());
    if (ccdh_generate_key(gp, rng, bob)) {
        cc_abort("Failure in ccdh_generate_key");
    }

    perf_start();
    do {
        int status=ccdh_compute_shared_secret(gkey, ccdh_ctx_public(bob), &tmp_len,tmp,rng);
        tmp_len = original_len;
        if (status) cc_abort("Failure in ccdh_compute_shared_secret");
    } while (--loops != 0);
    return perf_seconds();
}

static void ccperf_family_ccdh_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
}

F_DEFINE(ccdh, generate_key,     ccperf_size_iterations, 1)
F_DEFINE(ccdh, compute_shared_secret,   ccperf_size_iterations, 1)

