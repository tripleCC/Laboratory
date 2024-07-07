/* Copyright (c) (2014-2016,2018,2019,2022,2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec25519.h>
#include <corecrypto/ccsha2.h>

static double perf_cccurve25519_make_pub(size_t loops,
                                           CC_UNUSED size_t *size, CC_UNUSED const struct ccdigest_info *di)
{
    ccec25519secretkey sk;
    ccec25519pubkey pk;
    cccurve25519_make_priv(rng, sk);

    perf_start();
    do {
        cccurve25519_make_pub(pk, sk);
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_cccurve25519_make_key_pair(size_t loops,
                                         CC_UNUSED size_t *size, CC_UNUSED const struct ccdigest_info *di)
{
    ccec25519secretkey sk;
    ccec25519pubkey pk;

    perf_start();
    do {
        cccurve25519_make_key_pair(rng, pk, sk);
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_cced25519_make_key_pair(size_t loops, 
        CC_UNUSED size_t *psize, const struct ccdigest_info *di)
{
    ccec25519secretkey sk;
    ccec25519pubkey pk;

    perf_start();
    do {
        cced25519_make_key_pair(di, rng, pk, sk);
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_cced25519_sign(size_t loops, 
        size_t *psize, const struct ccdigest_info *di)
{
    ccec25519secretkey sk;
    ccec25519pubkey pk;
    cced25519_make_key_pair(di, rng, pk, sk);
    ccec25519signature sig;

    uint8_t msg[*psize];
    memset(msg,0xaa,*psize);

    perf_start();
    do {
        int status = cced25519_sign(di, sig, sizeof(msg), msg, pk, sk);
        if (status) cc_abort("Failure in cced25519_sign");
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_cced25519_verify(size_t loops, 
        size_t *psize, const struct ccdigest_info *di)
{
    ccec25519secretkey sk;
    ccec25519pubkey pk;
    cced25519_make_key_pair(di, rng, pk, sk);
    ccec25519signature sig;

    uint8_t msg[*psize];
    memset(msg,0xaa,*psize);

    int status = cced25519_sign(di, sig, sizeof(msg), msg, pk, sk);
    if (status) cc_abort("Failure in cced25519_sign");
    
    perf_start();
    do {
        int status=cced25519_verify(di, sizeof(msg), msg, sig,pk);
        if (status) cc_abort("Failure in cced25519_verify");
    } while (--loops != 0);
    return perf_seconds();
}

#define _TEST(_x,_di) { .name = #_x"("#_di")", .func = perf_ ## _x, .di = &_di}

static struct ccec25519_perf_test {
    const char *name;
    double(*func)(size_t loops, size_t *psize, const struct ccdigest_info *di);
    const struct ccdigest_info *di;
} ccec25519_perf_tests[] = {
    _TEST(cccurve25519_make_pub,ccsha512_ltc_di),
    _TEST(cccurve25519_make_key_pair,ccsha512_ltc_di),
    _TEST(cced25519_make_key_pair,ccsha512_ltc_di),
    _TEST(cced25519_sign,ccsha512_ltc_di),
    _TEST(cced25519_verify,ccsha512_ltc_di),
};

static double perf_ccec25519(size_t loops, CC_UNUSED size_t *psize, const void *arg)
{
    const struct ccec25519_perf_test *test=arg;
    // Message size of constant size 32
    size_t nbytes=32;
    return test->func(loops, &nbytes, test->di);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccec25519(int argc, char *argv[])
{
    F_GET_ALL(family, ccec25519);
    family.nsizes=1;
    family.sizes=malloc(family.nsizes*sizeof(size_t));
    family.sizes[0]=256;
    family.size_kind=ccperf_size_bits;
    return &family;
}
