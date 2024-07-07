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

#include "ccperf.h"
#include <corecrypto/ccec448.h>

static double perf_cccurve448_make_pub(size_t loops)
{
    ccec448secretkey sk;
    ccec448pubkey pk;

    if (cccurve448_make_priv(rng, sk)) {
        abort();
    }

    perf_start();

    do {
        if (cccurve448_make_pub(rng, pk, sk)) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_cccurve448_make_key_pair(size_t loops)
{
    ccec448secretkey sk;
    ccec448pubkey pk;

    perf_start();

    do {
        if (cccurve448_make_key_pair(rng, pk, sk)) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_cced448_make_key_pair(size_t loops)
{
    cced448pubkey pk;
    cced448secretkey sk;

    perf_start();

    do {
        if (cced448_make_key_pair(rng, pk, sk)) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_cced448_sign(size_t loops)
{
    cced448pubkey pk;
    cced448secretkey sk;

    if (cced448_make_key_pair(rng, pk, sk)) {
        abort();
    }

    uint8_t msg[32];
    cc_memset(msg, 0x5a, sizeof(msg));

    perf_start();

    do {
        cced448signature sig;
        if (cced448_sign(rng, sig, sizeof(msg), msg, pk, sk)) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_cced448_verify(size_t loops)
{
    cced448pubkey pk;
    cced448secretkey sk;

    if (cced448_make_key_pair(rng, pk, sk)) {
        abort();
    }

    uint8_t msg[32];
    cc_memset(msg, 0x5a, sizeof(msg));

    cced448signature sig;
    if (cced448_sign(rng, sig, sizeof(msg), msg, pk, sk)) {
        abort();
    }

    perf_start();

    do {
        if (cced448_verify(sizeof(msg), msg, sig, pk)) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}

static struct ccec448_perf_test {
    const char *name;
    double(*func)(size_t loops);
} ccec448_perf_tests[] = {
    _TEST(cccurve448_make_pub),
    _TEST(cccurve448_make_key_pair),
    _TEST(cced448_make_key_pair),
    _TEST(cced448_sign),
    _TEST(cced448_verify),
};

static double perf_ccec448(size_t loops, CC_UNUSED size_t *psize, const void *arg)
{
    return ((const struct ccec448_perf_test *)arg)->func(loops);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccec448(int argc, char *argv[])
{
    F_GET_ALL(family, ccec448);
    family.nsizes=1;
    family.sizes=malloc(family.nsizes*sizeof(size_t));
    family.sizes[0]=448;
    family.size_kind=ccperf_size_bits;
    return &family;
}
