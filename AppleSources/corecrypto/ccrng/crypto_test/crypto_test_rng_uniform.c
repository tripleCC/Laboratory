/* Copyright (c) (2018-2020,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrng.h>

#include "testmore.h"
#include "crypto_test_rng.h"

static double chisq(unsigned ncells, uint64_t *cells)
{
    unsigned i;
    double v = 0;
    uint64_t sum = 0;
    double Oi, Ei, vi;

    for (i = 0; i < ncells; i += 1) {
        sum += cells[i];
    }

    Ei = (double)sum / ncells;

    for (i = 0; i < ncells; i += 1) {
        Oi = (double)cells[i];
        vi = Oi - Ei;
        vi *= vi;
        vi /= Ei;
        v += vi;
    }

    return v;
}

int test_rng_uniform(void)
{
    struct ccrng_state* rng = global_test_rng;
    unsigned bound_nbits;
    uint64_t bound_mask;
    uint64_t bound;
    uint64_t rand;
    uint64_t cells[3] = {};
    unsigned i;
    double v;

    // Test some basic edge-case bounds.
    is(ccrng_uniform(rng, 0, &rand), CCERR_PARAMETER, "reject bound = 0");
    is(ccrng_uniform(rng, 1, &rand), CCERR_OK, "accept bound = 1");
    ok(rand == 0, "rand out of range (bound = 1)");
    is(ccrng_uniform(rng, UINT64_MAX, &rand), CCERR_OK, "accept bound = UINT64_MAX");
    ok(rand < UINT64_MAX, "rand out of range (bound = UINT64_MAX)");

    // Test with random bounds of random lengths.
    i = 0;
    while (i < (1 << 10)) {
        ccrng_generate(rng, sizeof(bound_nbits), &bound_nbits);
        bound_nbits &= 0x3f;    /* bound_nbits in [0, 63] */
        bound_nbits += 1;       /* bound_nbits in [1, 64] */

        bound_mask = (~0ULL) >> (64 - bound_nbits);

        ccrng_generate(rng, sizeof(bound), &bound);
        bound &= bound_mask;
        if (bound == 0) {
            continue;
        }

        is(ccrng_uniform(rng, bound, &rand), CCERR_OK, "accept bound = %llu", bound);
        ok(rand < bound, "rand out of range (bound = %llu)", bound);

        i += 1;
    }

    // This is a very weak statistical test designed to catch
    // catastrophic failures. It should not report false positives. It
    // does not attempt to do a rigorous statistical analysis of the
    // generated distribution.
    //
    // from R:
    //
    // > qchisq(1 - 2^-32, df=2)
    // [1] 44.36142
    //
    // If the null hypothesis (i.e. the function generates a uniform
    // distribution) is true, we should see a test statistic greater
    // than 44.36142 with probability 2^-32.
    //
    // In other words, if we fail this check, something is badly
    // broken. This is a basic sanity test and no more.

    for (i = 0; i < (1 << 20); i += 1) {
        is(ccrng_uniform(rng, 3, &rand), CCERR_OK, "accept bound = 3");
        ok(rand < 3, "rand out of range (bound = 3)");

        cells[rand] += 1;
    }

    v = chisq(3, cells);
    ok(v < 44.36142, "chi-squared: reject null hypothesis");

    return 1;
}
