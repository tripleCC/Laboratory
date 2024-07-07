/* Copyright (c) (2021-2023) Apple Inc. All rights reserved.
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
#include "cckeccak_internal.h"
#include "ccsha3_internal.h"
#include "cc_runtime_config.h"
#include "AccelerateCrypto.h"

#if defined(__arm64__) && CCSHA3_VNG_ARM
static void cckeccak_f1600_vng_hwassist(cckeccak_state_t state)
{
#if CC_INTERNAL_SDK
    if (CC_HAS_SHA3()) {
        AccelerateCrypto_SHA3_keccak_hwassist((uint64_t *)state);
    } else
#endif
    {
        AccelerateCrypto_SHA3_keccak((uint64_t *)state);
    }
}

static void cckeccak_f1600_vng(cckeccak_state_t state)
{
    AccelerateCrypto_SHA3_keccak((uint64_t *)state);
}
#endif

#if defined(__x86_64__) && CCSHA3_VNG_INTEL
static void cckeccak_f1600_vng(cckeccak_state_t state)
{
    if (CC_HAS_BMI2()) {
        AccelerateCrypto_SHA3_keccak((uint64_t *)state);
    } else {
        cckeccak_f1600_c(state);
    }
}
#endif

static double perf_cckeccak_absorb(size_t loops, cc_size n, cckeccak_permutation permutation)
{
    unsigned char *in = malloc(n);
    ccrng_generate(rng, n, in);

    perf_start();
    while (loops--) {
        struct cckeccak_state state;
        cckeccak_init_state(&state);
        cckeccak_absorb_and_pad(&state, 136, n, in, 0x06, permutation);
    }

    double seconds = perf_seconds();
    free(in);
    return seconds;
}

static double perf_cckeccak_absorb_squeeze(size_t loops, cc_size n, cckeccak_permutation permutation)
{
    unsigned char *in = malloc(n);
    unsigned char *out = malloc(n);
    ccrng_generate(rng, n, in);
    perf_start();
    while (loops--) {
        struct cckeccak_state state;
        cckeccak_init_state(&state);
        cckeccak_absorb_and_pad(&state, 136, n, in, 0x06, permutation);
        cckeccak_squeeze(&state, 136, n, out, permutation);
    }

    double seconds = perf_seconds();
    free(in);
    free(out);
    return seconds;
}

#define _TEST(_x, _y)                                        \
    {                                                        \
        .name = #_x#_y, .func = perf_##_x, .permutation = &_y\
    }
static struct cckeccak_perf_test {
    const char *name;
    const cckeccak_permutation permutation;
    double (*func)(size_t loops, cc_size n, cckeccak_permutation permutation);
} cckeccak_perf_tests[] = {
    _TEST(cckeccak_absorb, cckeccak_f1600_c),
    _TEST(cckeccak_absorb_squeeze, cckeccak_f1600_c),
#if defined(__arm64__) && CCSHA3_VNG_ARM
    _TEST(cckeccak_absorb, cckeccak_f1600_vng_hwassist),
    _TEST(cckeccak_absorb_squeeze, cckeccak_f1600_vng_hwassist),
    _TEST(cckeccak_absorb, cckeccak_f1600_vng),
    _TEST(cckeccak_absorb_squeeze, cckeccak_f1600_vng),
#elif defined(__x86_64__) && CCSHA3_VNG_INTEL
    _TEST(cckeccak_absorb, cckeccak_f1600_vng),
    _TEST(cckeccak_absorb_squeeze, cckeccak_f1600_vng),
#endif
};

static double perf_cckeccak(size_t loops, size_t *psize, const void *arg)
{
    const struct cckeccak_perf_test *test = arg;
    return test->func(loops, *psize, *test->permutation);;
}

static struct ccperf_family family;
static const size_t sizes[] = { 16, 200, 200 * 100 };

struct ccperf_family *ccperf_family_cckeccak(int argc, char *argv[])
{
    F_GET_ALL(family, cckeccak);
    F_SIZES_FROM_ARRAY(family, sizes);
    family.size_kind = ccperf_size_bytes;
    return &family;
}
