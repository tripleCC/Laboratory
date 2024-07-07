/* Copyright (c) (2014-2019,2021-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/cccmac.h>
#include <corecrypto/ccaes.h>
#include "ccmode_internal.h"
#include <corecrypto/cc_priv.h>

/* mode created with the CBC factory */
static struct ccmode_cbc ccaes_generic_ltc_cbc_encrypt_mode;

#if CCAES_INTEL_ASM
/* intel */
static struct ccmode_cbc ccaes_intel_cbc_encrypt_mode;
#endif

#define CCMODE_CBC_TEST(_mode, _keylen) { .name="cccmac_"#_mode"_"#_keylen, .cbc=&cc##_mode, .keylen=_keylen }

static struct cccmac_perf_test {
    const char *name;
    const struct ccmode_cbc *cbc;
    size_t keylen;
} cccmac_perf_tests[] = {
    CCMODE_CBC_TEST(aes_generic_ltc_cbc_encrypt_mode,16),
    CCMODE_CBC_TEST(aes_gladman_cbc_encrypt_mode,16),
#if CCAES_INTEL_ASM
    CCMODE_CBC_TEST(aes_intel_cbc_encrypt_mode,16),
#endif
#if CCAES_ARM_ASM
    CCMODE_CBC_TEST(aes_arm_cbc_encrypt_mode,16),
#endif
    CCMODE_CBC_TEST(aes_generic_ltc_cbc_encrypt_mode,24),
    CCMODE_CBC_TEST(aes_gladman_cbc_encrypt_mode,24),
#if CCAES_INTEL_ASM
    CCMODE_CBC_TEST(aes_intel_cbc_encrypt_mode,24),
#endif
#if CCAES_ARM_ASM
    CCMODE_CBC_TEST(aes_arm_cbc_encrypt_mode,24),
#endif
    CCMODE_CBC_TEST(aes_generic_ltc_cbc_encrypt_mode,32),
    CCMODE_CBC_TEST(aes_gladman_cbc_encrypt_mode,32),
#if CCAES_INTEL_ASM
    CCMODE_CBC_TEST(aes_intel_cbc_encrypt_mode,32),
#endif
#if CCAES_ARM_ASM
    CCMODE_CBC_TEST(aes_arm_cbc_encrypt_mode,32),
#endif
};

static double perf_cccmac(size_t loops, size_t *psize, const void *arg)
{
    const struct cccmac_perf_test *test=arg;
    unsigned char mac[test->cbc->block_size];
    unsigned char key[test->keylen];
    unsigned char *data = malloc(*psize);

    cc_clear(test->keylen,key);

    perf_start();
    do {
        cccmac_one_shot_generate(test->cbc, test->keylen, key,
               *psize, data, sizeof(mac), mac);
    } while (--loops != 0);

    double seconds = perf_seconds();
    free(data);
    return seconds;
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_cccmac(int argc, char *argv[])
{
    ccmode_factory_cbc_encrypt(&ccaes_generic_ltc_cbc_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
#if CCAES_INTEL_ASM
    if (CC_HAS_AESNI())
    {
        memcpy(&ccaes_intel_cbc_encrypt_mode,
                                   &ccaes_intel_cbc_encrypt_aesni_mode, sizeof(struct ccmode_cbc));
    }
    else
    {
        memcpy(&ccaes_intel_cbc_encrypt_mode,
                                   &ccaes_intel_cbc_encrypt_opt_mode, sizeof(struct ccmode_cbc));
    }
#endif
    F_GET_ALL(family, cccmac);
    const size_t sizes[]={32,256,4096,4*4096};
    F_SIZES_FROM_ARRAY(family, sizes);
    family.size_kind=ccperf_size_bytes;
    return &family;
}

