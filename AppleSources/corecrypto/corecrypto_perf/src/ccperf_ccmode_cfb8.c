/* Copyright (c) (2011,2013-2016,2018,2019,2021,2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccaes.h>
#include "ccmode_internal.h"

/* mode created with the CFB8 factory */
static struct ccmode_cfb8 ccaes_generic_ltc_cfb8_encrypt_mode;
static struct ccmode_cfb8 ccaes_generic_ltc_cfb8_decrypt_mode;
#if CCAES_ARM_ASM
static struct ccmode_cfb8 ccaes_generic_arm_cfb8_encrypt_mode;
static struct ccmode_cfb8 ccaes_generic_arm_cfb8_decrypt_mode;
#endif

#define CCMODE_CFB8_TEST(_mode, _keylen) { .name=#_mode"_"#_keylen, .cfb8=&_mode, .keylen=_keylen }

static struct cccfb8_perf_test {
    const char *name;
    const struct ccmode_cfb8 *cfb8;
    size_t keylen;
} cccfb8_perf_tests[] = {
    CCMODE_CFB8_TEST(ccaes_generic_ltc_cfb8_encrypt_mode, 16),
    CCMODE_CFB8_TEST(ccaes_generic_ltc_cfb8_decrypt_mode, 16),
    CCMODE_CFB8_TEST(ccaes_generic_ltc_cfb8_encrypt_mode, 24),
    CCMODE_CFB8_TEST(ccaes_generic_ltc_cfb8_decrypt_mode, 24),
    CCMODE_CFB8_TEST(ccaes_generic_ltc_cfb8_encrypt_mode, 32),
    CCMODE_CFB8_TEST(ccaes_generic_ltc_cfb8_decrypt_mode, 32),

#if CCAES_ARM_ASM
    CCMODE_CFB8_TEST(ccaes_generic_arm_cfb8_encrypt_mode, 16),
    CCMODE_CFB8_TEST(ccaes_generic_arm_cfb8_decrypt_mode, 16),
    CCMODE_CFB8_TEST(ccaes_generic_arm_cfb8_encrypt_mode, 24),
    CCMODE_CFB8_TEST(ccaes_generic_arm_cfb8_decrypt_mode, 24),
    CCMODE_CFB8_TEST(ccaes_generic_arm_cfb8_encrypt_mode, 32),
    CCMODE_CFB8_TEST(ccaes_generic_arm_cfb8_decrypt_mode, 32),
#endif
};

static double perf_cccfb8_init(size_t loops, size_t *psize  CC_UNUSED, const void *arg)
{
    const struct cccfb8_perf_test *test=arg;
    const struct ccmode_cfb8 *cfb8=test->cfb8;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    unsigned char ivd[cfb8->block_size];

    cc_clear(keylen,keyd);
    cccfb8_ctx_decl(cfb8->size, key);
    cc_clear(sizeof(ivd),ivd);

    perf_start();
    while(loops--)
        cccfb8_init(cfb8, key, keylen, keyd, ivd);

    return perf_seconds();
}

static double perf_cccfb8_update(size_t loops, size_t *psize, const void *arg)
{
    const struct cccfb8_perf_test *test=arg;
    const struct ccmode_cfb8 *cfb8=test->cfb8;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/cfb8->block_size;

    unsigned char keyd[keylen];
    unsigned char ivd[cfb8->block_size];
    unsigned char *temp = malloc(nblocks*cfb8->block_size);

    cc_clear(keylen,keyd);
    cc_clear(sizeof(ivd),ivd);
    cccfb8_ctx_decl(cfb8->size, key);

    cccfb8_init(cfb8, key, keylen, keyd, ivd);

    perf_start();
    while(loops--)
        cccfb8_update(cfb8, key, *psize, temp, temp);

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static double perf_cccfb8_one_shot(size_t loops, size_t *psize, const void *arg)
{
    const struct cccfb8_perf_test *test=arg;
    const struct ccmode_cfb8 *cfb8=test->cfb8;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/cfb8->block_size;

    unsigned char keyd[keylen];
    unsigned char ivd[cfb8->block_size];
    unsigned char *temp = malloc(nblocks*cfb8->block_size);

    cc_clear(keylen,keyd);
    cc_clear(sizeof(ivd),ivd);

    perf_start();
    while(loops--) {
        cccfb8_one_shot(cfb8,keylen, keyd, ivd, *psize, temp, temp);
    }

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}


static void ccperf_family_cccfb8_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    ccmode_factory_cfb8_encrypt(&ccaes_generic_ltc_cfb8_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_cfb8_decrypt(&ccaes_generic_ltc_cfb8_decrypt_mode, &ccaes_ltc_ecb_decrypt_mode);
#if CCAES_ARM_ASM
    ccmode_factory_cfb8_encrypt(&ccaes_generic_arm_cfb8_encrypt_mode, &ccaes_arm_ecb_encrypt_mode);
    ccmode_factory_cfb8_decrypt(&ccaes_generic_arm_cfb8_decrypt_mode, &ccaes_arm_ecb_decrypt_mode);
#endif

}

F_DEFINE(cccfb8, init,     ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(cccfb8, update,   ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(cccfb8, one_shot, ccperf_size_bytes, symmetric_crypto_data_nbytes)
