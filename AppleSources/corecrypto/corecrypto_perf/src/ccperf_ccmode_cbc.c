/* Copyright (c) (2011-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_priv.h>

/* mode created with the CBC factory */
static struct ccmode_cbc ccaes_generic_ltc_cbc_encrypt_mode;
static struct ccmode_cbc ccaes_generic_ltc_cbc_decrypt_mode;

static struct ccmode_cbc ccaes_default_cbc_encrypt_mode;
static struct ccmode_cbc ccaes_default_cbc_decrypt_mode;

#define CCMODE_CBC_TEST(_mode, _keylen) { .name=#_mode"_"#_keylen, .cbc=&_mode, .keylen=_keylen }

static struct cccbc_perf_test {
    const char *name;
    const struct ccmode_cbc *cbc;
    size_t keylen;
} cccbc_perf_tests[] = {
    CCMODE_CBC_TEST(ccaes_default_cbc_encrypt_mode, 16),
    CCMODE_CBC_TEST(ccaes_default_cbc_decrypt_mode, 16),
    CCMODE_CBC_TEST(ccaes_default_cbc_encrypt_mode, 24),
    CCMODE_CBC_TEST(ccaes_default_cbc_decrypt_mode, 24),
    CCMODE_CBC_TEST(ccaes_default_cbc_encrypt_mode, 32),
    CCMODE_CBC_TEST(ccaes_default_cbc_decrypt_mode, 32),

    CCMODE_CBC_TEST(ccaes_generic_ltc_cbc_encrypt_mode, 16),
    CCMODE_CBC_TEST(ccaes_generic_ltc_cbc_decrypt_mode, 16),
    CCMODE_CBC_TEST(ccaes_generic_ltc_cbc_encrypt_mode, 24),
    CCMODE_CBC_TEST(ccaes_generic_ltc_cbc_decrypt_mode, 24),
    CCMODE_CBC_TEST(ccaes_generic_ltc_cbc_encrypt_mode, 32),
    CCMODE_CBC_TEST(ccaes_generic_ltc_cbc_decrypt_mode, 32),

    CCMODE_CBC_TEST(ccaes_gladman_cbc_encrypt_mode, 16),
    CCMODE_CBC_TEST(ccaes_gladman_cbc_decrypt_mode, 16),
    CCMODE_CBC_TEST(ccaes_gladman_cbc_encrypt_mode, 24),
    CCMODE_CBC_TEST(ccaes_gladman_cbc_decrypt_mode, 24),
    CCMODE_CBC_TEST(ccaes_gladman_cbc_encrypt_mode, 32),
    CCMODE_CBC_TEST(ccaes_gladman_cbc_decrypt_mode, 32),

#if CCAES_ARM_ASM
    CCMODE_CBC_TEST(ccaes_arm_cbc_encrypt_mode, 16),
    CCMODE_CBC_TEST(ccaes_arm_cbc_decrypt_mode, 16),
    CCMODE_CBC_TEST(ccaes_arm_cbc_encrypt_mode, 24),
    CCMODE_CBC_TEST(ccaes_arm_cbc_decrypt_mode, 24),
    CCMODE_CBC_TEST(ccaes_arm_cbc_encrypt_mode, 32),
    CCMODE_CBC_TEST(ccaes_arm_cbc_decrypt_mode, 32),
#endif

};

static double perf_cccbc_init(size_t loops, size_t *psize CC_UNUSED, const void *arg)
{
    const struct cccbc_perf_test *test=arg;
    const struct ccmode_cbc *cbc=test->cbc;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];

    cc_clear(keylen,keyd);
    cccbc_ctx_decl(cbc->size, key);

    perf_start();
    while(loops--)
        cccbc_init(cbc, key, keylen, keyd);

    return perf_seconds();
}

static double perf_cccbc_update(size_t loops, size_t *psize, const void *arg)
{
    const struct cccbc_perf_test *test=arg;
    const struct ccmode_cbc *cbc=test->cbc;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/cbc->block_size;

    unsigned char keyd[keylen];
    unsigned char *temp = malloc(nblocks*cbc->block_size);

    cc_clear(keylen,keyd);
    cccbc_ctx_decl(cbc->size, key);
    cccbc_iv_decl(cbc->block_size, iv);

    cccbc_init(cbc, key, keylen, keyd);
    cccbc_set_iv(cbc, iv, NULL);

    perf_start();
    while(loops--)
        cccbc_update(cbc, key, iv, nblocks, temp, temp);

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static double perf_cccbc_one_shot(size_t loops, size_t *psize, const void *arg)
{
    const struct cccbc_perf_test *test=arg;
    const struct ccmode_cbc *cbc=test->cbc;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/cbc->block_size;

    unsigned char keyd[keylen];
    unsigned char *temp = malloc(nblocks*cbc->block_size);

    cc_clear(keylen,keyd);
    perf_start();
    while(loops--) {
        if (cccbc_one_shot(cbc, keylen, keyd, NULL, nblocks, temp, temp)) {
            abort();
        }
    }

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}


static void ccperf_family_cccbc_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    ccmode_factory_cbc_encrypt(&ccaes_generic_ltc_cbc_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_cbc_decrypt(&ccaes_generic_ltc_cbc_decrypt_mode, &ccaes_ltc_ecb_decrypt_mode);
    ccaes_default_cbc_encrypt_mode=*ccaes_cbc_encrypt_mode();
    ccaes_default_cbc_decrypt_mode=*ccaes_cbc_decrypt_mode();
}

F_DEFINE(cccbc, init,     ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(cccbc, update,   ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(cccbc, one_shot, ccperf_size_bytes, symmetric_crypto_data_nbytes)
