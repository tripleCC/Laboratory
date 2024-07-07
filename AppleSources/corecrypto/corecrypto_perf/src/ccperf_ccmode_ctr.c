/* Copyright (c) (2011,2013-2019,2021-2023) Apple Inc. All rights reserved.
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
#include "ccaes_vng_ctr.h"

/* mode created with the CTR factory */
static struct ccmode_ctr ccaes_generic_ltc_ctr_crypt_mode;
static struct ccmode_ctr ccaes_default_aes_ctr_crypt_mode;

#if CCMODE_CTR_VNG_SPEEDUP
static struct ccmode_ctr ccaes_vng_aes_ctr_crypt_mode;
#endif

#define CCMODE_CTR_TEST(_mode, _keylen) { .name=#_mode"_"#_keylen, .ctr=&_mode, .keylen=_keylen }

static struct ccctr_perf_test {
    const char *name;
    const struct ccmode_ctr *ctr;
    size_t keylen;
} ccctr_perf_tests[] = {
    CCMODE_CTR_TEST(ccaes_default_aes_ctr_crypt_mode, 16),
    CCMODE_CTR_TEST(ccaes_default_aes_ctr_crypt_mode, 24),
    CCMODE_CTR_TEST(ccaes_default_aes_ctr_crypt_mode, 32),

    CCMODE_CTR_TEST(ccaes_generic_ltc_ctr_crypt_mode, 16),
    CCMODE_CTR_TEST(ccaes_generic_ltc_ctr_crypt_mode, 24),
    CCMODE_CTR_TEST(ccaes_generic_ltc_ctr_crypt_mode, 32),

#if CCMODE_CTR_VNG_SPEEDUP
    CCMODE_CTR_TEST(ccaes_vng_aes_ctr_crypt_mode, 16),
    CCMODE_CTR_TEST(ccaes_vng_aes_ctr_crypt_mode, 24),
    CCMODE_CTR_TEST(ccaes_vng_aes_ctr_crypt_mode, 32),
#endif

};

static double perf_ccctr_init(size_t loops, size_t *psize  CC_UNUSED, const void *arg)
{
    const struct ccctr_perf_test *test=arg;
    const struct ccmode_ctr *ctr=test->ctr;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    unsigned char ivd[ctr->block_size];

    cc_clear(keylen,keyd);
    ccctr_ctx_decl(ctr->size, key);

    perf_start();
    while(loops--) {
        int ret;
        ret=ccctr_init(ctr, key, keylen, keyd, ivd);
        if (ret) return 0;
    }

    return perf_seconds();
}

static double perf_ccctr_update(size_t loops, size_t *psize, const void *arg)
{
    const struct ccctr_perf_test *test=arg;
    const struct ccmode_ctr *ctr=test->ctr;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/ctr->block_size;

    unsigned char keyd[keylen];
    unsigned char ivd[ctr->block_size];
    unsigned char *temp = malloc(nblocks*ctr->block_size);

    cc_clear(keylen,keyd);
    cc_clear(sizeof(ivd),ivd);
    ccctr_ctx_decl(ctr->size, key);

    int ret;
    ret=ccctr_init(ctr, key, keylen, keyd, ivd);
    if (ret) return 0;

    perf_start();
    while(loops--) {
        ret=ccctr_update(ctr,key, *psize, temp, temp);
        if (ret) abort();
    }

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static double perf_ccctr_one_shot(size_t loops, size_t *psize, const void *arg)
{
    const struct ccctr_perf_test *test=arg;
    const struct ccmode_ctr *ctr=test->ctr;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/ctr->block_size;

    unsigned char keyd[keylen];
    unsigned char ivd[ctr->block_size];
    unsigned char *temp = malloc(nblocks*ctr->block_size);

    cc_clear(keylen,keyd);
    cc_clear(sizeof(ivd),ivd);

    perf_start();
    while(loops--) {
        int ret=ccctr_one_shot(ctr,keylen, keyd, ivd, *psize, temp, temp);
        if (ret) return 0;
    }

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}


static void ccperf_family_ccctr_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    ccmode_factory_ctr_crypt(&ccaes_generic_ltc_ctr_crypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccaes_default_aes_ctr_crypt_mode=*ccaes_ctr_crypt_mode();
#if CCMODE_CTR_VNG_SPEEDUP
    ccaes_vng_ctr_crypt_mode_setup(&ccaes_vng_aes_ctr_crypt_mode);
#endif
}

F_DEFINE(ccctr, init,     ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccctr, update,   ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(ccctr, one_shot, ccperf_size_bytes, symmetric_crypto_data_nbytes)
