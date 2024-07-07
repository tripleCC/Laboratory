/* Copyright (c) (2015,2016,2018,2019,2021,2023) Apple Inc. All rights reserved.
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

/* mode created with the ccm factory */

static struct ccmode_ccm ccaes_default_ccm_encrypt_mode;
static struct ccmode_ccm ccaes_default_ccm_decrypt_mode;

static struct ccmode_ccm ccaes_generic_ltc_ccm_encrypt_mode;
static struct ccmode_ccm ccaes_generic_ltc_ccm_decrypt_mode;

#if CCAES_ARM_ASM
static struct ccmode_ccm ccaes_generic_arm_ccm_encrypt_mode;
static struct ccmode_ccm ccaes_generic_arm_ccm_decrypt_mode;
#elif CCAES_INTEL_ASM
static struct ccmode_ccm ccaes_generic_intel_ccm_encrypt_mode;
static struct ccmode_ccm ccaes_generic_intel_ccm_decrypt_mode;
#endif

#define CCMODE_CCM_TEST(_mode, _keylen) { .name=#_mode"_"#_keylen, .ccm=&_mode, .keylen=_keylen }

static struct ccccm_perf_test {
    const char *name;
    const struct ccmode_ccm *ccm;
    size_t keylen;
} ccccm_perf_tests[] = {
    CCMODE_CCM_TEST(ccaes_generic_ltc_ccm_encrypt_mode, 16),
    CCMODE_CCM_TEST(ccaes_generic_ltc_ccm_decrypt_mode, 16),
    CCMODE_CCM_TEST(ccaes_generic_ltc_ccm_encrypt_mode, 24),
    CCMODE_CCM_TEST(ccaes_generic_ltc_ccm_decrypt_mode, 24),
    CCMODE_CCM_TEST(ccaes_generic_ltc_ccm_encrypt_mode, 32),
    CCMODE_CCM_TEST(ccaes_generic_ltc_ccm_decrypt_mode, 32),

#if CCAES_ARM_ASM
    CCMODE_CCM_TEST(ccaes_generic_arm_ccm_encrypt_mode, 16),
    CCMODE_CCM_TEST(ccaes_generic_arm_ccm_decrypt_mode, 16),
    CCMODE_CCM_TEST(ccaes_generic_arm_ccm_encrypt_mode, 24),
    CCMODE_CCM_TEST(ccaes_generic_arm_ccm_decrypt_mode, 24),
    CCMODE_CCM_TEST(ccaes_generic_arm_ccm_encrypt_mode, 32),
    CCMODE_CCM_TEST(ccaes_generic_arm_ccm_decrypt_mode, 32),
#elif CCAES_INTEL_ASM
    CCMODE_CCM_TEST(ccaes_generic_intel_ccm_encrypt_mode, 16),
    CCMODE_CCM_TEST(ccaes_generic_intel_ccm_decrypt_mode, 16),
    CCMODE_CCM_TEST(ccaes_generic_intel_ccm_encrypt_mode, 24),
    CCMODE_CCM_TEST(ccaes_generic_intel_ccm_decrypt_mode, 24),
    CCMODE_CCM_TEST(ccaes_generic_intel_ccm_encrypt_mode, 32),
    CCMODE_CCM_TEST(ccaes_generic_intel_ccm_decrypt_mode, 32),
#endif

    CCMODE_CCM_TEST(ccaes_default_ccm_encrypt_mode, 16),
    CCMODE_CCM_TEST(ccaes_default_ccm_decrypt_mode, 16),
    CCMODE_CCM_TEST(ccaes_default_ccm_encrypt_mode, 24),
    CCMODE_CCM_TEST(ccaes_default_ccm_decrypt_mode, 24),
    CCMODE_CCM_TEST(ccaes_default_ccm_encrypt_mode, 32),
    CCMODE_CCM_TEST(ccaes_default_ccm_decrypt_mode, 32),
};

static double perf_ccccm_init(size_t loops, size_t *psize  CC_UNUSED, const void *arg)
{
    const struct ccccm_perf_test *test=arg;
    const struct ccmode_ccm *ccm=test->ccm;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];

    cc_clear(keylen,keyd);
    ccccm_ctx_decl(ccm->size, key);


    perf_start();
    while(loops--)
        ccccm_init(ccm, key, keylen, keyd);

    return perf_seconds();
}

static double perf_ccccm_set_iv(size_t loops, size_t *psize CC_UNUSED, const void *arg)
{
    const struct ccccm_perf_test *test=arg;
    const struct ccmode_ccm *ccm=test->ccm;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    unsigned char nonced[7];

    cc_clear(keylen,keyd);
    cc_clear(sizeof(nonced),nonced);
    ccccm_ctx_decl(ccm->size, key);
    ccccm_nonce_decl(ccm->nonce_size, nonce);
    ccccm_init(ccm, key, keylen, keyd);

    perf_start();
    while(loops--)
        ccccm_set_iv(ccm,key, nonce, sizeof(nonced), nonced,16,16,16);

    return perf_seconds();
}

static double perf_ccccm_cbcmac(size_t loops, size_t *psize, const void *arg)
{
    const struct ccccm_perf_test *test=arg;
    const struct ccmode_ccm *ccm=test->ccm;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/ccm->block_size;

    unsigned char keyd[keylen];
    unsigned char nonced[13];
    unsigned char *temp = malloc(nblocks*ccm->block_size);

    cc_clear(keylen,keyd);
    cc_clear(sizeof(nonced),nonced);
    ccccm_ctx_decl(ccm->size, key);
    ccccm_nonce_decl(ccm->nonce_size, nonce);

    ccccm_init(ccm, key, keylen, keyd);
    ccccm_set_iv(ccm,key, nonce, sizeof(nonced), nonced,16,*psize,16);

    perf_start();
    while(loops--)
        ccccm_cbcmac(ccm,key, nonce, *psize, temp);
    double elapsed = perf_seconds();

    free(temp);
    return elapsed;
}

static double perf_ccccm_update(size_t loops, size_t *psize, const void *arg)
{
    const struct ccccm_perf_test *test=arg;
    const struct ccmode_ccm *ccm=test->ccm;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/ccm->block_size;

    unsigned char keyd[keylen];
    unsigned char nonced[13];
    unsigned char *temp = malloc(nblocks*ccm->block_size);

    cc_clear(keylen,keyd);
    cc_clear(sizeof(nonced),nonced);
    ccccm_ctx_decl(ccm->size, key);
    ccccm_nonce_decl(ccm->nonce_size, nonce);

    ccccm_init(ccm, key, keylen, keyd);
    ccccm_set_iv(ccm,key, nonce, sizeof(nonced), nonced,16,*psize,0);
    ccccm_cbcmac(ccm,key, nonce, *psize, temp);

    perf_start();
    while(loops--)
        ccccm_update(ccm,key, nonce, *psize, temp, temp);

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static double perf_ccccm_finalize(size_t loops, size_t *psize CC_UNUSED, const void *arg)
{
    const struct ccccm_perf_test *test=arg;
    const struct ccmode_ccm *ccm=test->ccm;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    unsigned char nonced[13];
    unsigned char tag[16]={0};
    unsigned char data[16]={0};

    cc_clear(keylen,keyd);
    cc_clear(sizeof(nonced),nonced);
    ccccm_ctx_decl(ccm->size, key);
    ccccm_nonce_decl(ccm->nonce_size, nonce);

    ccccm_init(ccm, key, keylen, keyd);
    ccccm_set_iv(ccm,key, nonce, sizeof(nonced), nonced,sizeof(tag),*psize,0);
    ccccm_cbcmac(ccm,key, nonce, 0, NULL);
    ccccm_update(ccm,key, nonce, sizeof(data), data, data);

    perf_start();
    while(loops--)
        ccccm_finalize(ccm, key, nonce, tag);

    return perf_seconds();
}

static double perf_ccccm_one_shot(size_t loops, size_t *psize, const void *arg)
{
    const struct ccccm_perf_test *test=arg;
    const struct ccmode_ccm *ccm=test->ccm;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/ccm->block_size;

    unsigned char *temp = malloc(nblocks*ccm->block_size);
    unsigned char keyd[keylen];
    unsigned char tag[16]={0};
    unsigned char nonced[13];
    cc_clear(keylen,keyd);
    cc_clear(sizeof(nonced),nonced);

    perf_start();
    while(loops--) {
        ccccm_one_shot(ccm,
                       keylen,keyd, // Key
                       sizeof(nonced),nonced,      // Nonce
                       *psize, temp, temp, // Data in/out
                       0, NULL,         // Authenticated data
                       sizeof(tag), tag); // Tag
    }

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}


static void ccperf_family_ccccm_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    ccmode_factory_ccm_encrypt(&ccaes_generic_ltc_ccm_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_ccm_decrypt(&ccaes_generic_ltc_ccm_decrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
#if CCAES_ARM_ASM
    ccmode_factory_ccm_encrypt(&ccaes_generic_arm_ccm_encrypt_mode, &ccaes_arm_ecb_encrypt_mode);
    ccmode_factory_ccm_decrypt(&ccaes_generic_arm_ccm_decrypt_mode, &ccaes_arm_ecb_encrypt_mode);
#elif CCAES_INTEL_ASM
    ccmode_factory_ccm_encrypt(&ccaes_generic_intel_ccm_encrypt_mode, &ccaes_intel_ecb_encrypt_opt_mode);
    ccmode_factory_ccm_decrypt(&ccaes_generic_intel_ccm_decrypt_mode, &ccaes_intel_ecb_encrypt_opt_mode);
#endif

    ccaes_default_ccm_encrypt_mode=*ccaes_ccm_encrypt_mode();
    ccaes_default_ccm_decrypt_mode=*ccaes_ccm_decrypt_mode();
}

F_DEFINE(ccccm, init,     ccperf_size_iterations, 1)
F_DEFINE(ccccm, set_iv,   ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccccm, cbcmac,   ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(ccccm, update,   ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE(ccccm, finalize, ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccccm, one_shot, ccperf_size_bytes, symmetric_crypto_data_nbytes)

