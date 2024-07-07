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

/* mode created with the GCM factory */

static struct ccmode_gcm ccaes_default_gcm_encrypt_mode;
static struct ccmode_gcm ccaes_default_gcm_decrypt_mode;

static struct ccmode_gcm ccaes_generic_ltc_gcm_encrypt_mode;
static struct ccmode_gcm ccaes_generic_ltc_gcm_decrypt_mode;

#if CCAES_ARM_ASM
static struct ccmode_gcm ccaes_generic_arm_gcm_encrypt_mode;
static struct ccmode_gcm ccaes_generic_arm_gcm_decrypt_mode;
#elif CCAES_INTEL_ASM
static struct ccmode_gcm ccaes_generic_intel_gcm_encrypt_mode;
static struct ccmode_gcm ccaes_generic_intel_gcm_decrypt_mode;
#endif

#define CCMODE_GCM_TEST(_mode, _keylen) { .name=#_mode"_"#_keylen, .gcm=&_mode, .keylen=_keylen }

static struct ccgcm_perf_test {
    const char *name;
    const struct ccmode_gcm *gcm;
    size_t keylen;
} ccgcm_perf_tests[] = {
    CCMODE_GCM_TEST(ccaes_generic_ltc_gcm_encrypt_mode, 16),
    CCMODE_GCM_TEST(ccaes_generic_ltc_gcm_decrypt_mode, 16),
    CCMODE_GCM_TEST(ccaes_generic_ltc_gcm_encrypt_mode, 24),
    CCMODE_GCM_TEST(ccaes_generic_ltc_gcm_decrypt_mode, 24),
    CCMODE_GCM_TEST(ccaes_generic_ltc_gcm_encrypt_mode, 32),
    CCMODE_GCM_TEST(ccaes_generic_ltc_gcm_decrypt_mode, 32),

#if CCAES_ARM_ASM
    CCMODE_GCM_TEST(ccaes_generic_arm_gcm_encrypt_mode, 16),
    CCMODE_GCM_TEST(ccaes_generic_arm_gcm_decrypt_mode, 16),
    CCMODE_GCM_TEST(ccaes_generic_arm_gcm_encrypt_mode, 24),
    CCMODE_GCM_TEST(ccaes_generic_arm_gcm_decrypt_mode, 24),
    CCMODE_GCM_TEST(ccaes_generic_arm_gcm_encrypt_mode, 32),
    CCMODE_GCM_TEST(ccaes_generic_arm_gcm_decrypt_mode, 32),
#elif CCAES_INTEL_ASM
    CCMODE_GCM_TEST(ccaes_generic_intel_gcm_encrypt_mode, 16),
    CCMODE_GCM_TEST(ccaes_generic_intel_gcm_decrypt_mode, 16),
    CCMODE_GCM_TEST(ccaes_generic_intel_gcm_encrypt_mode, 24),
    CCMODE_GCM_TEST(ccaes_generic_intel_gcm_decrypt_mode, 24),
    CCMODE_GCM_TEST(ccaes_generic_intel_gcm_encrypt_mode, 32),
    CCMODE_GCM_TEST(ccaes_generic_intel_gcm_decrypt_mode, 32),
#endif

    CCMODE_GCM_TEST(ccaes_default_gcm_encrypt_mode, 16),
    CCMODE_GCM_TEST(ccaes_default_gcm_decrypt_mode, 16),
    CCMODE_GCM_TEST(ccaes_default_gcm_encrypt_mode, 24),
    CCMODE_GCM_TEST(ccaes_default_gcm_decrypt_mode, 24),
    CCMODE_GCM_TEST(ccaes_default_gcm_encrypt_mode, 32),
    CCMODE_GCM_TEST(ccaes_default_gcm_decrypt_mode, 32),
};

static double perf_ccgcm_init(size_t loops, size_t *psize  CC_UNUSED, const void *arg)
{
    const struct ccgcm_perf_test *test=arg;
    const struct ccmode_gcm *gcm=test->gcm;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];

    cc_clear(keylen,keyd);
    ccgcm_ctx_decl(gcm->size, key);


    perf_start();
    while(loops--)
        ccgcm_init(gcm, key, keylen, keyd);

    return perf_seconds();
}

static double perf_ccgcm_aad(size_t loops, size_t *psize, const void *arg)
{
    const struct ccgcm_perf_test *test=arg;
    const struct ccmode_gcm *gcm=test->gcm;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/gcm->block_size;

    unsigned char keyd[keylen];
    unsigned char ivd[gcm->block_size];
    unsigned char *temp = malloc(nblocks*gcm->block_size);

    cc_clear(keylen,keyd);
    cc_clear(sizeof(ivd),ivd);
    ccgcm_ctx_decl(gcm->size, key);

    ccgcm_init(gcm, key, keylen, keyd);
    ccgcm_set_iv(gcm,key, 12, ivd);
    ccgcm_aad(gcm, key, 1, temp);

    perf_start();
    while(loops--)
        ccgcm_aad(gcm,key, *psize, temp);

    double elapsed = perf_seconds();

    ccgcm_update(gcm,key, 0, NULL, NULL);
    ccgcm_finalize(gcm,key, gcm->block_size, ivd);

    free(temp);
    return elapsed;
}

static double perf_ccgcm_set_iv(size_t loops, size_t *psize, const void *arg)
{
    const struct ccgcm_perf_test *test=arg;
    const struct ccmode_gcm *gcm=test->gcm;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    unsigned char ivd[*psize];

    cc_clear(keylen,keyd);
    cc_clear(sizeof(ivd),ivd);
    ccgcm_ctx_decl(gcm->size, key);
    ccgcm_init(gcm, key, keylen, keyd);

    perf_start();
    while(loops--)
        ccgcm_set_iv(gcm,key, *psize, ivd);

    return perf_seconds();
}

static double perf_ccgcm_update(size_t loops, size_t *psize, const void *arg)
{
    const struct ccgcm_perf_test *test=arg;
    const struct ccmode_gcm *gcm=test->gcm;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/gcm->block_size;

    unsigned char keyd[keylen];
    unsigned char ivd[gcm->block_size];
    unsigned char *temp = malloc(nblocks*gcm->block_size);

    cc_clear(keylen,keyd);
    cc_clear(sizeof(ivd),ivd);
    ccgcm_ctx_decl(gcm->size, key);

    ccgcm_init(gcm, key, keylen, keyd);
    ccgcm_set_iv(gcm,key, 12, ivd);
    ccgcm_aad(gcm, key, 0, NULL);
    ccgcm_update(gcm, key, 1, temp, temp);

    perf_start();
    while(loops--)
        ccgcm_update(gcm,key, *psize, temp, temp);

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static double perf_ccgcm_finalize(size_t loops, size_t *psize CC_UNUSED, const void *arg)
{
    const struct ccgcm_perf_test *test=arg;
    const struct ccmode_gcm *gcm=test->gcm;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    unsigned char ivd[gcm->block_size];

    cc_clear(keylen,keyd);
    cc_clear(sizeof(ivd),ivd);
    ccgcm_ctx_decl(gcm->size, key);

    ccgcm_init(gcm, key, keylen, keyd);
    ccgcm_set_iv(gcm,key, 12, ivd);
    ccgcm_aad(gcm,key, 0, NULL);
    ccgcm_update(gcm,key, 0, NULL, NULL);

    perf_start();
    while(loops--)
        ccgcm_finalize(gcm, key, gcm->block_size, ivd);

    return perf_seconds();
}

static double perf_ccgcm_one_shot(size_t loops, size_t *psize, const void *arg)
{
    const struct ccgcm_perf_test *test=arg;
    const struct ccmode_gcm *gcm=test->gcm;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/gcm->block_size;

    unsigned char keyd[keylen];
    unsigned char ivd[gcm->block_size];
    unsigned char *temp = malloc(nblocks*gcm->block_size);

    cc_clear(keylen,keyd);
    cc_clear(sizeof(ivd),ivd);

    perf_start();
    while(loops--) {
        ccgcm_one_shot(gcm,keylen,keyd,12,ivd,0, NULL,*psize, temp, temp,gcm->block_size, ivd);
    }

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}


static void ccperf_family_ccgcm_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    ccmode_factory_gcm_encrypt(&ccaes_generic_ltc_gcm_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_gcm_decrypt(&ccaes_generic_ltc_gcm_decrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
#if CCAES_ARM_ASM
    ccmode_factory_gcm_encrypt(&ccaes_generic_arm_gcm_encrypt_mode, &ccaes_arm_ecb_encrypt_mode);
    ccmode_factory_gcm_decrypt(&ccaes_generic_arm_gcm_decrypt_mode, &ccaes_arm_ecb_encrypt_mode);
#elif CCAES_INTEL_ASM
    ccmode_factory_gcm_encrypt(&ccaes_generic_intel_gcm_encrypt_mode, &ccaes_intel_ecb_encrypt_opt_mode);
    ccmode_factory_gcm_decrypt(&ccaes_generic_intel_gcm_decrypt_mode, &ccaes_intel_ecb_encrypt_opt_mode);
#endif

    ccaes_default_gcm_encrypt_mode=*ccaes_gcm_encrypt_mode();
    ccaes_default_gcm_decrypt_mode=*ccaes_gcm_decrypt_mode();
}

const size_t iv_sizes[]={4,16,96};

F_DEFINE(ccgcm, init,     ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccgcm, aad,     ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(ccgcm, set_iv,   ccperf_size_bytes, iv_sizes)
F_DEFINE_SIZE_ARRAY(ccgcm, update,   ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE(ccgcm, finalize, ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccgcm, one_shot, ccperf_size_bytes, symmetric_crypto_data_nbytes)
