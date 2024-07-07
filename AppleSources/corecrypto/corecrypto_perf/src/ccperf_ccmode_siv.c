/* Copyright (c) (2017-2019,2021-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccmode_siv_priv.h>
#include "ccmode_siv_internal.h"

/* mode created with the siv factory */


static struct ccmode_siv ccaes_default_siv_encrypt_mode;
static struct ccmode_siv ccaes_default_siv_decrypt_mode;

static struct ccmode_cbc ccaes_generic_ltc_cbc_encrypt_mode;
static struct ccmode_ctr ccaes_generic_ltc_ctr_crypt_mode;
static struct ccmode_siv ccaes_generic_ltc_siv_encrypt_mode;
static struct ccmode_siv ccaes_generic_ltc_siv_decrypt_mode;

#define CCMODE_siv_TEST(_mode, _keylen) { .name=#_mode"_"#_keylen, .siv=&_mode, .keylen=_keylen }

static struct ccsiv_perf_test {
    const char *name;
    const struct ccmode_siv *siv;
    size_t keylen;
} ccsiv_perf_tests[] = {
    CCMODE_siv_TEST(ccaes_generic_ltc_siv_encrypt_mode, 32),
    CCMODE_siv_TEST(ccaes_generic_ltc_siv_decrypt_mode, 32),
    CCMODE_siv_TEST(ccaes_generic_ltc_siv_encrypt_mode, 48),
    CCMODE_siv_TEST(ccaes_generic_ltc_siv_decrypt_mode, 48),
    CCMODE_siv_TEST(ccaes_generic_ltc_siv_encrypt_mode, 64),
    CCMODE_siv_TEST(ccaes_generic_ltc_siv_decrypt_mode, 64),

    CCMODE_siv_TEST(ccaes_default_siv_encrypt_mode, 32),
    CCMODE_siv_TEST(ccaes_default_siv_decrypt_mode, 32),
    CCMODE_siv_TEST(ccaes_default_siv_encrypt_mode, 48),
    CCMODE_siv_TEST(ccaes_default_siv_decrypt_mode, 48),
    CCMODE_siv_TEST(ccaes_default_siv_encrypt_mode, 64),
    CCMODE_siv_TEST(ccaes_default_siv_decrypt_mode, 64),
};

static double perf_ccsiv_init(size_t loops, size_t *psize  CC_UNUSED, const void *arg)
{
    CC_UNUSED int status;
    const struct ccsiv_perf_test *test=arg;
    const struct ccmode_siv *siv=test->siv;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];

    cc_clear(keylen,keyd);
    ccsiv_ctx_decl(siv->size, key);

    perf_start();
    while(loops--) {
        status=ccsiv_init(siv, key, keylen, keyd);
        assert(status==0);
    }

    return perf_seconds();
}

// Nonce is processed the same way as AAD
static double perf_ccsiv_aad_or_nonce(size_t loops, size_t *psize, const void *arg)
{
    CC_UNUSED int status;
    const struct ccsiv_perf_test *test=arg;
    const struct ccmode_siv *siv=test->siv;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    unsigned char *temp = malloc(*psize);

    cc_clear(keylen,keyd);
    cc_clear(*psize,temp);
    ccsiv_ctx_decl(siv->size, key);
    ccsiv_init(siv, key, keylen, keyd);

    perf_start();
    while(loops--) {
        status=ccsiv_aad(siv,key, *psize, temp);
        assert(status==0);
    }

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static double perf_ccsiv_one_shot(size_t loops, size_t *psize, const void *arg)
{
    CC_UNUSED int status;
    const struct ccsiv_perf_test *test=arg;
    const struct ccmode_siv *siv=test->siv;
    size_t keylen=test->keylen;
    size_t ciphertext_len=ccsiv_ciphertext_size(siv, *psize);
    unsigned char keyd[keylen];
    unsigned char *temp = malloc(ciphertext_len);

    cc_clear(keylen,keyd);
    cc_clear(*psize,temp);

    perf_start();
    while(loops--) {
        // This fails in the decryption path, since the ciphertext is not valid
        // it does not matter in term of performance
        ccsiv_one_shot(siv,keylen,keyd,0,NULL,0, NULL,ciphertext_len, temp, temp);
    }

    double seconds = perf_seconds();
    free(temp);
    return seconds;
}


static void ccperf_family_ccsiv_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    ccmode_factory_ctr_crypt(&ccaes_generic_ltc_ctr_crypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_cbc_encrypt(&ccaes_generic_ltc_cbc_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_siv_encrypt(&ccaes_generic_ltc_siv_encrypt_mode, &ccaes_generic_ltc_cbc_encrypt_mode, &ccaes_generic_ltc_ctr_crypt_mode);
    ccmode_factory_siv_decrypt(&ccaes_generic_ltc_siv_decrypt_mode, &ccaes_generic_ltc_cbc_encrypt_mode, &ccaes_generic_ltc_ctr_crypt_mode);
    ccaes_default_siv_encrypt_mode=*ccaes_siv_encrypt_mode();
    ccaes_default_siv_decrypt_mode=*ccaes_siv_decrypt_mode();
}

F_DEFINE(ccsiv, init,         ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccsiv, aad_or_nonce, ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(ccsiv, one_shot,     ccperf_size_bytes, symmetric_crypto_data_nbytes)
