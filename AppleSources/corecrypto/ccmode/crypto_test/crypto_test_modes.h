/* Copyright (c) (2010-2012,2014-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CRYPTO_TEST_MODES_H_
#define _CORECRYPTO_CRYPTO_TEST_MODES_H_

#include "ccsymmetric.h"

typedef struct ccsymmetric_test_t {
    char *keyStr;
    char *twkStr;
    char *init_ivStr; // or nonce
    char *block_ivStr;
    char *aDataStr;
    char *aData2Str;
    char *ptStr;
    char *ctStr;
    char *tagStr;
} ccsymmetric_test_vector;

typedef struct duplex_cryptor_t {
    ciphermode_t encrypt_ciphermode;
    ciphermode_t decrypt_ciphermode;
    cc_cipher_select cipher;
    cc_mode_select mode;
    cc_digest_select digest;
} duplex_cryptor_s, *duplex_cryptor;

int test_mode(ciphermode_t encrypt_ciphermode, ciphermode_t decrypt_ciphermode, cc_cipher_select cipher, cc_mode_select mode);
int test_hmac_mode(ciphermode_t encrypt_ciphermode, ciphermode_t decrypt_ciphermode, cc_cipher_select cipher, cc_mode_select mode, cc_digest_select digest);
int test_gcm(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode);
int test_ccm(const struct ccmode_ccm *encrypt_ciphermode, const struct ccmode_ccm *decrypt_ciphermode);
int test_xts(const struct ccmode_xts *encrypt_ciphermode, const struct ccmode_xts *decrypt_ciphermode);
int test_siv_hmac_corner_cases(duplex_cryptor cryptor);
int ccmode_siv_hmac_state_tests(cc_ciphermode_descriptor cm, cc_symmetric_context_p ctx);
int ccmode_aes_siv_encrypt_decrypt_in_place_tests(cc_ciphermode_descriptor cm, cc_symmetric_context_p ctx, cc_ciphermode_descriptor dcm, cc_symmetric_context_p dctx);
int test_aes_siv_corner_cases(duplex_cryptor cryptor);

/* This function is intended to work for any block cipher
 It can be called from ccaes for AES-CTR, or ccdes for DES-CTR for example */
int test_ctr(const char *name, const struct ccmode_ctr *encrypt_ciphermode, const struct ccmode_ctr *decrypt_ciphermode,
             const ccsymmetric_test_vector *sym_vectors);

#endif /* _CORECRYPTO_CRYPTO_TEST_MODES_H_ */
