/* Copyright (c) (2017,2019-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"
#include "cc_memory.h"

#include <corecrypto/ccsha2.h>
#include "ccrsa_internal.h"
#include "ccrng_zero.h"

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_rsa_enc_dec.h"

#include "fipspost_post_rsa_enc_dec.inc"

#if !(CC_USE_L4 || CC_KERNEL)

CC_WARN_RESULT CC_NONNULL_ALL
static int fipspost_post_rsa_oaep_decrypt_ws(cc_ws_t ws,
                                             uint32_t fips_mode,
                                             ccrsa_full_ctx_t full_key,
                                             size_t ciphertext_nbytes,
                                             const uint8_t *ciphertext,
                                             size_t message_nbytes,
                                             const uint8_t *message)
{
    uint8_t plaintext[FIPS_RSA_OAEP_KEY_SIZE];
    size_t plaintext_nbytes = sizeof(plaintext);

    uint8_t ct[FIPS_RSA_OAEP_KEY_SIZE];
    memcpy(ct, ciphertext, ciphertext_nbytes);

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        ct[0] ^= 0xaa;
    }

    CC_DECL_BP_WS(ws, bp);

    int rv = ccrsa_decrypt_oaep_blinded_ws(ws,
                                           &ccrng_zero,
                                           full_key,
                                           ccsha256_di(),
                                           &plaintext_nbytes, plaintext,
                                           ciphertext_nbytes, ct,
                                           0, NULL);
    if (rv) {
        failf("ccrsa_decrypt_oaep");
        rv = CCPOST_GENERIC_FAILURE;
        goto errOut;
    }

    if (plaintext_nbytes != message_nbytes) {
        failf("len(plaintext) != len(message)");
        rv = CCPOST_KAT_FAILURE;
        goto errOut;
    }

    if (memcmp(plaintext, message, message_nbytes)) {
        failf("plaintext != message");
        rv = CCPOST_KAT_FAILURE;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_WARN_RESULT CC_NONNULL_ALL
static int fipspost_post_rsa_oaep_consistency_ws(cc_ws_t ws, uint32_t fips_mode)
{
    cc_size n = FIPS_RSA_OAEP_KEY_N;

    CC_DECL_BP_WS(ws, bp);
    ccrsa_full_ctx_t full_key = CCRSA_ALLOC_FULL_WS(ws, n);
    ccrsa_ctx_n(full_key) = n;

    int rv = ccrsa_import_priv_ws(ws, full_key, sizeof(FIPS_RSA_OAEP_KEY), FIPS_RSA_OAEP_KEY);
    if (rv) {
        failf("ccrsa_import_priv");
        rv = CCPOST_GENERIC_FAILURE;
        goto errOut;
    }

    uint8_t ciphertext[FIPS_RSA_OAEP_KEY_SIZE];
    size_t ciphertext_nbytes = sizeof(ciphertext);

    ccrsa_pub_ctx_t pub_key = ccrsa_ctx_public(full_key);
    rv = ccrsa_encrypt_oaep_ws(ws, pub_key, ccsha256_di(), &ccrng_zero,
                               &ciphertext_nbytes, ciphertext,
                               sizeof(FIPS_RSA_OAEP_MESSAGE), FIPS_RSA_OAEP_MESSAGE,
                               0, NULL);
    if (rv) {
        failf("ccrsa_encrypt_oaep");
        rv = CCPOST_GENERIC_FAILURE;
        goto errOut;
    }

    rv = fipspost_post_rsa_oaep_decrypt_ws(ws, fips_mode, full_key,
                                           ciphertext_nbytes, ciphertext,
                                           sizeof(FIPS_RSA_OAEP_MESSAGE),
                                           FIPS_RSA_OAEP_MESSAGE);
    if (rv) {
        failf("fipspost_post_rsa_oaep_consistency");
        rv = CCPOST_GENERIC_FAILURE;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_WARN_RESULT CC_NONNULL_ALL
static int fipspost_post_rsa_oaep_kat_ws(cc_ws_t ws, uint32_t fips_mode)
{
    cc_size n = FIPS_RSA_OAEP_KEY_N;

    CC_DECL_BP_WS(ws, bp);
    ccrsa_full_ctx_t full_key = CCRSA_ALLOC_FULL_WS(ws, n);
    ccrsa_ctx_n(full_key) = n;

    int rv = ccrsa_import_priv_ws(ws, full_key, sizeof(FIPS_RSA_OAEP_KEY), FIPS_RSA_OAEP_KEY);
    if (rv) {
        failf("ccrsa_import_priv");
        rv = CCPOST_GENERIC_FAILURE;
        goto errOut;
    }

    rv = fipspost_post_rsa_oaep_decrypt_ws(ws, fips_mode, full_key,
                                           sizeof(FIPS_RSA_OAEP_CIPHERTEXT),
                                           FIPS_RSA_OAEP_CIPHERTEXT,
                                           sizeof(FIPS_RSA_OAEP_MESSAGE),
                                           FIPS_RSA_OAEP_MESSAGE);
    if (rv) {
        failf("fipspost_post_rsa_oaep_kat");
        rv = CCPOST_KAT_FAILURE;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}
#endif // !(CC_USE_L4 || CC_KERNEL)

CC_WARN_RESULT CC_NONNULL_ALL
static int fipspost_post_rsa_enc_dec_ws(cc_ws_t ws, uint32_t fips_mode)
{
    int rv = CCERR_OK;
    CC_DECL_BP_WS(ws, bp);

#if !(CC_USE_L4 || CC_KERNEL)
    rv |= fipspost_post_rsa_oaep_consistency_ws(ws, fips_mode);
    rv |= fipspost_post_rsa_oaep_kat_ws(ws, fips_mode);
#endif

    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int fipspost_post_rsa_enc_dec(uint32_t fips_mode)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, FIPSPOST_POST_RSA_ENC_DEC_WORKSPACE_N(FIPS_RSA_OAEP_KEY_N));
    int rv = fipspost_post_rsa_enc_dec_ws(ws, fips_mode);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
