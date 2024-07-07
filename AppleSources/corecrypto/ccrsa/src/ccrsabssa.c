/* Copyright (c) (2020-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "ccrsabssa.h"
#include "cc_macros.h"
#include "ccrsa_internal.h"
#include <corecrypto/ccsha2.h>
#include "ccrsabssa_internal.h"

#pragma mark Ciphersuites Specific Support
#define CCRSABSSA_MAX_DIGEST_OUTPUT_SIZE CCSHA384_OUTPUT_SIZE
#define CCRSABSSA_MAX_SALT_SIZE 48

const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa2048_sha384 = {
        .rsa_modulus_nbits = 2048,
        .di = ccsha384_di,
        .salt_size_nbytes = 48,
};

const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa3072_sha384 = {
        .rsa_modulus_nbits = 3072,
        .di = ccsha384_di,
        .salt_size_nbytes = 48,
};

const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa4096_sha384 = {
        .rsa_modulus_nbits = 4096,
        .di = ccsha384_di,
        .salt_size_nbytes = 48,
};

static bool validate_rsa_key_size_for_ciphersuite(const struct ccrsabssa_ciphersuite *ciphersuite, ccrsa_pub_ctx_t pubKey) {
    size_t modulus_n_bits = ccrsa_pubkeylength(pubKey);
    size_t expected_size = ciphersuite->rsa_modulus_nbits;
    return modulus_n_bits == expected_size;
}

#pragma mark Signature Verification Wrapper with ciphersuite security parameters

CC_NONNULL_ALL
static int ccrsabssa_verify_signature_ws(cc_ws_t ws,
                                         const struct ccrsabssa_ciphersuite *ciphersuite,
                                         const ccrsa_pub_ctx_t key,
                                         const uint8_t *msg,
                                         const size_t msg_nbytes,
                                         const uint8_t *signature,
                                         const size_t signature_nbytes)
{
    cc_require_or_return(validate_rsa_key_size_for_ciphersuite(ciphersuite, key), CCERR_PARAMETER);

    size_t modulus_n_bits = ccrsa_pubkeylength(key);
    size_t modulus_n_bytes = cc_ceiling(modulus_n_bits, 8);
    cc_require_or_return(modulus_n_bytes == signature_nbytes, CCERR_PARAMETER);

    const struct ccdigest_info* di = ciphersuite->di();

    return ccrsa_verify_pss_msg_ws(ws, key, di, di, msg_nbytes, msg, signature_nbytes, signature, ciphersuite->salt_size_nbytes, NULL);
}

CC_NONNULL_ALL
static int ccrsabssa_blind_message_ws(cc_ws_t ws,
                                      const struct ccrsabssa_ciphersuite *ciphersuite,
                                      const ccrsa_pub_ctx_t key,
                                      const uint8_t *msg,
                                      const size_t msg_nbytes,
                                      uint8_t *blinding_inverse,
                                      size_t blinding_inverse_nbytes,
                                      uint8_t *blinded_msg,
                                      size_t blinded_msg_nbytes,
                                      struct ccrng_state *rng)
{
    int rc = CCERR_PARAMETER;

    // Setting up variables for ciphersuite.
    cc_require_or_return(validate_rsa_key_size_for_ciphersuite(ciphersuite, key), CCERR_PARAMETER);
    const struct ccdigest_info* di = ciphersuite->di();

    size_t modulus_n_bits = ccrsa_pubkeylength(key);
    size_t modulus_n_bytes = cc_ceiling(modulus_n_bits, 8);
    cc_require_or_return(blinding_inverse_nbytes == modulus_n_bytes, CCERR_PARAMETER);
    cc_require_or_return(blinded_msg_nbytes == modulus_n_bytes, CCERR_PARAMETER);

    const cc_size emBits = modulus_n_bits-1; //as defined in §8.1.1 of PKCS1-V2
    const cc_size emLen = cc_ceiling(emBits, 8); //In theory, emLen can be one byte less than modBytes

    uint8_t msg_hash[CCRSABSSA_MAX_DIGEST_OUTPUT_SIZE];
    ccdigest(di, msg_nbytes, msg, msg_hash);
    uint8_t salt[CCRSABSSA_MAX_SALT_SIZE];
    rc = ccrng_generate(rng, ciphersuite->salt_size_nbytes, salt);
    cc_require_or_return(rc == CCERR_OK, rc);

    const cc_size n = ccrsa_ctx_n(key);
    CC_DECL_BP_WS(ws, bp);

    cc_unit *EM = CC_ALLOC_WS(ws, n);
    EM[0]=EM[n-1] = 0; //in case emLen<modWord* sizeof(cc_unit), zeroize

    const size_t ofs = ccn_sizeof_n(n) - emLen;
    cc_assert(ofs<=sizeof(cc_unit)); //EM can only be one cc_unit larger

    rc = ccrsa_emsa_pss_encode(di, di, ciphersuite->salt_size_nbytes, salt, di->output_size, msg_hash, emBits, (uint8_t *)EM+ofs);
    cc_require(rc == CCERR_OK, errOut);

    rc = ccrsa_emsa_pss_decode_ws(ws, di, di, ciphersuite->salt_size_nbytes, di->output_size, msg_hash, emBits, (uint8_t *)EM + ofs);
    cc_require_action(rc == CCERR_OK, errOut, rc = CCERR_INTERNAL);

    ccn_swap(n, EM);

    cc_unit *r = CC_ALLOC_WS(ws, n);
    rc = cczp_generate_non_zero_element_ws(ws, ccrsa_ctx_zm(key), rng, r);
    cc_require(rc == CCERR_OK, errOut);

    cc_unit *r_inv = CC_ALLOC_WS(ws, n);
    rc = cczp_inv_ws(ws, ccrsa_ctx_zm(key), r_inv, r);
    cc_require(rc == CCERR_OK, errOut);

    cc_unit *X = CC_ALLOC_WS(ws, n);
    rc = ccrsa_pub_crypt_ws(ws, key, X, r);
    cc_require(rc == CCERR_OK, errOut);

    cc_unit *z = CC_ALLOC_WS(ws, n);
    cczp_mul_ws(ws, ccrsa_ctx_zm(key), z, EM, X);

    rc = ccn_write_uint_padded_ct(n, z, modulus_n_bytes, blinded_msg);
    cc_require(rc >= 0, errOut);

    rc = ccn_write_uint_padded_ct(n, r_inv, modulus_n_bytes, blinding_inverse);
    cc_require(rc >= 0, errOut);

    rc = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rc;
}

int ccrsabssa_blind_message(const struct ccrsabssa_ciphersuite *ciphersuite,
                            const ccrsa_pub_ctx_t key,
                            const uint8_t *msg,
                            const size_t msg_nbytes,
                            uint8_t *blinding_inverse,
                            size_t blinding_inverse_nbytes,
                            uint8_t *blinded_msg,
                            size_t blinded_msg_nbytes,
                            struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSABSSA_BLIND_MESSAGE_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsabssa_blind_message_ws(ws,
                                        ciphersuite,
                                        key,
                                        msg,
                                        msg_nbytes,
                                        blinding_inverse,
                                        blinding_inverse_nbytes,
                                        blinded_msg,
                                        blinded_msg_nbytes,
                                        rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

CC_NONNULL_ALL
static int ccrsabssa_unblind_signature_ws(cc_ws_t ws,
                                          const struct ccrsabssa_ciphersuite *ciphersuite,
                                          const ccrsa_pub_ctx_t key,
                                          const uint8_t *blind_signature,
                                          const size_t blind_signature_nbytes,
                                          const uint8_t *blinding_inverse,
                                          const size_t blinding_inverse_nbytes,
                                          const uint8_t *msg,
                                          const size_t msg_nbytes,
                                          uint8_t *unblinded_signature,
                                          const size_t unblinded_signature_nbytes)
{
    cc_require_or_return(validate_rsa_key_size_for_ciphersuite(ciphersuite, key), CCERR_PARAMETER);

    size_t modulus_n_bits = ccrsa_pubkeylength(key);
    size_t modulus_n_bytes = cc_ceiling(modulus_n_bits, 8);
    cc_require_or_return(blind_signature_nbytes     == modulus_n_bytes, CCERR_PARAMETER);
    cc_require_or_return(blinding_inverse_nbytes    == modulus_n_bytes, CCERR_PARAMETER);
    cc_require_or_return(unblinded_signature_nbytes == modulus_n_bytes, CCERR_PARAMETER);

    int rc = CCERR_OK;

    const cc_size n = ccrsa_ctx_n(key);
    CC_DECL_BP_WS(ws, bp);

    cc_unit *z = CC_ALLOC_WS(ws, n);
    rc = ccn_read_uint(n, z, blind_signature_nbytes, blind_signature);
    cc_require(rc == CCERR_OK, errOut);

    cc_unit *blind_inverse = CC_ALLOC_WS(ws, n);
    rc = ccn_read_uint(n, blind_inverse, modulus_n_bytes, blinding_inverse);
    cc_require(rc == CCERR_OK, errOut);

    cc_unit *s = CC_ALLOC_WS(ws, n);
    cczp_mul_ws(ws, ccrsa_ctx_zm(key), s, z, blind_inverse);

    rc = ccn_write_uint_padded_ct(n, s, modulus_n_bytes, unblinded_signature);
    cc_require(rc >= 0, errOut);

    rc = ccrsabssa_verify_signature_ws(ws, ciphersuite, key, msg, msg_nbytes, unblinded_signature, unblinded_signature_nbytes);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rc;
}

int ccrsabssa_unblind_signature(const struct ccrsabssa_ciphersuite *ciphersuite,
                                const ccrsa_pub_ctx_t key,
                                const uint8_t *blind_signature,
                                const size_t blind_signature_nbytes,
                                const uint8_t *blinding_inverse,
                                const size_t blinding_inverse_nbytes,
                                const uint8_t *msg,
                                const size_t msg_nbytes,
                                uint8_t *unblinded_signature,
                                const size_t unblinded_signature_nbytes)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSABSSA_UNBLIND_SIGNATURE_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsabssa_unblind_signature_ws(ws,
                                            ciphersuite,
                                            key,
                                            blind_signature,
                                            blind_signature_nbytes,
                                            blinding_inverse,
                                            blinding_inverse_nbytes,
                                            msg,
                                            msg_nbytes,
                                            unblinded_signature,
                                            unblinded_signature_nbytes);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

#pragma mark Signer Functions

CC_NONNULL_ALL
static int ccrsabssa_sign_blinded_message_ws(cc_ws_t ws,
                                             const struct ccrsabssa_ciphersuite *ciphersuite,
                                             const ccrsa_full_ctx_t key,
                                             const uint8_t *blinded_message,
                                             const size_t blinded_message_nbytes,
                                             uint8_t *signature,
                                             const size_t signature_nbytes,
                                             struct ccrng_state *blinding_rng)
{
    cc_require_or_return(validate_rsa_key_size_for_ciphersuite(ciphersuite, ccrsa_ctx_public(key)), CCERR_PARAMETER);

    size_t modulus_n_bits = ccrsa_pubkeylength(ccrsa_ctx_public(key));
    size_t modulus_n_bytes = cc_ceiling(modulus_n_bits, 8);
    cc_require_or_return(signature_nbytes       == modulus_n_bytes, CCERR_PARAMETER);
    cc_require_or_return(blinded_message_nbytes == modulus_n_bytes, CCERR_PARAMETER);

    const cc_size n = ccrsa_ctx_n(key);
    CC_DECL_BP_WS(ws, bp);

    cc_unit *signatureCCN = CC_ALLOC_WS(ws, n);
    cc_unit *blindedMessage = CC_ALLOC_WS(ws, n);

    int rc = ccn_read_uint(n, blindedMessage, blinded_message_nbytes, blinded_message);
    cc_require(rc == CCERR_OK, errOut);

    // Require that encoded blindedMessage < n
    cc_require_action(ccn_cmp(n, key->pb_ccn, blindedMessage) == 1, errOut, rc = CCERR_PARAMETER);
    
    rc = ccrsa_priv_crypt_blinded_ws(ws, blinding_rng, key, signatureCCN, blindedMessage);
    cc_require(rc == CCERR_OK, errOut);

    rc = ccn_write_uint_padded_ct(n, signatureCCN, signature_nbytes, signature);
    cc_require(rc >= 0, errOut);

    rc = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rc;
}

int ccrsabssa_sign_blinded_message(const struct ccrsabssa_ciphersuite *ciphersuite,
                                   const ccrsa_full_ctx_t key,
                                   const uint8_t *blinded_message,
                                   const size_t blinded_message_nbytes,
                                   uint8_t *signature,
                                   const size_t signature_nbytes,
                                   struct ccrng_state *blinding_rng)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSABSSA_SIGN_BLINDED_MESSAGE_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsabssa_sign_blinded_message_ws(ws,
                                               ciphersuite,
                                               key,
                                               blinded_message,
                                               blinded_message_nbytes,
                                               signature,
                                               signature_nbytes,
                                               blinding_rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
