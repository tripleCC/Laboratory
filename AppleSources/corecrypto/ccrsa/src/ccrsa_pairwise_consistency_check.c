/* Copyright (c) (2011-2013,2015-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>
#include "ccrsa_internal.h"
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include "cc_macros.h"

static const uint8_t FAKE_DIGEST[CCSHA256_OUTPUT_SIZE] = {
    0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
    0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
    0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
    0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa
};

int ccrsa_pairwise_consistency_check_ws(cc_ws_t ws,
                                        const ccrsa_full_ctx_t full_key,
                                        struct ccrng_state *rng)
{
    ccrsa_full_ctx_t fk = full_key;
    ccrsa_pub_ctx_t pub_key = ccrsa_ctx_public(fk);
    size_t n = ccrsa_ctx_n(full_key);
    size_t nbits = cczp_bitlen(ccrsa_ctx_zm(pub_key));
    int rv = CCERR_PARAMETER;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r = CC_ALLOC_WS(ws, n);
    cc_unit *s = CC_ALLOC_WS(ws, n);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    // Verify the key is valid for signature / verification
    uint8_t *sig = (uint8_t *)CC_ALLOC_WS(ws, n);
    size_t siglen = CC_BITLEN_TO_BYTELEN(nbits);

    rv = ccrsa_sign_pkcs1v15_blinded_ws(ws, rng, full_key, ccoid_sha256, sizeof(FAKE_DIGEST), FAKE_DIGEST, &siglen, sig);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccrsa_verify_pkcs1v15_digest_ws(ws, pub_key, ccoid_sha256, sizeof(FAKE_DIGEST), FAKE_DIGEST, siglen, sig, NULL);
    cc_require(rv == CCERR_VALID_SIGNATURE, errOut);

    // Verify the key is valid for encryption / decryption
    ccn_seti(n, s, 42);
    ccn_set_bit(s, nbits - 9, 1);

    // Encrypt
    rv = ccrsa_pub_crypt_ws(ws, pub_key, r, s);
    cc_require(rv == CCERR_OK, errOut);

    // Make sure that the input does not match the output
    cc_require_action(ccn_cmp(n, s, r) != 0, errOut, rv = CCERR_PARAMETER);

    // Decrypt
    rv = ccrsa_priv_crypt_blinded_ws(ws, rng, fk, t, r);
    cc_require(rv == CCERR_OK, errOut);

    // Make sure that output makes plain text
    cc_require_action(ccn_cmp(n, t, s) == 0, errOut, rv = CCERR_PARAMETER);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}
