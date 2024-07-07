/* Copyright (c) (2011,2013,2015-2017,2019,2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccrsa_internal.h"

int ccrsa_decrypt_eme_pkcs1v15_blinded_ws(cc_ws_t ws,
                                          struct ccrng_state *blinding_rng,
                                          ccrsa_full_ctx_t key,
                                          size_t *r_size, uint8_t *r,
                                          size_t s_size, const uint8_t *s)
{
    size_t m_size = ccrsa_block_size(ccrsa_ctx_public(key));
    cc_size n = ccrsa_ctx_n(key);
    int rv = CCERR_OK;

    if (*r_size < m_size) {
        return CCRSA_INVALID_INPUT;
    }

    *r_size = m_size;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp = CC_ALLOC_WS(ws, n);

    if (ccn_read_uint(n, tmp, s_size, s)) {
        rv = CCRSA_INVALID_INPUT;
        goto errOut;
    }

    // RSA decryption
    rv = ccrsa_priv_crypt_blinded_ws(ws, blinding_rng, key, tmp, tmp);
    if (rv) {
        goto errOut;
    }

    // Padding decoding
    rv = ccrsa_eme_pkcs1v15_decode_safe_ws(ws, key, r_size, r, m_size, tmp);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}
