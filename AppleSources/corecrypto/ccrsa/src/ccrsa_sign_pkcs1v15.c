/* Copyright (c) (2011,2015,2016,2018-2023) Apple Inc. All rights reserved.
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
#include "ccrsa_internal.h"

/* return non zero on error */
/* siglen will be the actual length of the prime in bytes */
int ccrsa_sign_pkcs1v15_blinded_ws(cc_ws_t ws,
                                   struct ccrng_state *blinding_rng,
                                   ccrsa_full_ctx_t key,
                                   const uint8_t *oid,
                                   size_t digest_len,
                                   const uint8_t *digest,
                                   size_t *sig_len,
                                   uint8_t *sig)
{
    size_t m_size = ccn_write_uint_size(ccrsa_ctx_n(key), ccrsa_ctx_m(key));
    cc_size n = ccrsa_ctx_n(key);
    int err;

    if (*sig_len < m_size) {
        return CCRSA_INVALID_INPUT;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    *sig_len = m_size;

    err = ccrsa_emsa_pkcs1v15_encode(m_size, sig, digest_len, digest, oid);
    if (err) {
        goto errOut;
    }

    ccn_read_uint(n, s, m_size, sig);

    err = ccrsa_priv_crypt_blinded_ws(ws, blinding_rng, key, s, s);
    if (err) {
        goto errOut;
    }

    /* we need to write leading zeroes if necessary */
    ccn_write_uint_padded_ct(n, s, m_size, sig);

    err = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return err;
}

int ccrsa_sign_pkcs1v15_blinded(struct ccrng_state *blinding_rng,
                                ccrsa_full_ctx_t key,
                                const uint8_t *oid,
                                size_t digest_len,
                                const uint8_t *digest,
                                size_t *sig_len,
                                uint8_t *sig)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_SIGN_PKCS1V15_BLINDED_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_sign_pkcs1v15_blinded_ws(ws, blinding_rng, key, oid, digest_len, digest, sig_len, sig);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccrsa_sign_pkcs1v15(ccrsa_full_ctx_t key,
                        const uint8_t *oid,
                        size_t digest_len,
                        const uint8_t *digest,
                        size_t *sig_len,
                        uint8_t *sig)
{
    CC_ENSURE_DIT_ENABLED

    struct ccrng_state *rng = ccrng(NULL);
    if (rng == NULL) {
        return CCERR_INTERNAL;
    }

    return ccrsa_sign_pkcs1v15_blinded(rng, key, oid, digest_len, digest, sig_len, sig);
}

int ccrsa_sign_pkcs1v15_msg_blinded(struct ccrng_state *blinding_rng,
                                    ccrsa_full_ctx_t key,
                                    const struct ccdigest_info *di,
                                    size_t msg_len,
                                    const uint8_t *msg,
                                    size_t *sig_len,
                                    uint8_t *sig)
{
    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];
    ccdigest(di, msg_len, msg, digest);

    return ccrsa_sign_pkcs1v15_blinded(blinding_rng, key, di->oid, di->output_size, digest, sig_len, sig);
}

int ccrsa_sign_pkcs1v15_msg(ccrsa_full_ctx_t key,
                            const struct ccdigest_info *di,
                            size_t msg_len,
                            const uint8_t *msg,
                            size_t *sig_len,
                            uint8_t *sig)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];
    ccdigest(di, msg_len, msg, digest);

    return ccrsa_sign_pkcs1v15(key, di->oid, di->output_size, digest, sig_len, sig);
}
