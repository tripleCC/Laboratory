/* Copyright (c) (2014-2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccaes.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccwrap.h>
#include "ccec_internal.h"
#include "cc_macros.h"

#define MAX_WRAPPED_KEY_NBYTES(_n_) (           \
    2 + 1 + 48 +                                \
    /* ccec_rfc6637_wrap_pub_size() */          \
    1 + 2 * ccn_sizeof_n(_n_) +                 \
    /* CCEC_RFC6637_DEBUG_KEYS */               \
    2 + 36 /* max keylen */ + ccn_sizeof_n(_n_) \
)

struct ccec_rfc6637_unwrap {
    const struct ccec_rfc6637 *pgp;
    const struct ccmode_ecb * (*CC_SPTR(ccec_rfc6637_unwrap, dec))(void);
};

const struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha256_kek_aes128 = {
    .pgp = &ccec_rfc6637_sha256_kek_aes128,
    .dec = ccaes_ecb_decrypt_mode,
};

const struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha512_kek_aes256 = {
    .pgp = &ccec_rfc6637_sha512_kek_aes256,
    .dec = ccaes_ecb_decrypt_mode,
};

static int ccec_rfc6637_unwrap_key_ws(cc_ws_t ws,
                                      ccec_full_ctx_t private_key,
                                      size_t *key_len,
                                      void *key,
                                      unsigned long flags,
                                      uint8_t *symm_key_alg,
                                      const struct ccec_rfc6637_curve *curve,
                                      const struct ccec_rfc6637_unwrap *unwrap,
                                      const uint8_t *fingerprint,
                                      size_t wrapped_key_len,
                                      const void *wrapped_key)
{
    const struct ccdigest_info *di = unwrap->pgp->difun();
    const uint8_t *wkey = wrapped_key;
    int res;

    if (di->output_size < unwrap->pgp->keysize) {
        return CCERR_PARAMETER;
    }

    if (wrapped_key_len < 5) {
        return CCERR_PARAMETER;
    }

    size_t wkey_size = CC_BITLEN_TO_BYTELEN(((size_t)wkey[0] << 8) | wkey[1]);
    if (wkey_size > wrapped_key_len - 2 - 1) {
        return CCERR_PARAMETER;
    }

    size_t wrapped_size = wkey[2 + wkey_size];
    if ((flags & CCEC_RFC6637_DEBUG_KEYS)) {
        if (wrapped_key_len < 2 + wkey_size + 1 + wrapped_size) {
            return CCERR_PARAMETER;
        }
    } else if (wrapped_key_len != 2 + wkey_size + 1 + wrapped_size) {
        return CCERR_PARAMETER;
    }

    /*
     * Import the ephemeral public key and generate the shared key.
     */

    ccec_const_cp_t cp = ccec_ctx_cp(private_key);
    cc_size n = ccec_cp_n(cp);

    const struct ccmode_ecb *ecbmode = unwrap->dec();
    ccecb_ctx_decl(ccecb_context_size(ecbmode), ecb);

    CC_DECL_BP_WS(ws, bp);
    uint8_t *skey = (uint8_t *)CC_ALLOC_WS(ws, n);
    uint8_t hash[MAX_DIGEST_OUTPUT_SIZE];

    ccec_pub_ctx_t ephemeral_key = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_ctx_init(cp, ephemeral_key);

    /*
     * There is no ccec_NNN_IMPORT_pub_size()
     */
    if (ccec_export_pub_size(ephemeral_key) == wkey_size) {
        res = ccec_import_pub_ws(ws, cp, wkey_size, &wkey[2], ephemeral_key);
    } else if ((flags & CCEC_RFC6637_COMPACT_KEYS) && ccec_compact_export_size(0, ephemeral_key) >= wkey_size) {
        res = ccec_compact_import_pub_ws(ws, cp, wkey_size, &wkey[2], ephemeral_key);
    } else {
        res = CCERR_PARAMETER;
    }
    cc_require(res == CCERR_OK, errOut);

    size_t skey_size = ccec_cp_prime_size(cp);

    res = ccecdh_compute_shared_secret_ws(ws, private_key, ephemeral_key, &skey_size, skey, NULL);
    cc_require(res == CCERR_OK, errOut);

    /*
     * KDF
     */
    ccec_rfc6637_kdf(di, curve, unwrap->pgp, skey_size, skey, 20, fingerprint, hash);

    /*
     * unwrap
     */
    
    ccecb_init(ecbmode, ecb, unwrap->pgp->keysize, hash);
    cc_clear(di->output_size, hash);

    uint8_t *m = (uint8_t *)CC_ALLOC_WS(ws, MAX_WRAPPED_KEY_NBYTES(n));
    size_t m_size = wrapped_size;
    
    res = ccwrap_auth_decrypt(ecbmode, ecb, wrapped_size, &wkey[2 + wkey_size + 1], &m_size, m);
    ccecb_ctx_clear(ccecb_context_size(ecbmode), ecb);
    cc_require(res == CCERR_OK, errOut);

    /*
     * validate key
     */

    cc_require_action(1 <= m_size && m_size <= wrapped_size - 1, errOut, res = CCERR_INTEGRITY);

    *symm_key_alg = m[0];

    uint8_t padding = m[m_size - 1];

    /*
     * Don't need to make this constant time since ccwrap_auth_decrypt() have a checksum.
     */
    cc_require_action(padding <= m_size - 1 - 2, errOut, res = CCERR_INTEGRITY);

    for (size_t i = 0; i < padding; i += 1) {
        cc_require_action(m[m_size - 1 - i] == padding, errOut, res = CCERR_INTEGRITY);
    }

    cc_require_action(*key_len >= m_size - 1 - 2 - padding, errOut, res = CCERR_BUFFER_TOO_SMALL);
    *key_len = m_size - 1 - 2 - padding;

    /*
     * validate key checksum
     */

    uint16_t cksum = pgp_key_checksum(*key_len, m + 1);
    cc_require_action(((cksum >> 8) & 0xff) == m[1 + *key_len] && (cksum & 0xff) == m[1 + *key_len + 1], errOut, res = CCERR_INTEGRITY);

    cc_memcpy(key, m + 1, *key_len);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return res;
}

int ccec_rfc6637_unwrap_key(ccec_full_ctx_t private_key,
                            size_t *key_len,
                            void *key,
                            unsigned long flags,
                            uint8_t *symm_key_alg,
                            const struct ccec_rfc6637_curve *curve,
                            const struct ccec_rfc6637_unwrap *unwrap,
                            const uint8_t *fingerprint,
                            size_t wrapped_key_len,
                            const void  *wrapped_key)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(private_key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_RFC6637_UNWRAP_KEY_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_rfc6637_unwrap_key_ws(ws, private_key, key_len, key, flags,
                                        symm_key_alg, curve, unwrap,
                                        fingerprint, wrapped_key_len,
                                        wrapped_key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
