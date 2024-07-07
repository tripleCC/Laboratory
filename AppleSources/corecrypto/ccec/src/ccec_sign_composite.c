/* Copyright (c) (2014-2022) Apple Inc. All rights reserved.
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
#include "ccec_internal.h"
#include "cc_macros.h"

CC_NONNULL_ALL CC_WARN_RESULT
static int ccec_sign_composite_ws(cc_ws_t ws,
                                  ccec_full_ctx_t key,
                                  size_t digest_len,
                                  const uint8_t *digest,
                                  uint8_t *sig_r,
                                  uint8_t *sig_s,
                                  struct ccrng_state *rng)
{
    int result = -1;
    cc_size n = ccec_ctx_n(key);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r = CC_ALLOC_WS(ws, n);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    cc_assert(ccec_ctx_size(key) == ccec_signature_r_s_size(ccec_ctx_pub(key)));

    // Doing the signature
    result = ccec_sign_internal_ws(ws, key, digest_len, digest, r, s, rng);
    cc_require((result == 0), errOut);

    // Exporting in byte/Big endian format, padded to the size of the key.
    ccn_write_uint_padded_ct(ccec_ctx_n(key), r, ccec_signature_r_s_size(ccec_ctx_pub(key)), sig_r);
    ccn_write_uint_padded_ct(ccec_ctx_n(key), s, ccec_signature_r_s_size(ccec_ctx_pub(key)), sig_s);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_sign_composite_msg(ccec_full_ctx_t key,
                            const struct ccdigest_info *di,
                            size_t msg_len,
                            const uint8_t *msg,
                            uint8_t *sig_r,
                            uint8_t *sig_s,
                            struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);
    cc_size digest_n = ccn_nof_size(di->output_size);
    CC_DECL_WORKSPACE_OR_FAIL(ws, digest_n + CCEC_SIGN_COMPOSITE_WORKSPACE_N(ccec_cp_n(cp)));

    uint8_t *digest = (uint8_t *)CC_ALLOC_WS(ws, digest_n);
    ccdigest(di, msg_len, msg, digest);

    int rv = ccec_sign_composite_ws(ws, key, di->output_size, digest, sig_r, sig_s, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccec_sign_composite(ccec_full_ctx_t key,
                        size_t digest_len,
                        const uint8_t *digest,
                        uint8_t *sig_r,
                        uint8_t *sig_s,
                        struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_SIGN_COMPOSITE_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_sign_composite_ws(ws, key, digest_len, digest, sig_r, sig_s, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
