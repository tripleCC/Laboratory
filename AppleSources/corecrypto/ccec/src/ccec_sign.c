/* Copyright (c) (2010-2012,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#define USE_CCDER 1

#include "cc_internal.h"
#include <corecrypto/ccec_priv.h>
#include "cc_macros.h"
#include "cc_debug.h"
#include "ccec_internal.h"
#if USE_CCDER
#include <corecrypto/ccder.h>
#else
#include <corecrypto/ccasn1.h>
#endif

static int ccec_sign_ws(cc_ws_t ws,
                        ccec_full_ctx_t key,
                        size_t digest_len,
                        const uint8_t *digest,
                        size_t *sig_len,
                        uint8_t *sig,
                        struct ccrng_state *rng)
{
    int result;

    cc_size n = ccec_ctx_n(key);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r = CC_ALLOC_WS(ws, n);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    result = ccec_sign_internal_ws(ws, key, digest_len, digest, r, s, rng);
    cc_require((result == CCERR_OK), errOut);

    /* Encode resulting signature into sig as SEQUENCE { r, s -- integer } */
#if USE_CCDER
    size_t s_len = ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE,
                                ccder_sizeof_integer(ccec_ctx_n(key), r) + ccder_sizeof_integer(ccec_ctx_n(key), s));
    if (*sig_len < s_len) {
        *sig_len = s_len;
        result = CCERR_BUFFER_TOO_SMALL;
        goto errOut;
    }
    *sig_len = s_len;

    uint8_t *der_end = sig + s_len;
    ccder_encode_constructed_tl(
        CCDER_CONSTRUCTED_SEQUENCE,
        der_end,
        sig,
        ccder_encode_integer(ccec_ctx_n(key), r, sig, ccder_encode_integer(ccec_ctx_n(key), s, sig, der_end)));

#else

    uint8_t tl, rl, sl, ll;
    int six = 0;
    rl = ccn_write_int_size(ccec_ctx_n(key), r);
    sl = ccn_write_int_size(ccec_ctx_n(key), s);
    tl = rl + sl + 4;
    if (tl < 0x80)
        ll = 1;
    else
        ll = 2;

    if (*sig_len < (size_t)tl + ll + 1) {
        *sig_len = tl + ll + 1;
        result = CCERR_BUFFER_TOO_SMALL;
        goto errOut;
    }
    *sig_len = tl + ll + 1;
    sig[six++] = CCASN1_CONSTRUCTED_SEQUENCE;
    if (tl < 0x80)
        sig[six++] = tl;
    else {
        sig[six++] = 0x81;
        sig[six++] = tl;
    }
    sig[six++] = CCASN1_INTEGER;
    sig[six++] = rl;
    ccn_write_int(ccec_ctx_n(key), r, rl, sig + six);
    six += rl;
    sig[six++] = CCASN1_INTEGER;
    sig[six++] = sl;
    ccn_write_int(ccec_ctx_n(key), s, sl, sig + six);
#endif

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_sign_msg_ws(cc_ws_t ws,
                     ccec_full_ctx_t key,
                     const struct ccdigest_info *di,
                     size_t msg_len,
                     const uint8_t *msg,
                     size_t *sig_len,
                     uint8_t *sig,
                     struct ccrng_state *rng)
{
    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];
    ccdigest(di, msg_len, msg, digest);

    return ccec_sign_ws(ws, key, di->output_size, digest, sig_len, sig, rng);
}

int ccec_sign_msg(ccec_full_ctx_t key,
                  const struct ccdigest_info *di,
                  size_t msg_len,
                  const uint8_t *msg,
                  size_t *sig_len,
                  uint8_t *sig,
                  struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_SIGN_MSG_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_sign_msg_ws(ws, key, di, msg_len, msg, sig_len, sig, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccec_sign(ccec_full_ctx_t key,
              size_t digest_len,
              const uint8_t *digest,
              size_t *sig_len,
              uint8_t *sig,
              struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_SIGN_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_sign_ws(ws, key, digest_len, digest, sig_len, sig, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
