/* Copyright (c) (2010-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#define USE_CCDER_STRICT 0

#include "cc_internal.h"
#include "ccec_internal.h"
#include <corecrypto/ccder.h>
#include "cc_macros.h"

static int decode_signature(cc_size n, size_t sig_len, const uint8_t *sig, cc_unit *r, cc_unit *s, int strict)
{
    int result = CCERR_PARAMETER;

    const uint8_t *der_end = sig + sig_len;
    if (strict) {
        cc_require(ccder_decode_seqii_strict(n, r, s, sig, der_end) == der_end, err);
    } else {
        cc_require(ccder_decode_seqii(n, r, s, sig, der_end) == der_end, err);
    }

    result = CCERR_OK;
err:
    return result;
}

int ccec_extract_rs_ws(cc_ws_t ws,
                       ccec_pub_ctx_t key,
                       size_t sig_len,
                       const uint8_t *sig,
                       uint8_t *r_out,
                       uint8_t *s_out)
{
    int result = CCERR_PARAMETER;
    cc_size n = ccec_ctx_n(key);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r = CC_ALLOC_WS(ws, n);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    cc_require(decode_signature(n, sig_len, sig, r, s, USE_CCDER_STRICT) == CCERR_OK, out);

    if (r_out) {
        cc_require(ccn_write_uint_padded_ct(n, r, ccec_signature_r_s_size(key), r_out) >= 0, out);
    }
    if (s_out) {
        cc_require(ccn_write_uint_padded_ct(n, s, ccec_signature_r_s_size(key), s_out) >= 0, out);
    }
    result = CCERR_OK;

out:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_extract_rs(ccec_pub_ctx_t key, size_t sig_len, const uint8_t *sig, uint8_t *r_out, uint8_t *s_out)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_EXTRACT_RS_WORKSPACE_N(ccec_ctx_n(key)));
    int rv = ccec_extract_rs_ws(ws, key, sig_len, sig, r_out, s_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

static int ccec_verify_digest_ws(cc_ws_t ws,
                                 ccec_pub_ctx_t key,
                                 size_t digest_len,
                                 const uint8_t *digest,
                                 size_t sig_len,
                                 const uint8_t *sig,
                                 cc_fault_canary_t fault_canary_out)
{
    if (fault_canary_out) {
        CC_FAULT_CANARY_CLEAR(fault_canary_out);
    }
    cc_fault_canary_t fault_canary;

    int result = CCERR_INVALID_SIGNATURE;
    cc_size n = ccec_ctx_n(key);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r = CC_ALLOC_WS(ws, n);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    cc_require_action(
        decode_signature(n, sig_len, sig, r, s, USE_CCDER_STRICT) == CCERR_OK, out, result = CCERR_PARAMETER);

    result = ccec_verify_internal_ws(ws, key, digest_len, digest, r, s, fault_canary);
    cc_require(result == CCERR_VALID_SIGNATURE, out);

    if (fault_canary_out) {
        CC_FAULT_CANARY_MEMCPY(fault_canary_out, fault_canary);
    }

out:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_verify_digest(ccec_pub_ctx_t key,
                       size_t digest_len,
                       const uint8_t *digest,
                       size_t sig_len,
                       const uint8_t *sig,
                       cc_fault_canary_t fault_canary_out)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_VERIFY_DIGEST_WORKSPACE_N(ccec_ctx_n(key)));
    int rv = ccec_verify_digest_ws(ws, key, digest_len, digest, sig_len, sig, fault_canary_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccec_verify_msg_ws(cc_ws_t ws,
                       ccec_pub_ctx_t key,
                       const struct ccdigest_info *di,
                       size_t msg_len,
                       const uint8_t *msg,
                       size_t sig_len,
                       const uint8_t *sig,
                       cc_fault_canary_t fault_canary_out)
{
    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];
    ccdigest(di, msg_len, msg, digest);

    return ccec_verify_digest_ws(ws, key, di->output_size, digest, sig_len, sig, fault_canary_out);
}

int ccec_verify_msg(ccec_pub_ctx_t key,
                    const struct ccdigest_info *di,
                    size_t msg_len,
                    const uint8_t *msg,
                    size_t sig_len,
                    const uint8_t *sig,
                    cc_fault_canary_t fault_canary_out)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_VERIFY_MSG_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_verify_msg_ws(ws, key, di, msg_len, msg, sig_len, sig, fault_canary_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccec_verify(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest, size_t sig_len, const uint8_t *sig, bool *valid)
{
    CC_ENSURE_DIT_ENABLED

    *valid = false;
    int result = ccec_verify_digest(key, digest_len, digest, sig_len, sig, NULL);

    switch (result) {
    case CCERR_VALID_SIGNATURE:
        *valid = true;
        result = CCERR_OK; // Maintain backwards compatibility
        break;
    case CCERR_INVALID_SIGNATURE:
        *valid = false;
        result = CCERR_OK; // Maintain backwards compatibility
        break;
    default:
        *valid = false;
    }
    return result;
}

static int ccec_verify_strict_ws(cc_ws_t ws,
                                 ccec_pub_ctx_t key,
                                 size_t digest_len,
                                 const uint8_t *digest,
                                 size_t sig_len,
                                 const uint8_t *sig,
                                 bool *valid)
{
    int result = CCERR_INVALID_SIGNATURE;
    cc_size n = ccec_ctx_n(key);
    *valid = false;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r = CC_ALLOC_WS(ws, n);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    cc_fault_canary_t unused_fault_canary;
    bool strict = true;

    cc_require_action(decode_signature(n, sig_len, sig, r, s, strict) == CCERR_OK, err, result = CCERR_PARAMETER);

    result = ccec_verify_internal_ws(ws, key, digest_len, digest, r, s, unused_fault_canary);

    switch (result) {
    case CCERR_VALID_SIGNATURE:
        *valid = true;
        result = CCERR_OK; // Maintain backwards compatibility
        break;
    case CCERR_INVALID_SIGNATURE:
        *valid = false;
        result = CCERR_OK; // Maintain backwards compatibility
        break;
    default:
        *valid = false;
    }

err:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int ccec_verify_strict(ccec_pub_ctx_t key,
                       size_t digest_len,
                       const uint8_t *digest,
                       size_t sig_len,
                       const uint8_t *sig,
                       bool *valid)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_VERIFY_STRICT_WORKSPACE_N(ccec_ctx_n(key)));
    int rv = ccec_verify_strict_ws(ws, key, digest_len, digest, sig_len, sig, valid);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
