/* Copyright (c) (2018-2023) Apple Inc. All rights reserved.
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
#include "cc_fault_canary_internal.h"
#include "cc_macros.h"

CC_NONNULL_ALL CC_WARN_RESULT
static bool ccrsa_verify_check_sig_length(const ccrsa_pub_ctx_t key,
                                          size_t sig_len,
                                          int sig_len_validation)
{
    cc_size n = ccrsa_ctx_n(key);
    size_t m_size = ccn_write_uint_size(n, ccrsa_ctx_m(key));

    switch (sig_len_validation) {
    case CCRSA_SIG_LEN_VALIDATION_ALLOW_SHORT_SIGS:
        return sig_len <= m_size;
    default:
        return sig_len == m_size;
    }
}

int ccrsa_verify_pkcs1v15_internal_ws(cc_ws_t ws,
                                      const ccrsa_pub_ctx_t key,
                                      const uint8_t *oid,
                                      size_t digest_len,
                                      const uint8_t *digest,
                                      size_t sig_len,
                                      const uint8_t *sig,
                                      int sig_len_validation,
                                      cc_fault_canary_t fault_canary_out)
{
    CC_FAULT_CANARY_CLEAR(fault_canary_out);
    cc_size n = ccrsa_ctx_n(key);

    if (!ccrsa_verify_check_sig_length(key, sig_len, sig_len_validation)) {
        return CCRSA_INVALID_INPUT;
    }

    volatile int rv;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *s = CC_ALLOC_WS(ws, n);
    cc_unit *t = CC_ALLOC_WS(ws, n);
    CC_CLEAR_BP_WS(ws, bp);

    // Read signature.
    rv = CCERR_INTERNAL;
    rv = ccn_read_uint(n, s, sig_len, sig);
    cc_require_action(CC_MULTI_IF_AND(rv == 0), errOut, rv = CCRSA_INVALID_INPUT);

    // Public key operation.
    rv = CCERR_INTERNAL;
    rv = ccrsa_pub_crypt_ws(ws, key, t, s);
    cc_require(CC_MULTI_IF_AND(rv == CCERR_OK), errOut);

    // Prepare data for encoding verification.
    ccn_swap(n, t);

    size_t m_size = ccn_write_uint_size(n, ccrsa_ctx_m(key));
    const uint8_t *em = (const uint8_t *)t + (ccn_sizeof_n(n) - m_size);

    // Verify encoding.
    rv = CCERR_INTERNAL;
    rv = ccrsa_emsa_pkcs1v15_verify_canary_out(m_size, em, digest_len, digest, oid, fault_canary_out);
    cc_require_action(CC_MULTI_IF_AND(rv == CCERR_OK), errOut, rv = CCERR_INVALID_SIGNATURE);

    // rv = CCERR_VALID_SIGNATURE, if fault canary is good.
    rv ^= CCRSA_PKCS1_FAULT_CANARY_XOR;
    CC_FAULT_CANARY_XOR_RV(rv, fault_canary_out);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccrsa_verify_pkcs1v15_internal(const ccrsa_pub_ctx_t key,
                                   const uint8_t *oid,
                                   size_t digest_len,
                                   const uint8_t *digest,
                                   size_t sig_len,
                                   const uint8_t *sig,
                                   int sig_len_validation,
                                   cc_fault_canary_t fault_canary_out)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_VERIFY_PKCS1V15_INTERNAL_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_verify_pkcs1v15_internal_ws(ws, key, oid, digest_len, digest, sig_len, sig, sig_len_validation, fault_canary_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
