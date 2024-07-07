/* Copyright (c) (2018-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccn.h>
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccrsa_priv.h>
#include "ccrsa_internal.h"
#include "ccn_internal.h"
#include "cc_macros.h"
#include "cc_priv.h"
#include "cc_workspaces.h"

// Parses e,p and q and places them into the RSA context, before we use these
// values to compute the remainder of the context value. Uses a workspace and
// so is factored off from the main function. Ensures p > q, e != 0 and e != 1.
static int ccrsa_make_priv_parse_input_ws(cc_ws_t ws,
                                          ccrsa_full_ctx_t full_ctx,
                                          size_t e_m,
                                          const uint8_t *e,
                                          size_t p_m,
                                          const uint8_t *p,
                                          size_t q_m,
                                          const uint8_t *q_in)
{
    int error = 0;
    const cc_size n = ccrsa_ctx_n(full_ctx);
    const cc_size max_e_blob_n = n;
    const cc_size max_pq_blob_n = max_e_blob_n / 2 + 1;

    // Inputs come in as Big Endian blobs and we need to convert them to
    // little endian. The following buffers hold these values.
    CC_DECL_BP_WS(ws, bp);
    cc_unit *ccn_p = CC_ALLOC_WS(ws, n / 2 + 1);
    cc_unit *ccn_q = CC_ALLOC_WS(ws, n / 2 + 1);
    cc_unit *ccn_e = CC_ALLOC_WS(ws, n);

    // Canonicalize input to little endian, and strip leading zeros.
    // Read p, q and e in that order.
    cc_require_action(ccn_read_uint(max_pq_blob_n, ccn_p, p_m, p) == 0, error_out, error = CCRSA_INVALID_INPUT);
    cc_require_action(ccn_read_uint(max_pq_blob_n, ccn_q, q_m, q_in) == 0, error_out, error = CCRSA_INVALID_INPUT);
    cc_require_action(ccn_read_uint(max_e_blob_n, ccn_e, e_m, e) == 0, error_out, error = CCRSA_INVALID_INPUT);
    cc_size ccn_e_n = ccn_n(max_e_blob_n, ccn_e);
    cc_require_action(ccn_is_zero_or_one(ccn_e_n, ccn_e) == 0, error_out, error = CCRSA_INVALID_INPUT);

    // Ensure p is bigger than q.
    unsigned int s = (unsigned int)ccn_cmp(max_pq_blob_n, ccn_p, ccn_q);
    // Ensure the primes are not the same.
    cc_require_action(s != 0, error_out, error = CCRSA_INVALID_INPUT);
    ccn_cond_swap(max_pq_blob_n, (cc_unit)(s >> (sizeof(unsigned int) * 8 - 1)), ccn_p, ccn_q);

    cc_size p_bit_length = ccn_bitlen(max_pq_blob_n, ccn_p);
    cc_size q_bit_length = ccn_bitlen(max_pq_blob_n, ccn_q);

    // Make sure that p is only 2 bits longer than q
    cc_require_action((p_bit_length - q_bit_length) <= 2, error_out, error = CCRSA_KEYGEN_PQ_DELTA_ERROR);

    // Make sure that the product of p and q will fit in the data structure.
    cc_require_action(p_bit_length + q_bit_length <= ccn_bitsof_n(n), error_out, error = CCRSA_INVALID_INPUT);

    cc_size ccn_p_n = ccn_nof(p_bit_length);
    cc_size ccn_q_n = ccn_nof(q_bit_length);

    // Load p,q and e into the rsa context
    CCZP_N(ccrsa_ctx_private_zp(full_ctx)) = ccn_p_n;
    ccn_set(ccn_p_n, CCZP_PRIME(ccrsa_ctx_private_zp(full_ctx)), ccn_p);
    CCZP_N(ccrsa_ctx_private_zq(full_ctx)) = ccn_q_n;
    ccn_set(ccn_q_n, CCZP_PRIME(ccrsa_ctx_private_zq(full_ctx)), ccn_q);
    ccn_setn(n, ccrsa_ctx_e(full_ctx), ccn_e_n, ccn_e);

error_out:
    CC_FREE_BP_WS(ws, bp);
    return error;
}

static int ccrsa_make_priv_ws(cc_ws_t ws, ccrsa_full_ctx_t full_ctx,
                              size_t e_nbytes, const uint8_t *e_bytes,
                              size_t p_nbytes, const uint8_t *p_bytes,
                              size_t q_nbytes, const uint8_t *q_bytes)
{
    CC_DECL_BP_WS(ws, bp);

    // Parse input into RSA context
    int rv = ccrsa_make_priv_parse_input_ws(ws, full_ctx,
                                            e_nbytes, e_bytes,
                                            p_nbytes, p_bytes,
                                            q_nbytes, q_bytes);
    cc_require(rv == CCERR_OK, out);

    rv = cczp_init_ws(ws, ccrsa_ctx_private_zp(full_ctx));
    cc_require(rv == CCERR_OK, out);

    rv = cczp_init_ws(ws, ccrsa_ctx_private_zq(full_ctx));
    cc_require(rv == CCERR_OK, out);

    rv = ccrsa_crt_makekey_ws(ws, full_ctx);

out:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

// Takes p,q,e in big endian format and an instantiated RSA context with the
// size of N specified, and fills in the rsa_full_ctx as a side-effect. Returns
// CCERR_OK if everything is fine, and an appropriate error value otherwise.
int ccrsa_make_priv(ccrsa_full_ctx_t full_ctx,
                    size_t e_nbytes, const uint8_t *e_bytes,
                    size_t p_nbytes, const uint8_t *p_bytes,
                    size_t q_nbytes, const uint8_t *q_bytes)
{
    CC_ENSURE_DIT_ENABLED

    const cc_size n = ccrsa_ctx_n(full_ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_MAKE_PRIV_WORKSPACE_N(n));
    int rv = ccrsa_make_priv_ws(ws, full_ctx, e_nbytes, e_bytes, p_nbytes, p_bytes, q_nbytes, q_bytes);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
