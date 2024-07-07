/* Copyright (c) (2012,2014-2017,2019-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccder.h>
#include "cc_macros.h"

/*! @function ccrsa_ensure_2p_gt_q
 @abstract Checks whether 2*p > q.

 @param np  Length of p in cc_units
 @param p   Prime p
 @param nq  Length of q in cc_units
 @param q   Prime q

 @return 0 if 2*p > q, -1 otherwise.
 */
static int ccrsa_ensure_2p_gt_q_ws(cc_ws_t ws, cc_size np, const cc_unit *p, cc_size nq, const cc_unit *q)
{
    cc_size n = np;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp = CC_ALLOC_WS(ws, n + 1);

    tmp[np] = p[np - 1] >> (CCN_UNIT_BITS - 1);
    ccn_shift_left(np, tmp, p, 1);

    // Check if 2*p > q (i.e. rv=1).
    int rv = ccn_cmpn(np + 1, tmp, nq, q);
    // Set rv=0, iff 2*p > q. rv=1 otherwise.
    CC_HEAVISIDE_STEP(rv, rv ^ 1);
    // Return 0 or -1.
    rv = -rv;

    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_WARN_RESULT CC_NONNULL_ALL
const uint8_t *ccder_decode_rsa_priv_ws(cc_ws_t ws, const ccrsa_full_ctx_t key, const uint8_t *der, const uint8_t *der_end)
{
    cc_size n = ccrsa_ctx_n(key);
    cc_size pqn = ccn_nof(ccn_bitsof_n(n) / 2 + 1);

    CC_DECL_BP_WS(ws, bp);
    der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end);

    // Check that version == 0.
    cc_unit version_0 = 0x00;
    der = ccder_decode_uint(1, &version_0, der, der_end);
    cc_require(der != NULL, errOut);
    cc_require_action(version_0 == 0, errOut, der = NULL);

    der = ccder_decode_uint(n, ccrsa_ctx_m(key), der, der_end);
    der = ccder_decode_uint(n, ccrsa_ctx_e(key), der, der_end);
    der = ccder_decode_uint(n, ccrsa_ctx_d(key), der, der_end);
    cc_require(der != NULL, errOut);

    cc_require_action(cczp_init_ws(ws, ccrsa_ctx_zm(key)) == CCERR_OK, errOut, der = NULL);

    cczp_t zp = ccrsa_ctx_private_zp(key);
    der = ccder_decode_uint(pqn, CCZP_PRIME(zp), der, der_end);
    cc_require(der != NULL, errOut);

    CCZP_N(zp) = ccn_nof(ccn_bitlen(pqn, cczp_prime(zp)));
    cc_require_action(cczp_init_ws(ws, zp) == CCERR_OK, errOut, der = NULL);

    cczp_t zq = ccrsa_ctx_private_zq(key);
    der = ccder_decode_uint(pqn, CCZP_PRIME(zq), der, der_end);
    cc_require(der != NULL, errOut);

    CCZP_N(zq) = ccn_nof(ccn_bitlen(pqn, cczp_prime(zq)));
    cc_require_action(cczp_init_ws(ws, zq) == CCERR_OK, errOut, der = NULL);

    // Ensure |p| >= |q|.
    cc_require_action(cczp_bitlen(zp) >= cczp_bitlen(zq), errOut, der = NULL);

    // Ensure 2*p > q for Garner recombination.
    cc_require_action(ccrsa_ensure_2p_gt_q_ws(ws, cczp_n(zp), cczp_prime(zp), cczp_n(zq), cczp_prime(zq)) == CCERR_OK, errOut, der = NULL);

    der = ccder_decode_uint(cczp_n(zp), ccrsa_ctx_private_dp(key), der, der_end);
    der = ccder_decode_uint(cczp_n(zq), ccrsa_ctx_private_dq(key), der, der_end);
    der = ccder_decode_uint(cczp_n(zp), ccrsa_ctx_private_qinv(key), der, der_end);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return der;
}

const uint8_t *ccder_decode_rsa_priv(const ccrsa_full_ctx_t key, const uint8_t *der, const uint8_t *der_end)
{
    CC_ENSURE_DIT_ENABLED

    int rv;
    CC_DECL_WORKSPACE_RV(ws, CCDER_DECODE_RSA_PRIV_WORKSPACE_N(ccrsa_ctx_n(key)), rv);
    if (rv) {
        return NULL;
    }

    der = ccder_decode_rsa_priv_ws(ws, key, der, der_end);
    CC_FREE_WORKSPACE(ws);
    return der;
}
