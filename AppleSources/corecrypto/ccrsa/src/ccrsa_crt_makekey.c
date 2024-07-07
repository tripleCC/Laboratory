/* Copyright (c) (2019-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccn_internal.h"
#include "cczp_internal.h"
#include "ccrsa_internal.h"
#include "cc_macros.h"
#include "cc_workspaces.h"

int ccrsa_crt_makekey_ws(cc_ws_t ws, ccrsa_full_ctx_t fk)
{
    int status;

    cczp_t zm = ccrsa_ctx_zm(fk);
    cczp_t zp = ccrsa_ctx_private_zp(fk);
    cczp_t zq = ccrsa_ctx_private_zq(fk);

    cc_size n = cczp_n(zm);
    cc_size pn = cczp_n(zp);
    cc_size qn = cczp_n(zq);

    if (pn < qn || pn > n / 2 + 1) {
        return CCERR_INTERNAL;
    }

    /* p might be one whole unit longer than q, but the public modulus will
     never be more than pbits + qbits bits, and qbits is at most two bits less
     than pbits. */
    if (ccn_cmpn(pn, cczp_prime(zp), qn, cczp_prime(zq)) <= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    // n+2 units to handle intermediate results when n < pn+qn or n < 2*pn.
    cc_unit *tmp = CC_ALLOC_WS(ws, n + 2);
    cc_unit *pm1 = CC_ALLOC_WS(ws, n / 2 + 1);
    cc_unit *qm1 = CC_ALLOC_WS(ws, n / 2 + 1);

    // Compute m = p * q.
    ccn_clear(n, tmp);
    ccn_mul_ws(ws, qn, tmp, cczp_prime(zp), cczp_prime(zq));

    // Handle cczp_n(zp) > cczp_n(zq).
    for (size_t i = 0; i < (pn - qn); i++) {
        tmp[(qn * 2) + i] = ccn_addmul1(qn, &tmp[qn + i], cczp_prime(zq), cczp_prime(zp)[qn + i]);
    }

    ccn_set(n, CCZP_PRIME(zm), tmp);
    cc_require((status = cczp_init_ws(ws, zm)) == CCERR_OK, errOut);

    // Compute p-1, q-1.
    ccn_set(pn, pm1, cczp_prime(zp));
    ccn_setn(pn, qm1, qn, cczp_prime(zq));

    // Since p, q are odd we just clear bit 0 to subtract 1.
    cc_assert((pm1[0] & 1) && (qm1[0] & 1));
    pm1[0] &= ~CC_UNIT_C(1);
    qm1[0] &= ~CC_UNIT_C(1);

    // lambda = lcm(p-1, q-1)
    ccn_clear(n, tmp);
    ccn_lcm_ws(ws, pn, tmp, pm1, qm1);

    const cc_unit *e = ccrsa_ctx_e(fk);
    cc_unit *d = ccrsa_ctx_d(fk);

    // Compute d = e^(-1) (mod lcm(p-1, q-1)) (X9.31's "lambda function")
    cc_require((status = ccn_invmod_ws(ws, n, d, ccn_n(n, e), e, tmp)) == 0, errOut);

    /* dp = d mod (p-1) */
    ccn_mod_ws(ws, n, d, pn, ccrsa_ctx_private_dp(fk), pm1);

    /* dq = d mod (q-1) */
    ccn_mod_ws(ws, n, d, pn, ccrsa_ctx_private_dq(fk), qm1);

    /* qInv = q^(-1) mod p. This requires q to be at least as long as p with
       proper zero padding. Obviously qInv can be as big as p too. */
    ccn_setn(pn, ccrsa_ctx_private_qinv(fk), qn, cczp_prime(zq));
    cc_require_action(cczp_inv_ws(ws, zp, ccrsa_ctx_private_qinv(fk), ccrsa_ctx_private_qinv(fk)) == 0, errOut,
        status = CCRSA_KEYGEN_MODULUS_CRT_INV_ERROR);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}
