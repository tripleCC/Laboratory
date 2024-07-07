/* Copyright (c) (2012,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccsrp_internal.h"

void ccsrp_generate_k_ws(cc_ws_t ws, ccsrp_ctx_t srp, cc_unit *k)
{
    ccsrp_digest_ccn_ccn_ws(ws, srp, k,
                            ccdh_gp_prime(ccsrp_ctx_gp(srp)),
                            ccsrp_ctx_gp_g(srp),
                            0,
                            (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_k_U_X));
}

void ccsrp_generate_u_ws(cc_ws_t ws, ccsrp_ctx_t srp, cc_unit *u, const cc_unit *A, const cc_unit *B)
{
    size_t u_nbytes = ccsrp_generate_u_nbytes(srp);

    if ((SRP_FLG(srp).variant & CCSRP_OPTION_VARIANT_MASK) != CCSRP_OPTION_VARIANT_SRP6a) {
        A = NULL;
    }

    ccsrp_digest_ccn_ccn_ws(
        ws, srp, u, A, B, u_nbytes, (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_k_U_X));
}
