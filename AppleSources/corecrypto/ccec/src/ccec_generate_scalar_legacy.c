/* Copyright (c) (2015-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include "cc_macros.h"
#include "cc_debug.h"
#include "ccec_internal.h"

/*
 Create a scalar using a buffer of entropy, of size at least ccn_sizeof(ccec_cp_order_bitlen(cp)).

 This approach induces a bias on the generated scalar, hence this method is NOT recommended.
 This function is only available to reconstruct deterministic keys made with this method.
 */
int ccec_generate_scalar_legacy_ws(cc_ws_t ws, ccec_const_cp_t cp, size_t entropy_nbytes, const uint8_t *entropy, cc_unit *k)
{
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = ccec_cp_n(cp);

    // Ensure that there is at least ccn_sizeof_n(n) bytes of entropy
    cc_require_or_return(entropy_nbytes >= ccn_sizeof_n(n), CCEC_GENERATE_NOT_ENOUGH_ENTROPY);

    // Copy ccn_sizeof_n(n) bytes of entropy
    cc_memcpy(k, entropy, ccn_sizeof_n(n));

    // Truncate the most significant bits
    cc_size lbits = ccec_cp_order_bitlen(cp) & (CCN_UNIT_BITS - 1);
    if (lbits) {
        k[n - 1] &= (CCN_UNIT_MASK >> (CCN_UNIT_BITS - lbits));
    }

    // Now that 0 <= k < 2 * q, adjust k to be in the correct range with a conditional subtraction
    CC_DECL_BP_WS(ws, bp);
    cc_unit *kmq = CC_ALLOC_WS(ws, n);
    cc_unit s = ccn_sub_ws(ws, n, kmq, k, cczp_prime(zq)); // s = 0 if k >= q
    ccn_mux(n, s ^ 1, k, kmq, k);
    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

int ccec_generate_scalar_legacy(ccec_const_cp_t cp, size_t entropy_nbytes, const uint8_t *entropy, cc_unit *k)
{
    cc_size n = ccec_cp_n(cp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_GENERATE_SCALAR_LEGACY_WORKSPACE_N(n));
    int rv = ccec_generate_scalar_legacy_ws(ws, cp, entropy_nbytes, entropy, k);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
