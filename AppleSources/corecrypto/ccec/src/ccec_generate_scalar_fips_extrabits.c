/* Copyright (c) (2015-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include "ccec_internal.h"
#include "cc_macros.h"

/* Make a scalar k in the good range and without bias */
/* Implementation per FIPS186-4 - "Extra bits" */

/* requires at least CC_BITLEN_TO_BYTELEN(ccec_cp_order_bitlen(cp)+64) of entropy
 Compute k as k=(entropy mod (q-1) + 1) */
#define NUMBER_OF_EXTRABITS 64

// 128 bytes is a lot more entropy than we need but we
// have to support existing callers passing up to 128 bytes.
#define ENTROPY_NBYTES_MAX 128
#define ENTROPY_NUNITS_MAX ccn_nof_size(ENTROPY_NBYTES_MAX)

size_t ccec_scalar_fips_extrabits_min_entropy_len(ccec_const_cp_t cp)
{
    return CC_BITLEN_TO_BYTELEN(ccec_cp_order_bitlen(cp) + NUMBER_OF_EXTRABITS);
}

int ccec_generate_scalar_fips_extrabits_ws(cc_ws_t ws,
                                           ccec_const_cp_t cp,
                                           size_t entropy_len,
                                           const uint8_t *entropy,
                                           cc_unit *k)
{
    int retval = CCEC_GENERATE_KEY_DEFAULT_ERR;
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = cczp_n(zq);

    CC_DECL_BP_WS(ws, bp);

    // Minimum and maximum size for the entropy
    cc_require_action(entropy_len >= ccec_scalar_fips_extrabits_min_entropy_len(cp),
                      errOut, retval = CCEC_GENERATE_NOT_ENOUGH_ENTROPY);
    cc_require_action(entropy_len <= ENTROPY_NBYTES_MAX,
                      errOut, retval = CCERR_PARAMETER);

    cc_unit *kn = CC_ALLOC_WS(ws, ENTROPY_NUNITS_MAX);
    cc_unit *qm1 = CC_ALLOC_WS(ws, n);
    ccn_set(n, qm1, cczp_prime(zq));
    qm1[0] &= ~CC_UNIT_C(1);

    // Method is from FIPS 186-4 Extra Bits method.
    //  k = entropy mod (q-1)) + 1, where entropy is interpreted as big endian.
    cc_require((retval=ccn_read_uint(ENTROPY_NUNITS_MAX, kn, entropy_len, entropy))==0,errOut);

    /* Compute r = (c mod (q-1)) + 1 via regular division to protect the entropy. */
    ccn_mod_ws(ws, ccn_nof_size(entropy_len), kn, n, k, qm1);
    (void)ccn_add1_ws(ws, n, k, k, 1); // We know there is no carry happening here

errOut:
    CC_FREE_BP_WS(ws, bp);
    return retval;
}

int ccec_generate_scalar_fips_extrabits(ccec_const_cp_t cp,
                                        size_t entropy_len,
                                        const uint8_t *entropy,
                                        cc_unit *k)
{
    cczp_const_t zq = ccec_cp_zq(cp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_GENERATE_SCALAR_FIPS_EXTRABITS_WORKSPACE_N(cczp_n(zq)));
    int rv = ccec_generate_scalar_fips_extrabits_ws(ws, cp, entropy_len, entropy, k);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
