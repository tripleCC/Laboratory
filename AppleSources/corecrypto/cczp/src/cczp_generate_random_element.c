/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_macros.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include "ccn_internal.h"
#include <corecrypto/cczp.h>
#include "cczp_internal.h"

#define NUMBER_OF_EXTRA_BITS 64
#define NUMBER_OF_EXTRA_BYTES CC_BITLEN_TO_BYTELEN(NUMBER_OF_EXTRA_BITS)

/*
 cczp_generate_non_zero_element follows the FIPS186-4 "Extra Bits" method
 for generating values within a particular range.
 */

int cczp_generate_random_element_ws(cc_ws_t ws, cczp_const_t zp, struct ccrng_state *rng, cc_unit *out)
{
    int result;
    CC_DECL_BP_WS(ws, bp);

    cc_size n = cczp_n(zp);
    cc_size bitlen = cczp_bitlen(zp) + NUMBER_OF_EXTRA_BITS;
    cc_size np = ccn_nof(bitlen);
    cc_unit *r = CC_ALLOC_WS(ws, n + ccn_nof_size(NUMBER_OF_EXTRA_BYTES));

    cc_require(((result = ccn_random_bits(bitlen, r, rng)) == 0), cleanup);

    // We are computing out = r % p => out is in the range [0, p)
    cczp_modn_ws(ws, zp, out, np, r);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return result;
}
