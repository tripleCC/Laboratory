/* Copyright (c) (2011,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_priv.h>
#include "ccdh_internal.h"
#include "cc_internal.h"
#include "cc_macros.h"

/* Compute an DH shared secret between private_key and public_key. Return
   the result in computed_key and the length of the result in bytes in
   *computed_key_len. Return 0 iff successful. */
int ccdh_compute_shared_secret_ws(cc_ws_t ws,
                                  ccdh_full_ctx_t private_key,
                                  ccdh_pub_ctx_t public_key,
                                  size_t *computed_shared_secret_len,
                                  uint8_t *computed_shared_secret,
                                  struct ccrng_state *blinding_rng)
{
    ccdh_const_gp_t gp = ccdh_ctx_gp(private_key);
    cc_size n = ccdh_gp_n(gp);

    size_t outlen = CC_BITLEN_TO_BYTELEN(ccdh_gp_prime_bitlen(gp));

    if (outlen > *computed_shared_secret_len) {
        return CCDH_INVALID_INPUT;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r = CC_ALLOC_WS(ws, n);

    /* Validate the public key */
    int rv = ccdh_check_pub_ws(ws, gp, public_key);
    cc_require(rv == CCERR_OK, errOut);

    /* Actual computation */
    rv = ccdh_power_blinded_ws(ws, blinding_rng, gp, r, ccdh_ctx_y(public_key), ccdh_gp_prime_bitlen(gp), ccdh_ctx_x(private_key));
    cc_require(rv == CCERR_OK, errOut);

    /* Result can't be 0 (computation issue) or 1 (y in the group) or p-1, where p is size of group*/
    if (ccdh_valid_shared_secret(n, r, gp)) {
        *computed_shared_secret_len = ccn_write_uint_size(n, r);
        ccn_write_uint(n, r, *computed_shared_secret_len, computed_shared_secret);
    } else {
        rv = CCDH_INVALID_INPUT;
        *computed_shared_secret_len = 0;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccdh_compute_shared_secret(ccdh_full_ctx_t private_key,
                               ccdh_pub_ctx_t public_key,
                               size_t *computed_shared_secret_len,
                               uint8_t *computed_shared_secret,
                               struct ccrng_state *blinding_rng)
{
    CC_ENSURE_DIT_ENABLED

    ccdh_const_gp_t gp = ccdh_ctx_gp(private_key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCDH_COMPUTE_SHARED_SECRET_WORKSPACE_N(ccdh_gp_n(gp)));
    int rv = ccdh_compute_shared_secret_ws(ws, private_key, public_key,
                                           computed_shared_secret_len,
                                           computed_shared_secret,
                                           blinding_rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
