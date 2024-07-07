/* Copyright (c) (2011-2022) Apple Inc. All rights reserved.
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
#include "cc_macros.h"

int ccrsa_generate_key_internal_ws(cc_ws_t ws,
                                   size_t nbits,
                                   ccrsa_full_ctx_t fk,
                                   size_t e_nbytes,
                                   const uint8_t *e,
                                   struct ccrng_state *rng,
                                   struct ccrng_state *rng_mr)
{
#if CC_DISABLE_RSAKEYGEN
    (void)ws;
    (void)nbits;    (void)fk;
    (void)e_nbytes; (void)e;
    (void)rng;      (void)rng_mr;

    return CCRSA_FIPS_KEYGEN_DISABLED;
#else
    // RSA key generation takes a lot of stack space, check the key size.
    if (nbits > CCRSA_KEYGEN_MAX_NBITS) {
        return CCRSA_INVALID_INPUT;
    }

    cc_size pbits = (nbits >> 1) + 1, qbits = nbits - pbits;

    // Consistency check for the computations above.
    if (pbits != ((nbits >> 1) + 1) || (qbits + pbits) != nbits) {
        return CCERR_INTERNAL;
    }

    cc_size n = ccn_nof(nbits);
    CC_DECL_BP_WS(ws, bp);

    /* size of pub zp priv zp and zq - ensure p > q */
    ccrsa_ctx_n(fk) = n;
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);

    CCZP_N(ccrsa_ctx_private_zp(fk)) = ccn_nof(pbits);
    CCZP_N(ccrsa_ctx_private_zq(fk)) = ccn_nof(qbits);

    int rv = ccn_read_uint(n, ccrsa_ctx_e(pubk), e_nbytes, e);
    cc_require(rv == CCERR_OK, errOut);

    /* The public key e must be odd. */
    cc_require_action(ccrsa_ctx_e(pubk)[0] & 1, errOut, rv = CCRSA_INVALID_INPUT);

    /* The public key e must be > 1. */
    cc_require_action(ccn_bitlen(n, ccrsa_ctx_e(pubk)) > 1, errOut, rv = CCRSA_INVALID_INPUT);

    cczp_t zp = ccrsa_ctx_private_zp(fk);
    cczp_t zq = ccrsa_ctx_private_zq(fk);

    /* Generate random n bit primes p and q. */
    rv = ccrsa_generate_prime_ws(ws, pbits, CCZP_PRIME(zp), ccrsa_ctx_e(pubk), rng, rng_mr);
    cc_require(rv == CCERR_OK, errOut);

    rv = cczp_init_ws(ws, zp);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccrsa_generate_prime_ws(ws, qbits, CCZP_PRIME(zq), ccrsa_ctx_e(pubk), rng, rng_mr);
    cc_require(rv == CCERR_OK, errOut);

    rv = cczp_init_ws(ws, zq);
    cc_require(rv == CCERR_OK, errOut);

    rv = ccrsa_crt_makekey_ws(ws, fk);
    cc_require(rv == CCERR_OK, errOut);

    /* Final consistency check. */
    rv = ccrsa_pairwise_consistency_check_ws(ws, fk, rng);
    if (rv) {
        rv = CCRSA_KEYGEN_KEYGEN_CONSISTENCY_FAIL;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
#endif
}

int ccrsa_generate_key_internal(size_t nbits, ccrsa_full_ctx_t fk,
                                size_t e_nbytes, const uint8_t *e,
                                struct ccrng_state *rng,
                                struct ccrng_state *rng_mr)
{
    cc_size n = ccn_nof(nbits);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_GENERATE_KEY_INTERNAL_WORKSPACE_N(n));
    int rv = ccrsa_generate_key_internal_ws(ws, nbits, fk, e_nbytes, e, rng, rng_mr);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
