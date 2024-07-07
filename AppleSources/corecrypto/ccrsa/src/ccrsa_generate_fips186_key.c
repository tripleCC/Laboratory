/* Copyright (c) (2014-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrsa_priv.h>
#include "ccrsa_internal.h"
#include "cc_debug.h"
#include <corecrypto/ccrng_rsafips_test.h>
#include "cc_macros.h"
#include "ccprime_internal.h"
#include "cczp_internal.h"
#include "ccn_internal.h"
#include "cc_workspaces.h"

// Utility macros.
#define ccn_cleartop(N,r,partial_n) \
    if((N)>(partial_n)) ccn_zero((N)-(partial_n), (r)+(partial_n))

// Configuration
#define SEED_X_MAX_RETRIES                  100
#define RESEED_MAX_RETRIES                  100
#define GENERATE_Q_MAX_RETRIES              100
#define GENERATE_PROBABLE_PRIME_MAX_RETRIES 100

#if !CC_DISABLE_RSAKEYGEN

// Use approximation for sqrt[2]:
// We precompute Sqrt(2)*2^255. Mathematica code snippet:
//  mySqrt2 = IntegerPart[N[Sqrt[2]*2^255, 40]];
//  Print[IntegerString[IntegerDigits[mySqrt2, 256], 16, 2]]

static const cc_unit SQRT2_N = CCN256_N;
static const cc_unit SQRT2[] = {
    CCN256_C(b5,04,f3,33,f9,de,64,84,59,7d,89,b3,75,4a,be,9f,1d,6f,60,ba,89,3b,a8,4c,ed,17,ac,85,83,33,99,15)
};

//==============================================================================
//                              Internal functions
//==============================================================================

// Determine the bit length of p1, p2 for bit length of p.
// Per FIPS 186-4 Table B.1 and FIPS 186-5 Table A.1.
static cc_size ccrsa_fips186_auxiliary_prime_nbits(cc_size pbits)
{
    // 4096 RSA key size (and above) -> FIPS 186-5
    if (pbits >= 2048) {
        return 201;
    }

    // [3072, 4096) RSA key size -> FIPS 186-4 and FIPS 186-5
    if (pbits >= 1536) {
        return 171;
    }

    // [2048, 3072) RSA key size -> FIPS 186-4 and FIPS 186-5
    if (pbits >= 1024) {
        return 141;
    }

    // (1024, 2048) RSA key size
    // -> Using requirement from 2048 RSA key size FIPS 186-4 and FIPS 186-5
    if (pbits > 512) {
        return 141;
    }

    // <= 1024 RSA key size -> FIPS 186-4
    return 101;
}

// Check that |p-q| > 2^(plen-100) and |Xp-Xq| > 2^(plen-100)
// to ensure that (p,q) and (Xp,Xq) are far enough apart.
CC_NONNULL_ALL CC_WARN_RESULT
static int ccrsa_check_delta_100bits_ws(cc_ws_t ws,
                                        cc_size n,
                                        const cc_unit *p,
                                        const cc_unit *q,
                                        const cc_unit *Xp,
                                        const cc_unit *Xq)
{
    CC_DECL_BP_WS(ws, bp);

    cc_unit *tmp = CC_ALLOC_WS(ws, n);
    cc_unit *delta = CC_ALLOC_WS(ws, n);
    size_t pbits = ccn_bitlen(n, p);

    // 2^(plen-100)
    ccn_zero(n, delta);
    ccn_set_bit(delta, pbits - 100, 1);

    // Abs(p,q)
    (void)ccn_abs(n, tmp, p, q);
    int r1 = ccn_cmp(n, tmp, delta);

    // Abs(Xp,Xq)
    (void)ccn_abs(n, tmp, Xp, Xq);
    int r2 = ccn_cmp(n, tmp, delta);

    CC_FREE_BP_WS(ws,bp);

    if (r1 + r2 == 2) {
        return CCERR_OK;
    }

    return CCRSA_KEYGEN_PQ_DELTA_ERROR;
}

// Provided a value, find the next prime by increment.
CC_NONNULL_ALL CC_WARN_RESULT
static int ccrsa_find_next_prime_ws(cc_ws_t ws, size_t pbits, cc_unit *p, struct ccrng_state *rng_mr)
{
    cc_size n = ccn_nof(pbits);
    cc_size MR_iterations = ccrsa_num_mr_iterations_aux(pbits);

    // Substract two, check the value was >= 2.
    if (ccn_sub1(n, p, p, 2)) {
        return CCRSA_KEYGEN_NEXT_PRIME_ERROR;
    }

    // Ensure p is odd.
    p[0] |= 1;

    int is_prime = 0;
    int rv = CCRSA_KEYGEN_NEXT_PRIME_ERROR;

    CC_DECL_BP_WS(ws, bp);

    // Increment until probably prime according to Miller-Rabin.
    while (is_prime == 0) {
        // p += 2 and check for primality. Exit when p overflows `n` units.
        cc_require(ccn_add1_ws(ws, n, p, p, 2) == 0, errOut);

        is_prime = ccprime_rabin_miller_ws(ws, n, p, MR_iterations, rng_mr);
        cc_require(is_prime == 0 || is_prime == 1, errOut);
    }

    rv = CCERR_OK;

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

// Generate a random number X such that
// (Sqrt(2)*(2^(pbits-1))<= X <= (2^(pbits)-1)
CC_NONNULL_ALL CC_WARN_RESULT
static int ccrsa_seed_X_ws(cc_ws_t ws,
                           cc_size n,
                           cc_unit *X,
                           cc_size pbits,
                           struct ccrng_state *rng)
{
    int status = CCRSA_KEYGEN_SEED_X_ERROR;
    ccn_zero(n, X);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp = CC_ALLOC_WS(ws, n);

    for (size_t i = 0; i < SEED_X_MAX_RETRIES; i += 1) {
        // Generate a random number X
        cc_require(ccn_random_bits_fips(pbits, X, rng) == CCERR_OK, errOut);

        // Set most significant bit
        ccn_set_bit(X, pbits - 1, 1); // must be pbits long

        // Compare to an approximation of sqrt2:
        // copy X to tmp, bit-shift tmp to compare against SQRT2
        ccn_shift_right_multi(n, tmp, X, pbits - ccn_bitsof_n(SQRT2_N));
        if (ccn_cmp(SQRT2_N, tmp, SQRT2) >= 0) {
            status = CCERR_OK;
            break;
        }
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

// Generate the two auxiliary primes r1 and r2 from rng provided specified sizes.
CC_NONNULL((1, 3, 5, 6, 7)) CC_WARN_RESULT
static int ccrsa_generate_auxiliary_primes_ws(cc_ws_t ws,
                                              cc_size r1bits,
                                              cc_unit *r1,
                                              cc_size r2bits,
                                              cc_unit *r2,
                                              struct ccrng_state *rng,
                                              struct ccrng_state *rng_mr,
                                              struct ccrsa_fips186_trace *trace)
{
    int status = CCRSA_KEYGEN_SEED_r_ERROR;
    cc_size n = ccn_nof(r1bits);
    cc_assert(n >= ccn_nof(r2bits));

    // Take seeds for r1 and r2
    ccn_zero(n, r1);
    ccn_zero(n, r2);

    if (ccn_random_bits_fips(r1bits, r1, rng)) {
        return status;
    }
    if (ccn_random_bits_fips(r2bits, r2, rng)) {
        return status;
    }

    CC_DECL_BP_WS(ws, bp);

    // Set MSbit to guarantee bitsize
    ccn_set_bit(r1, r1bits - 1, 1); // must be rxbits long
    ccn_set_bit(r2, r2bits - 1, 1); // must be rxbits long

    if (trace) {
        cc_assert(ccn_sizeof_n(n) <= sizeof(trace->xp1));
        cc_assert(ccn_sizeof_n(n) <= sizeof(trace->xp2));

        trace = trace + trace->curr;
        trace->bitlen1 = ccn_bitlen(n, r1);
        trace->bitlen2 = ccn_bitlen(n, r2);
        cc_memcpy(trace->xp1, r1, ccn_sizeof_n(n));
        cc_memcpy(trace->xp2, r2, ccn_sizeof_n(n));
        trace->xp1[0] |= 1; // these two operations are done in ccrsa_find_next_prime_ws();
        trace->xp2[0] |= 1; // but we cannot catch r1 & r2 there.
    }

    // Transform seed into primes
    status = ccrsa_find_next_prime_ws(ws, r1bits, r1, rng_mr);
    cc_require(status == CCERR_OK, errOut);

    status = ccrsa_find_next_prime_ws(ws, r2bits, r2, rng_mr);
    cc_require(status == CCERR_OK, errOut);

    if (trace) {
        cc_assert(ccn_sizeof_n(n) <= sizeof(trace->p1));
        cc_assert(ccn_sizeof_n(n) <= sizeof(trace->p2));

        cc_memcpy(trace->p1, r1, ccn_sizeof_n(n));
        cc_memcpy(trace->p2, r2, ccn_sizeof_n(n));
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

// R = ((r2^–1 mod 2r1) * r2) – (((2r1)^–1 mod r2) * 2r1).
// Output is {R, r1r2x2}
CC_NONNULL_ALL CC_WARN_RESULT
static int ccrsa_compute_R_ws(cc_ws_t ws,
                              cc_size n,
                              cc_unit *R,
                              cc_unit *r1r2x2,
                              size_t r1bits,
                              const cc_unit *r1,
                              size_t r2bits,
                              const cc_unit *r2)
{
    CC_DECL_BP_WS(ws, bp);

    // Per spec, defined as the CRT so that R=1 (mod 2*r1) and R=-1 (mod r2)
    // This can be rewritten using Garner recombination (HAC p613)
    // R = 1 + 2*r1[r2 - ((r1)^-1 mod r2)]

    cc_size nr = ccn_nof(CC_MAX_EVAL(r1bits + 1, r2bits));
    cc_assert(2 * nr <= n);

    // All intermediary variables normalized to fit on nr cc_units
    cc_unit *tmp1 = CC_ALLOC_WS(ws, n);
    cc_unit *tmp2 = tmp1 + nr;

    ccn_setn(nr, tmp2, ccn_nof(r1bits), r1); // normalize r1
    ccn_setn(nr, R, ccn_nof(r2bits), r2);    // normalize r2 (R as temp)

    // Calculate tmp1 = (r1^{-1} mod r2)
    int rv = ccn_invmod_ws(ws, nr, tmp1, nr, tmp2, R);
    cc_require(rv == CCERR_OK, errOut);

    // Go on with Garner's recombination
    ccn_sub_ws(ws, nr, tmp1, R, tmp1);    // r2 - ((r1)^-1 mod r2)
    ccn_add_ws(ws, nr, tmp2, tmp2, tmp2); // 2*r1

    // r1*r2*2
    ccn_mul_ws(ws, nr, r1r2x2, tmp2, R);
    ccn_cleartop(n, r1r2x2, 2*nr);

    // R = 1 + 2*r1*(r2 - ((r1)^-1 mod r2))
    ccn_mul_ws(ws, nr, R, tmp2, tmp1);
    ccn_add1_ws(ws, 2*nr, R, R, 1); // can't overflow since ((r1)^-1 mod r2) > 0)
    ccn_cleartop(n, R, 2*nr);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

// Generate {p, X} from primes r1 and r2.
// Follows FIPS186-4, B.3.6
// "n" of both p and X must have been set
CC_NONNULL((1, 3, 4, 6, 8, 10, 11, 12)) CC_WARN_RESULT
static int ccrsa_generate_probable_prime_from_aux_primes_ws(cc_ws_t ws,
                                                            cc_size pbits,
                                                            cc_unit *p,
                                                            cc_unit *X,
                                                            size_t r1bits,
                                                            const cc_unit *r1,
                                                            size_t r2bits,
                                                            const cc_unit *r2,
                                                            cc_size ne,
                                                            const cc_unit *e,
                                                            struct ccrng_state *rng,
                                                            struct ccrng_state *rng_mr,
                                                            struct ccrsa_fips186_trace *trace)
{
    int prime_status=CCRSA_KEYGEN_PRIME_NEED_NEW_SEED;
    cc_size n = ccn_nof(pbits);
    cc_size MR_iterations = ccrsa_num_mr_iterations(pbits);
    cc_size r1r2x2max_bitsize;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *R = CC_ALLOC_WS(ws, n);
    cc_unit *tmp = CC_ALLOC_WS(ws, n);
    cc_unit *r1r2x2 = CC_ALLOC_WS(ws, n);

    // Pre-requisite: Check log2(r1.r2) <= pbits - log2(pbits) - 6
    // Equivalent to Check log2(2.r1.r2) <= pbits - log2(pbits) - 5
    R[0]=pbits;
    r1r2x2max_bitsize=pbits-ccn_bitlen(1,R)-5;

    // This constraint met by ccrsa_fips186_auxiliary_prime_nbits
    // Therefore no need to check here.

    // 1) Check GCD(2r1,r2)!=1
    // r1 and r2 are prime and >2 so this check is not needed.

    // 2) R = ((r2^–1 mod 2r1) * r2) – (((2r1)^–1 mod r2) * 2r1).
    // and compute 2.r1.r2
    int rv = ccrsa_compute_R_ws(ws, n, R, r1r2x2, r1bits, r1, r2bits, r2);
    if (rv) {
        prime_status = CCRSA_KEYGEN_PRIME_SEED_GENERATION_ERROR;
    } else if (ccn_bitlen(n, r1r2x2) > r1r2x2max_bitsize) {
        prime_status = CCRSA_KEYGEN_R1R2_SIZE_ERROR;
    }

    // Outer loop for reseeding (rare case)
    for (size_t ctr=0; (ctr<RESEED_MAX_RETRIES) && (prime_status==CCRSA_KEYGEN_PRIME_NEED_NEW_SEED);ctr++)
    {
        cc_unit c; // carry

        // 3) Generate random X
        if (ccrsa_seed_X_ws(ws, n, X, pbits, rng)) {
            prime_status = CCRSA_KEYGEN_PRIME_SEED_GENERATION_ERROR;
            break;
        }

        if (trace) {
            cc_assert(ccn_sizeof_n(n) <= sizeof(trace->xp));

            trace = trace + trace->curr;
            cc_memcpy(trace->xp, X, ccn_sizeof_n(n));
        }

        // 4) Y = X+((R–X) mod 2r1r2)
        ccn_mod_ws(ws, n, X, n, p, r1r2x2);

        // (R-X) mod 2r1r2
        cc_unit borrow = ccn_sub_ws(ws, n, p, R, p);
        ccn_add_ws(ws, n, tmp, r1r2x2, p);
        ccn_mux(n, borrow, p, tmp, p);
        // X+((R–X) mod 2r1r2)
        c = ccn_add_ws(ws, n, p, X, p);
        // c is used for 1st iteration of for loop

        // Inner loop for incremental search.
        // Candidate is now in p.
        // 5,8,9) Increment p until a good candidate is found
        // Iterate a maximum of 5*pbits
        prime_status=CCRSA_KEYGEN_PRIME_TOO_MANY_ITERATIONS;
        for (size_t i = 0; i < 5 * pbits; i += 1)
        {
            // 6) Check p >= 2^pbits
            if ((c > 0) || (pbits < ccn_bitlen(n, p))) {
                // Candidate is too large, needs new seed
                prime_status = CCRSA_KEYGEN_PRIME_NEED_NEW_SEED;
                break;
            }

            /* Check that p is a prime and gcd(p-1,e) == 1. */
            rv = ccrsa_is_valid_prime_ws(ws, n, p, ne, e, MR_iterations, rng_mr);
            if (rv < 0) {
                prime_status = CCRSA_KEYGEN_PRIME_SEED_GENERATION_ERROR;
                break;
            }
            if (rv == 1) {
                prime_status = CCERR_OK; // Prime found
                break;
            }

            // 10) p=p+2.r1.r2
            c = ccn_add_ws(ws, n, p, p, r1r2x2);
        }
    }

    // Prepare exit
    if (prime_status) {
        ccn_clear(n, p);
        ccn_clear(n, X);
    }

    if (trace) {
        cc_assert(ccn_sizeof_n(n) <= sizeof(trace->p));

        // XXX This was present but increments past the end of the array
        //
        // If the FIPS test fails, examine this carefully:
        //    trace = trace + trace->curr;
        cc_memcpy(trace->p, p, ccn_sizeof_n(n));
    }

    CC_FREE_BP_WS(ws, bp);
    return prime_status;
}

// Generate {p, X} from rng and the size of the arbitrary primes to use
CC_NONNULL((1, 3, 4, 8, 9, 10)) CC_WARN_RESULT
static int ccrsa_generate_probable_prime_ws(cc_ws_t ws,
                                            cc_size pbits,
                                            cc_unit *p,
                                            cc_unit *X,
                                            cc_size r1_bitsize,
                                            cc_size r2_bitsize,
                                            cc_size ne,
                                            const cc_unit *e,
                                            struct ccrng_state *rng,
                                            struct ccrng_state *rng_mr,
                                            struct ccrsa_fips186_trace *trace)
{
    int ret = CCERR_INTERNAL;
    cc_size n = ccn_nof(pbits);

    // Sanity check.
    cc_assert(ccn_nof(r1_bitsize) <= n && ccn_nof(r2_bitsize) <= n);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *r1 = CC_ALLOC_WS(ws, n);
    cc_unit *r2 = CC_ALLOC_WS(ws, n);

    unsigned i;
    for (i = 0; ret && (i < GENERATE_PROBABLE_PRIME_MAX_RETRIES); i += 1) {
        // Loops until it finds two aux primes. Does not fail probabilistically.
        ret = ccrsa_generate_auxiliary_primes_ws(ws, r1_bitsize, r1, r2_bitsize, r2, rng, rng_mr, trace);
        cc_require(ret == CCERR_OK, cleanup);

        // May fail probabilistically (albeit very rarely).
        // If it does, generate new aux primes and try again.
        ret = ccrsa_generate_probable_prime_from_aux_primes_ws(ws, pbits, p, X, r1_bitsize, r1, r2_bitsize, r2, ne, e, rng, rng_mr, trace);
    }

    if (i == GENERATE_PROBABLE_PRIME_MAX_RETRIES) {
        ret = CCERR_INTERNAL;
    }

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return ret;
}

// Fill out a ccrsa context given e, p, and q.  The "n" of the key context is expected
// to be set prior to this call.  p and q are cczps with no assumption as to their
// relative values.
// D is calculated per ANS 9.31 / FIPS 186 rules.
CC_NONNULL_ALL CC_WARN_RESULT
static int ccrsa_crt_make_fips186_key_ws(cc_ws_t ws,
                                         size_t nbits,
                                         ccrsa_full_ctx_t fk,
                                         cc_size ne,
                                         const cc_unit *e,
                                         const cc_unit *p,
                                         const cc_unit *q)
{
    int status = CCRSA_INVALID_INPUT;
    cc_size n = ccrsa_ctx_n(fk);
    cc_size n_pq = n / 2 + 1;
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);

    if (ccn_bitlen(n_pq, p) + ccn_bitlen(n_pq, q) > ccn_bitsof_n(n)) {
        return CCRSA_INVALID_INPUT;
    }

    CC_DECL_BP_WS(ws, bp);

    ccn_setn(n, ccrsa_ctx_e(pubk), ne, e);

    // Swap p and q, if necessary.
    if (ccn_cmp(n_pq, p, q) < 0) {
        const cc_unit *t = p;
        p = q;
        q = t;
    }

    // Initialize zp before zq, otherwise ccrsa_ctx_private_zq()
    // won't point to the right place in memory.
    CCZP_N(ccrsa_ctx_private_zp(fk)) = n_pq;
    CCZP_N(ccrsa_ctx_private_zq(fk)) = n_pq;

    cczp_t zm = ccrsa_ctx_zm(pubk);
    cczp_t zp = ccrsa_ctx_private_zp(fk);
    cczp_t zq = ccrsa_ctx_private_zq(fk);

    ccn_set(n_pq, CCZP_PRIME(zp), p);
    ccn_set(n_pq, CCZP_PRIME(zq), q);

    status = cczp_init_ws(ws, zp);
    cc_require(status == CCERR_OK, errOut);

    status = cczp_init_ws(ws, zq);
    cc_require(status == CCERR_OK, errOut);

    status = ccrsa_crt_makekey_ws(ws, fk);
    cc_require(status == CCERR_OK, errOut);

    if (cczp_bitlen(zm) + 1 < nbits) {
        status = CCRSA_INVALID_INPUT;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

// This is pretty much the same interface as the "stock" RSA keygen except that
// two rng descriptors need to be provided.  You *can* call it with the same
// descriptor if you really want to.
// rng is used for the prime factors, rng_mr for Miller-Rabin.
CC_NONNULL((1, 3, 4, 6, 7, 8)) CC_WARN_RESULT
static int ccrsa_generate_fips186_prime_factors_ws(cc_ws_t ws,
                                                   size_t nbits,
                                                   cc_unit *p,
                                                   cc_unit *q,
                                                   cc_size ne,
                                                   const cc_unit *e,
                                                   struct ccrng_state *rng,
                                                   struct ccrng_state *rng_mr,
                                                   struct ccrsa_fips186_trace *trace)
{
    if (nbits < 512) {
        return CCRSA_KEY_ERROR;
    }

    cc_size pbits = (nbits + 1) >> 1, qbits = nbits - pbits;

    // Sanity check for the computations above.
    if (pbits != ((nbits + 1) >> 1) || (qbits + pbits) != nbits) {
        return CCRSA_KEY_ERROR;
    }

    cc_size alpha = ccrsa_fips186_auxiliary_prime_nbits(pbits);
    size_t ebitlen = ccn_bitlen(ne, e);

    // Space to generate P and Q
    cc_size n = ccn_nof(nbits);
    cc_size n_pq = n / 2 + 1;

    CC_DECL_BP_WS(ws, bp);

    // Auxiliary-Primes space to generate P & Q
    cc_unit *xp = CC_ALLOC_WS(ws, n / 2 + 1 /* n_pq */);
    cc_unit *xq = CC_ALLOC_WS(ws, n / 2 + 1 /* n_pq */);

    int ret = CCRSA_KEY_ERROR;
    // e must be odd && e must verify 2^16 < e < 2^256
    cc_require((e[0] & 1) && (ebitlen > 16) && (ebitlen < 256), errOut);

    // Generate P
    if (trace) {
        cc_clear(2 * sizeof(trace[0]), trace);
        trace[0].curr = trace[1].curr = 0;
    }

    ret = ccrsa_generate_probable_prime_ws(ws, pbits, p, xp, alpha, alpha, ne, e, rng, rng_mr, trace);
    cc_require(ret == CCERR_OK, errOut);

    // Now, do the same for q. But repeat until q,p and Xp, Xq are
    // sufficiently far apart, and d is sufficiently large
    ret = CCRSA_KEYGEN_PQ_DELTA_ERROR;
    for (size_t i = 0; i < GENERATE_Q_MAX_RETRIES && ret == CCRSA_KEYGEN_PQ_DELTA_ERROR; i++) {
        // Generate Q - we're going to check for a large enough delta in various steps of this.
        if (trace) {
            trace[0].curr = trace[1].curr = 1;
        }

        ret = ccrsa_generate_probable_prime_ws(ws, qbits, q, xq, alpha, alpha, ne, e, rng, rng_mr, trace);
        cc_require(ret == CCERR_OK, errOut);

        // If (|p-q|<= 2^(plen-100)) or If (|Xp-Xq|<= 2^(plen-100)) retry
        // (Make sure the seed P and Q were far enough apart)
        ret = ccrsa_check_delta_100bits_ws(ws, n_pq, p, q, xp, xq);
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return ret;
}

//==============================================================================
//                              External functions
//==============================================================================

CC_NONNULL((1, 3, 5, 6, 7)) CC_WARN_RESULT
static int ccrsa_generate_fips186_key_trace_ws(cc_ws_t ws,
                                               size_t nbits,
                                               ccrsa_full_ctx_t fk,
                                               size_t e_nbytes,
                                               const void *e_bytes,
                                               struct ccrng_state *rng,
                                               struct ccrng_state *rng_mr,
                                               struct ccrsa_fips186_trace *trace)
{
    // Key generation takes a lot of stack space, check the key size.
    if (nbits > CCRSA_KEYGEN_MAX_NBITS) {
        return CCRSA_INVALID_INPUT;
    }

    int ret;
    cc_size n = ccn_nof(nbits);
    cc_size n_pq = n / 2 + 1;
    ccrsa_ctx_n(fk) = n;
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);

    // Use the RSA key area to hold e as a ccn_unit.  Get 'ne' so we don't
    // need to roll on the full ccn_unit if we don't have to.
    if (ccn_read_uint(n, ccrsa_ctx_e(pubk), e_nbytes, e_bytes)) {
        return CCRSA_KEY_ERROR;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *p = CC_ALLOC_WS(ws, n / 2 + 1 /* n_pq */);
    cc_unit *q = CC_ALLOC_WS(ws, n / 2 + 1 /* n_pq */);

    cc_size ne = ccn_nof_size(e_nbytes);
    const cc_unit *d = ccrsa_ctx_d(fk);
    cc_unit *e = ccrsa_ctx_e(pubk);

    size_t pbits = (nbits + 1) >> 1;
    cc_assert(ccn_bitsof_n(n_pq) > pbits);

    // dlb := 2^pbits (lower bound for d)
    cc_unit *dlb = CC_ALLOC_WS(ws, n / 2 + 1 /* n_pq */);
    ccn_clear(n_pq, dlb);
    ccn_set_bit(dlb, pbits, 1);

    do {
        // Generate prime factors.
        ret = ccrsa_generate_fips186_prime_factors_ws(ws, nbits, p, q, ne, e, rng, rng_mr, trace);
        cc_require(ret == CCERR_OK, errOut);

        // Compute m,d and CRT components.
        ret = ccrsa_crt_make_fips186_key_ws(ws, nbits, fk, ne, e, p, q);
        cc_require(ret == CCERR_OK, errOut);

        // If d <= 2^pbits, try again.
    } while (ccn_cmpn(n, d, n_pq, dlb) < 1);

    // Check that the key works
    if (ccrsa_pairwise_consistency_check_ws(ws, fk, rng)) {
        ret = CCRSA_KEYGEN_KEYGEN_CONSISTENCY_FAIL;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return ret;
}

CC_NONNULL_ALL CC_WARN_RESULT
int ccrsa_make_fips186_key_ws(cc_ws_t ws,
                              size_t nbits,
                              cc_size ne,
                              const cc_unit *e,
                              cc_size xp1Len,
                              const cc_unit *xp1,
                              cc_size xp2Len,
                              const cc_unit *xp2,
                              cc_size xpLen,
                              const cc_unit *xp,
                              cc_size xq1Len,
                              const cc_unit *xq1,
                              cc_size xq2Len,
                              const cc_unit *xq2,
                              cc_size xqLen,
                              const cc_unit *xq,
                              ccrsa_full_ctx_t fk,
                              cc_size *np,
                              cc_unit *r_p,
                              cc_size *nq,
                              cc_unit *r_q,
                              cc_size *nm,
                              cc_unit *r_m,
                              cc_size *nd,
                              cc_unit *r_d)
{
    // key generation takes a lot of stack space
    // therefore sanity check the key size
    if (nbits > CCRSA_KEYGEN_MAX_NBITS) {
        return CCRSA_INVALID_INPUT;
    }

    cc_size pqbits = (nbits >> 1);
    cc_size n = ccn_nof(nbits);
    cc_size n_pq = n / 2 + 1;
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *p = CC_ALLOC_WS(ws, n / 2 + 1 /* n_pq */);
    cc_unit *q = CC_ALLOC_WS(ws, n / 2 + 1 /* n_pq */);

    struct ccrng_rsafips_test_state rng;
    cc_size x1_bitsize;
    cc_size x2_bitsize;

    ccrsa_ctx_n(fk) = n;

    cc_unit *xpp = CC_ALLOC_WS(ws, n / 2 + 1 /* n_pq */);
    cc_unit *xqq = CC_ALLOC_WS(ws, n / 2 + 1 /* n_pq */);

    int ret;
    struct ccrng_state *rng_mr = ccrng(&ret);
    cc_require(rng_mr != NULL, errOut);

    // e must be > 2 and odd.
    cc_require_action((e[0] & 1) && ccn_bitlen(ne, e) > 1, errOut, ret = CCRSA_KEY_ERROR);

    // Generate P
    ccrng_rsafips_test_init(&rng,xp1Len,xp1,xp2Len,xp2,xpLen,xp);
    x1_bitsize = ccn_bitlen(xp1Len, xp1);
    x2_bitsize = ccn_bitlen(xp2Len, xp2);
    ret = ccrsa_generate_probable_prime_ws(ws, pqbits, p, xpp, x1_bitsize, x2_bitsize, ne, e, (struct ccrng_state *)&rng, rng_mr, NULL);
    cc_require(ret == CCERR_OK, errOut);

    // Generate Q
    ccrng_rsafips_test_init(&rng,xq1Len,xq1,xq2Len,xq2,xqLen,xq);
    x1_bitsize = ccn_bitlen(xq1Len, xq1);
    x2_bitsize = ccn_bitlen(xq2Len, xq2);
    ret = ccrsa_generate_probable_prime_ws(ws, pqbits, q, xqq, x1_bitsize, x2_bitsize, ne, e, (struct ccrng_state *)&rng, rng_mr, NULL);
    cc_require(ret == CCERR_OK, errOut);

    // Check delta between P and Q, XP, XQ
    ret = ccrsa_check_delta_100bits_ws(ws, n_pq, p, q, xpp, xqq);
    cc_require(ret == CCERR_OK, errOut);

    // Return P&Q now since we might've assigned them in reverse in the CRT routine.
    *np = n_pq;
    ccn_set(*np, r_p, p);
    *nq = n_pq;
    ccn_set(*nq, r_q, q);

    // Construct the key from p and q
    ret = ccrsa_crt_make_fips186_key_ws(ws, nbits, fk, ne, e, p, q);
    cc_require(ret == CCERR_OK, errOut);

    // Return m and d.
    *nm = cczp_n(ccrsa_ctx_zm(pubk));
    ccn_set(*nm, r_m, cczp_prime(ccrsa_ctx_zm(pubk)));
    *nd = cczp_n(ccrsa_ctx_zm(pubk));
    ccn_set(*nd, r_d, ccrsa_ctx_d(fk));

errOut:
    CC_FREE_BP_WS(ws, bp);
    return ret;
}
#endif // CC_DISABLE_RSAKEYGEN

CC_NONNULL((2, 4, 5, 6))
int ccrsa_generate_fips186_key_trace(size_t nbits,
                                     ccrsa_full_ctx_t fk,
                                     size_t e_nbytes,
                                     const void *e_bytes,
                                     struct ccrng_state *rng,
                                     struct ccrng_state *rng_mr,
                                     struct ccrsa_fips186_trace *trace)
{
#if CC_DISABLE_RSAKEYGEN
    (void)nbits;    (void)fk;
    (void)e_nbytes; (void)e_bytes;
    (void)rng;      (void)rng_mr;
    (void)trace;
    return CCRSA_FIPS_KEYGEN_DISABLED;
#else
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_GENERATE_FIPS186_KEY_TRACE_WORKSPACE_N(ccn_nof(nbits)));
    int rv = ccrsa_generate_fips186_key_trace_ws(ws, nbits, fk, e_nbytes, e_bytes, rng, rng_mr, trace);
    CC_FREE_WORKSPACE(ws);
    return rv;
#endif
}

int ccrsa_generate_fips186_key(size_t nbits,
                               ccrsa_full_ctx_t fk,
                               size_t e_nbytes,
                               const void *e_bytes,
                               struct ccrng_state *rng,
                               struct ccrng_state *rng_mr)
{
    CC_ENSURE_DIT_ENABLED

    int rv = ccrsa_generate_fips186_key_trace(nbits, fk, e_nbytes, e_bytes, rng, rng_mr, NULL);
    cc_try_abort_if(rv == CCRSA_KEYGEN_KEYGEN_CONSISTENCY_FAIL, "ccrsa_generate_fips186_key consistency");

    return rv;
}
