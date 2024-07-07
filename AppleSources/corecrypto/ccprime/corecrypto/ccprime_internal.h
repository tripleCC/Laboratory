/* Copyright (c) (2017-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCPRIME_INTERNAL_H_
#define _CORECRYPTO_CCPRIME_INTERNAL_H_

#include "ccn_internal.h"
#include "cczp_internal.h"

// A Miller-Rabin context storing p-1 = 2^s*d and the Montgomery zp.
typedef cczp_t ccprime_mr_t;

#define ccprime_mr_nof_n(_n_) (cczp_nof_n(_n_) + 2 * (_n_) + 1)

#define ccprime_mr_zp(_mr_) (_mr_)
#define ccprime_mr_s(_mr_) (((cc_unit *)(_mr_)) + cczp_nof_n((_mr_)->n))
#define ccprime_mr_d(_mr_) (ccprime_mr_s(_mr_) + 1)
#define ccprime_mr_pm1(_mr_) (ccprime_mr_d(_mr_) + (_mr_)->n)

#define ccprime_mr_decl_n(_n_, _name_) \
    cc_ctx_decl(struct cczp, ccn_sizeof_n(ccprime_mr_nof_n(_n_)), _name_)

/*! @function ccprime_rabin_miller_init_ws
 @abstract Initializes a given Miller-Rabin context.

 @param ws  Workspace.
 @param mr  Miller-Rabin context.
 @param n   Length of candidate p in units
 @param p   Prime candidate p.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int ccprime_rabin_miller_init_ws(cc_ws_t ws, ccprime_mr_t mr, cc_size n, const cc_unit *p);

/*! @function ccprime_rabin_miller_iteration_ws
 @abstract Initializes a given Miller-Rabin context.

 @param ws    Workspace.
 @param mr    Miller-Rabin context.
 @param base  Base, possible composite witness.
 @param rng   RNG for blinded exponentiation.

 @return  1 iff base is NOT a composite witness.
          0 iff base is a composite witness (and p not a prime).
          Negative value on failure. See cc_error.h for more details.

 */
CC_NONNULL_ALL
int ccprime_rabin_miller_iteration_ws(cc_ws_t ws, ccprime_mr_t mr, const cc_unit *base, struct ccrng_state *rng);

/*! @function ccprime_rabin_miller
 @abstract Performs a Miller-Rabin primality test on p.

 @discussion  Use only for random prime generation.

              This primality test checks _random_ prime candidates and should
              be used for prime generation only. Rejecting a valid prime with
              negligible probability is fine as long as the caller retries with
              a different prime candidate.

              The run time is dependent on the length n of the prime candidate
              p, but not on the actual value of p. For different prime candidates
              with the same length argument, this test will always take the same
              amount of time to finish. Only composites are reported as early
              as possible -- i.e. in variable time.

              mr_depth specifies the number of MR iterations and thus the
              probability of not detecting a composite. For n=mr_depth a
              composite might pass as prime with probability 2^(-2n).

 @param n         Length of candidate p in units
 @param p         Prime candidate p.
 @param mr_depth  Number of Miller-Rabin iterations.
 @param rng       RNG for random base selection.

 @return  1 if p is _probably_ a prime.
          0 if p is _definitely_ a composite.
          Negative value on failure. See cc_error.h for more details.

 */
CC_NONNULL_ALL
int ccprime_rabin_miller(cc_size n, const cc_unit *p, size_t mr_depth, struct ccrng_state *rng);

CC_NONNULL_ALL
int ccprime_rabin_miller_ws(cc_ws_t ws, cc_size n, const cc_unit *p, size_t mr_depth, struct ccrng_state *rng);

#endif // _CORECRYPTO_CCPRIME_INTERNAL_H_
