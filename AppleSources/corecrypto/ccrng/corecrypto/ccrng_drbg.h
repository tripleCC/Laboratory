/* Copyright (c) (2014-2016,2018,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_ccrng_drbg_h
#define corecrypto_ccrng_drbg_h

#include <corecrypto/ccrng.h>
#include <corecrypto/ccdrbg.h>

struct ccrng_drbg_state {
    CCRNG_STATE_COMMON
    const struct ccdrbg_info *drbg_info;
    struct ccdrbg_state *drbg_state;
};

// Setup a RNG based on a DRBG.
//   Init calls the init from the DRBG
cc_deprecate_with_replacement("ccrng_drbg_init_withdrbg", 13.0, 10.15, 13.0, 6.0, 4.0)
int ccrng_drbg_init(struct ccrng_drbg_state *rng,
                    const struct ccdrbg_info *drbg_info,
                    struct ccdrbg_state *drbg_state,
                    size_t length, const void *seed);

// Reseed underlying DRBG
cc_deprecate_with_replacement("ccrng_drbg_init_withdrbg", 13.0, 10.15, 13.0, 6.0, 4.0)
int ccrng_drbg_reseed(struct ccrng_drbg_state *rng,
                      size_t entropylen, const void *entropy,
                      size_t inlen, const void *in);

// Clear the DRBG
cc_deprecate_with_replacement("ccrng_drbg_init_withdrbg", 13.0, 10.15, 13.0, 6.0, 4.0)
void ccrng_drbg_done(struct ccrng_drbg_state *rng);

/*!
  @function ccrng_drbg_init_withdrbg
  @abstract Wrap a ccdrbg instance in the ccrng interface

  @param rng An instance of ccrng_drbg_state to be initialized
  @param drbg_info The DRBG configuration
  @param drbg_state The DRBG instance

  @result Zero iff successful, nonzero otherwise.

  @discussion The user must retain a reference to the DRBG instance
  and manage it normally. The user must initialize the DRBG before
  calling ccrng_drbg_init. When passing a ccrng_drbg instance to a
  corecrypto function, the user should check for the
  CCDRBG_STATUS_NEED_RESEED return code and reseed and retry as
  necessary.
*/

int ccrng_drbg_init_withdrbg(struct ccrng_drbg_state *rng,
                             const struct ccdrbg_info *drbg_info,
                             struct ccdrbg_state *drbg_state);

#endif
