/* Copyright (c) (2016,2017,2018,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_INTERNAL_H_
#define _CORECRYPTO_CCRNG_INTERNAL_H_

#include <corecrypto/ccrng.h>
#include "cc_internal.h"

int cc_get_entropy(size_t entropy_size, void *entropy);

#define CCRNG_FIPS_REQUEST_SIZE_THRESHOLD (12)

// Do not call this directly. See the macro ccrng_generate_fips below.
CC_INLINE
int ccrng_generate_fips_internal(struct ccrng_state *rng, size_t nbytes, void *out)
{
    int status;
    uint8_t buf[CCRNG_FIPS_REQUEST_SIZE_THRESHOLD];

    if (nbytes < CCRNG_FIPS_REQUEST_SIZE_THRESHOLD) {
        // Request additional output to meet the threshold. See
        // ccrng_crypto.c for more details.
        status = ccrng_generate(rng, sizeof(buf), buf);
        cc_memcpy(out, buf, nbytes);
        cc_clear(nbytes, buf);
    } else {
        status = ccrng_generate(rng, nbytes, out);
    }

    return status;
}

/*!
  @function   ccrng_generate_fips
  @abstract   Generate `outlen` bytes of output, stored in `out`, using ccrng_state `rng`.

  @param rng  `struct ccrng_state` representing the state of the RNG.
  @param nbytes  Amount of random bytes to generate.
  @param out  Pointer to memory where random bytes are stored, of size at least `outlen`.

  @result 0 on success and nonzero on failure.

  @discussion If the request size is below the threshold, tries to abort.
*/
#define ccrng_generate_fips(rng, nbytes, out)                           \
    ccrng_generate_fips_internal((struct ccrng_state *)rng, nbytes, out)

#endif /* _CORECRYPTO_CCRNG_INTERNAL_H_ */
