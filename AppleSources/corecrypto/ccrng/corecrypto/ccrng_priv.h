/* Copyright (c) (2016-2018,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_PRIV_H_
#define _CORECRYPTO_CCRNG_PRIV_H_

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng.h>

/*!
 @function ccrng_trng
 @abstract Get a handle to a hardware-based TRNG, if available

 @param error A pointer to set in case of error; may be null

 @result A handle to a TRNG, if available, or null otherwise

 @discussion
 Typical clients should prefer to call the more general ccrng()
 function. Not all platforms and configurations have access to a TRNG.
 */
struct ccrng_state *ccrng_trng(int *error);

/*!
 @function ccrng_prng
 @abstract Get a handle to a software-based PRNG

 @param error A pointer to set in case of error; may be null

 @result A handle to a PRNG, or null if one cannot be initialized successfully

 @discussion
 Typical clients should prefer to call the more general ccrng()
 function.
 */
struct ccrng_state *ccrng_prng(int *error);

#endif /* _CORECRYPTO_CCRNG_PRIV_H_ */
