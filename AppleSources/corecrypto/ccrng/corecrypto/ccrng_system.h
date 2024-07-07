/* Copyright (c) (2010,2013,2014,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_SYSTEM_H_
#define _CORECRYPTO_CCRNG_SYSTEM_H_

#include <corecrypto/ccrng.h>

struct ccrng_system_state {
    CCRNG_STATE_COMMON
    int fd;
};

/*!
 @function   ccrng_system_init - DEPRECATED
 @abstract   Default ccrng.
    Please transition to ccrng() which is easier to use and with provide the fastest, most secure option

 @param  rng   Structure containing the state of the RNG, must remain allocated as
 long as the rng is used.
 @result 0 iff successful

 @discussion
        This RNG require call to "init" AND "done", otherwise it may leak a file descriptor.
 */

// Initialize ccrng
// Deprecated, if you need a rng, just call the function ccrng()
int ccrng_system_init(struct ccrng_system_state *rng)
cc_deprecate_with_replacement("ccrng", 13.0, 10.15, 13.0, 6.0, 4.0);

// Close the system RNG
// Mandatory step to avoid leaking file descriptor
void ccrng_system_done(struct ccrng_system_state *rng)
cc_deprecate_with_replacement("ccrng", 13.0, 10.15, 13.0, 6.0, 4.0);

#endif /* _CORECRYPTO_CCRNG_SYSTEM_H_ */
