/* Copyright (c) (2014,2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

// To be used to set the scalar to a known fix value
// May fail if value is not as expect.

#ifndef _CORECRYPTO_CCRNG_ECFIPS_TEST_H_
#define _CORECRYPTO_CCRNG_ECFIPS_TEST_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>

struct ccrng_ecfips_test_state {
    CCRNG_STATE_COMMON
    uint8_t *state;
    size_t len;
};

int ccrng_ecfips_test_init(struct ccrng_ecfips_test_state *rng,
                           size_t len, uint8_t *sequence);

#endif /* _CORECRYPTO_CCRNG_ECFIPS_TEST_H_ */
