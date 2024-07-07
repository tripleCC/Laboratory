/* Copyright (c) (2011,2014,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_TEST_H_
#define _CORECRYPTO_CCRNG_TEST_H_

#include <corecrypto/ccrng.h>
#include <corecrypto/ccdrbg.h>

struct ccrng_test_state {
    CCRNG_STATE_COMMON

    struct ccdrbg_info drbg_info;
    struct ccdrbg_state *drbg_state;
};

int ccrng_test_init(struct ccrng_test_state *rng, size_t length, const void *seed,
                    const char *personalization_string);

void ccrng_test_done(struct ccrng_test_state *rng);

#endif /* _CORECRYPTO_CCRNG_TEST_H_ */
