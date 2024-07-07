/* Copyright (c) (2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <limits.h>
#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>
#include <corecrypto/ccrng.h>
#include "testmore.h"

// almost equivalent of c rand() stdlib function
unsigned int cc_rand(unsigned max)
{
    struct ccrng_state *rng = global_test_rng;
    unsigned int result;
    int rng_status;
    unsigned int r;
    rng_status=ccrng_generate(rng, sizeof(r),&r);
    cc_assert(rng_status==0);
    (void)rng_status;
    result=(unsigned int)(((double)r/UINT_MAX)*max);
    cc_assert(result<=max);
    return result;
}


cc_unit cc_rand_unit(void)
{
    struct ccrng_state *rng = global_test_rng;
    cc_unit r;
    ccrng_generate(rng, sizeof(r), &r);
    return r;
}
