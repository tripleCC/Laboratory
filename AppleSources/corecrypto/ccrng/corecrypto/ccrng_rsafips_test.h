/* Copyright (c) (2014,2015,2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_RSAFIPS_TEST_H_
#define _CORECRYPTO_CCRNG_RSAFIPS_TEST_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>

struct ccrng_rsafips_test_state {
    CCRNG_STATE_COMMON
    uint8_t *state;
    cc_size index;
    struct ccrng_rsafips_test_state *next;
    cc_size r1Len;
    const cc_unit *r1;
    cc_size r2Len;
    const cc_unit *r2;
    cc_size XLen;
    const cc_unit *X;
};

int
ccrng_rsafips_test_init(struct ccrng_rsafips_test_state *rng,
                      const cc_size r1Len, const cc_unit *r1,
                      const cc_size r2Len, const cc_unit *r2,
                      const cc_size XLen,  const cc_unit *X);

void
ccrng_rsafips_test_set_next(struct ccrng_rsafips_test_state *rng,
                            struct ccrng_rsafips_test_state *next);

#endif /* _CORECRYPTO_CCRNG_RSAFIPS_TEST_H_ */
