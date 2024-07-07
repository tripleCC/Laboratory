/* Copyright (c) (2011,2012,2015,2017-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCZ_PRIV_H_
#define _CORECRYPTO_CCZ_PRIV_H_

#include <corecrypto/ccz.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

#ifndef CCZ_PREC
#define CCZ_PREC                 32     /* default units of precision */
#endif

/* Error codes. */
enum {
    CCZ_OK = 0,
    CCZ_MEM,
};

CC_NONNULL_ALL
int ccz_sign(const ccz *s);

CC_NONNULL_ALL
cc_size ccz_n(const ccz *s);

CC_NONNULL_ALL
cc_size ccz_capacity(const ccz *s);

#if CC_PTRCHECK
// Not currently available when bounds attributes are enabled.

cc_unavailable()
void ccz_set_sign(ccz *r, int sign);

cc_unavailable()
void ccz_set_n(ccz *r, cc_size n);

cc_unavailable()
void ccz_set_capacity(ccz *r, cc_size capacity);

#else
CC_NONNULL((1))
void ccz_set_sign(ccz *r, int sign);

CC_NONNULL((1))
void ccz_set_n(ccz *r, cc_size n);

CC_NONNULL((1))
void ccz_set_capacity(ccz *r, cc_size capacity);
#endif /* !CC_PTRCHECK */

#endif /* _CORECRYPTO_CCZ_PRIV_H_ */
