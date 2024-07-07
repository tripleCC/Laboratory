/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_ZERO_H_
#define _CORECRYPTO_CCRNG_ZERO_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>

// This is a ccrng instance that generates an infinite sequence of
// zeros. It has no security value and is to be used for internal test
// cases only.
extern struct ccrng_state ccrng_zero;

#endif /* _CORECRYPTO_CCRNG_ZERO_H_ */
