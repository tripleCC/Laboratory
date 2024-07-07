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

#ifndef _CORECRYPTO_CCRNG_RDRAND_H_
#define _CORECRYPTO_CCRNG_RDRAND_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>

// This is a ccrng wrapper for Intel's RDRAND instruction, which is a
// simple interface to a hardware DRNG. See Intel's documentation for
// more information.
//
// This instance is not intended for direct use by clients external to
// corecrypto. Instead, see ccrng().
//
// This RNG instance will return CCERR_NOT_SUPPORTED on platforms that
// do not support RDRAND. This includes all ARM processors and older
// Intel processors. (At this time, Apple does not support any Intel
// processors that do not implement RDRAND.)
//
// Note that this instance handles any necessary "chunking" of
// requests. It also transparently retries in case of ephemeral RDRAND
// failures; this is as recommended by Intel.
extern struct ccrng_state ccrng_rdrand;

#endif /* _CORECRYPTO_CCRNG_RDRAND_H_ */
