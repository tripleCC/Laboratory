/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_GETENTROPY_H_
#define _CORECRYPTO_CCRNG_GETENTROPY_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>

// This is a ccrng wrapper for the getentropy(2) system call. (See its
// man page for further details.)
//
// getentropy(2) is a simple interface to the kernel RNG. While the
// kernel RNG does reseed frequently, it cannot provide full-entropy
// outputs exceeding the security level of the underlying
// deterministic generator. It also cannot guarantee prediction
// resistance across successive requests.
//
// We mitigate these issues in corecrypto by polling getentropy(2)
// frequently for fresh entropy as the kernel RNG reseeds itself.
//
// This instance is not intended for clients external to
// corecrypto. Instead, see ccrng().
//
// This RNG instance will abort on failure (which should never
// happen).
//
// Note that this instance handles any necessary "chunking" of
// requests, i.e. the maximum request size of getentropy(2) is not
// enforced.
extern struct ccrng_state ccrng_getentropy;

// We assume that all iOS-derivated trains have the random syscall, this will not build before iOS 10.
#if (CC_DARWIN && !CC_KERNEL)
#define CC_GETENTROPY_SUPPORTED 1
#else
#define CC_GETENTROPY_SUPPORTED 0
#endif

#endif /* _CORECRYPTO_CCRNG_GETENTROPY_H_ */
