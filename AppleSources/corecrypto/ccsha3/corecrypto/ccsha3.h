/* Copyright (c) (2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSHA3_H_
#define _CORECRYPTO_CCSHA3_H_

#include <corecrypto/ccdigest.h>

// SHA3-224
#define CCSHA3_224_BLOCK_NBYTES 144
#define CCSHA3_224_OUTPUT_NBYTES 28
const struct ccdigest_info *ccsha3_224_di(void);

// SHA3-256
#define CCSHA3_256_BLOCK_NBYTES  136
#define CCSHA3_256_OUTPUT_NBYTES 32
const struct ccdigest_info *ccsha3_256_di(void);

// SHA3-384
#define CCSHA3_384_BLOCK_NBYTES  104
#define CCSHA3_384_OUTPUT_NBYTES 48
const struct ccdigest_info *ccsha3_384_di(void);

// SHA3-512
#define CCSHA3_512_BLOCK_NBYTES  72
#define CCSHA3_512_OUTPUT_NBYTES 64
const struct ccdigest_info *ccsha3_512_di(void);

#endif /* _CORECRYPTO_CCSHA3_H_ */
