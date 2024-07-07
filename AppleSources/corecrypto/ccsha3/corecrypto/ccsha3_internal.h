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

#ifndef _CORECRYPTO_CCSHA3_INTERNAL_H_
#define _CORECRYPTO_CCSHA3_INTERNAL_H_

#include <corecrypto/ccsha3.h>
#include "cckeccak_internal.h"

extern const uint64_t ccsha3_keccak_p1600_initial_state[CCKECCAK_STATE_NUINT64];

#define CCSHA3_STATE_NBYTES (CCKECCAK_STATE_NUINT64 * sizeof(uint64_t))
#define CCSHA3_OID_LEN 11

#define CCSHA3_224_RATE CCSHA3_224_BLOCK_NBYTES
#define CCSHA3_256_RATE CCSHA3_256_BLOCK_NBYTES
#define CCSHA3_384_RATE CCSHA3_384_BLOCK_NBYTES
#define CCSHA3_512_RATE CCSHA3_512_BLOCK_NBYTES

extern const struct ccdigest_info ccsha3_224_c_di;
extern const struct ccdigest_info ccsha3_256_c_di;
extern const struct ccdigest_info ccsha3_384_c_di;
extern const struct ccdigest_info ccsha3_512_c_di;

void ccsha3_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, uint8_t *digest, cckeccak_permutation permutation);

#endif /* _CORECRYPTO_CCSHA3_INTERNAL_H_ */
