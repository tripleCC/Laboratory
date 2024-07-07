/* Copyright (c) (2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCLR_INTERNAL_H_
#define _CORECRYPTO_CCLR_INTERNAL_H_

#include "cc_internal.h"
#include "cclr.h"

#define CCLR_MAX_PRF_NBYTES (CCAES_BLOCK_SIZE)
#define CCLR_MAX_BLOCK_NBITS (CCAES_BLOCK_SIZE * 8)
#define CCLR_MAX_BLOCK_NBYTES ((CCLR_MAX_BLOCK_NBITS + 7) / 8)
#define CCLR_MAX_HALF_BLOCK_NBYTES ((CCLR_MAX_BLOCK_NBYTES + 1) / 2)

#define CCLR_MIN_NROUNDS (4)
#define CCLR_MAX_NROUNDS (10)

struct cclr_info {
    int (*prf_eval)(const cclr_ctx_t *ctx,
                    void *out,
                    const void *in);
};

#endif // _CORECRYPTO_CCLR_INTERNAL_H_
