/* Copyright (c) (2014-2016,2018-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include <corecrypto/ccansikdf.h>
#include <corecrypto/ccsha2.h>
#include "ccansikdf_internal.h"
#include <corecrypto/ccdigest_priv.h>
#include "cc_debug.h"

int ccansikdf_x963(const struct ccdigest_info *di,
                   const size_t Z_nbytes,
                   const unsigned char *Z,
                   const size_t sharedinfo_nbytes,
                   const void *sharedinfo,
                   const size_t key_nbytes,
                   uint8_t *key)
{
    CC_ENSURE_DIT_ENABLED

    const cc_iovec_t shared_data[1] = {
        {
            .base = sharedinfo,
            .nbytes = sharedinfo_nbytes,
        },
    };

    return ccansikdf_x963_iovec(di, Z_nbytes, Z, 1, shared_data, key_nbytes, key);
}

static void ccansikdf_x963_round(const struct ccdigest_info *di,
                                 struct ccdigest_ctx *working_ctx,
                                 const struct ccdigest_ctx *start_ctx,
                                 size_t index,
                                 size_t sharedinfo_count,
                                 const cc_iovec_t *cc_counted_by(sharedinfo_count) sharedinfo_inputs,
                                 uint8_t *out)
{
    uint8_t counter[4];
    cc_memcpy(working_ctx, start_ctx, ccdigest_di_size(di));

    CC_STORE32_BE(index, counter);
    ccdigest_update(di, working_ctx, sizeof(counter), counter);

    for (size_t j = 0; j < sharedinfo_count; j++) {
        ccdigest_update(di, working_ctx, sharedinfo_inputs[j].nbytes, sharedinfo_inputs[j].base);
    }
    ccdigest_final(di, working_ctx, out);
}

int ccansikdf_x963_iovec(const struct ccdigest_info *di,
                         const size_t Z_nbytes,
                         const unsigned char *cc_counted_by(Z_len) Z,
                         size_t sharedinfo_count,
                         const cc_iovec_t *cc_counted_by(sharedinfo_count) sharedinfo_inputs,
                         const size_t key_nbytes,
                         uint8_t *cc_counted_by(key_len) key)
{
    uint8_t finaldigest[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t *out = key;

    size_t r = cc_ceiling(key_nbytes, di->output_size);
    if (r >= UINT32_MAX) {
        return CCERR_PARAMETER;
    }

    ccdigest_di_decl(di, Z_ctx);
    ccdigest_init(di, Z_ctx);
    ccdigest_update(di, Z_ctx, Z_nbytes, Z);

    ccdigest_di_decl(di, ctx);

    for (size_t i = 1; i < r; i++) {
        ccansikdf_x963_round(di, ctx, Z_ctx, i, sharedinfo_count, sharedinfo_inputs, out);
        out += di->output_size;
    }

    // Final round may not be the full hash size
    ccansikdf_x963_round(di, ctx, Z_ctx, r, sharedinfo_count, sharedinfo_inputs, finaldigest);
    cc_memcpy(out, finaldigest, key_nbytes - ((r - 1) * di->output_size));

    ccdigest_di_clear(di, ctx);
    ccdigest_di_clear(di, Z_ctx);
    return CCERR_OK;
}
