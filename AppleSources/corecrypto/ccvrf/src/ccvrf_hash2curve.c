/* Copyright (c) (2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccvrf_internal.h"

void
ccvrf_irtf_ed25519_hash2curve_elligator2(const struct ccdigest_info *di, const ge_p3 *Y, const uint8_t *alpha,
                                 const size_t alphalen, uint8_t *H_string)
{
    cc_assert(di->output_size == 64);

    uint8_t PK_string[CCVRF_IRTF_ED25519_ENCODEDPOINT_LEN];
    uint8_t truncated_h_string[MAX_DIGEST_OUTPUT_SIZE];

    uint8_t suite = CCVRF_IRTF_ED25519_SUITE;
    uint8_t one = CCVRF_IRTF_ED25519_ONE;
    ccvrf_irtf_ed25519_point_to_string(PK_string, Y);

    // Compute Hash(suite_string || one_string || PK_string || alpha_string )
    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);
    ccdigest_update(di, ctx, sizeof(suite), &suite);
    ccdigest_update(di, ctx, sizeof(one), &one);
    ccdigest_update(di, ctx, sizeof(PK_string), PK_string);
    ccdigest_update(di, ctx, alphalen, alpha);
    ccdigest_final(di, ctx, truncated_h_string);

    // Clear sign bit from the first 32 bytes, and then run the resulting element through elligator2.
    truncated_h_string[31] &= 0x7f;
    ge_from_uniform(H_string, truncated_h_string);
}
