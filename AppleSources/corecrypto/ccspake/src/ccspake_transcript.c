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

#include "cc_internal.h"
#include "ccspake_internal.h"

void ccspake_transcript_init(ccspake_ctx_t ctx)
{
    ccdigest_init(ccspake_ctx_mac(ctx)->di(), ccspake_ctx_hash(ctx));
}

/*! @function ccspake_transcript_append_length
 @abstract Hash `length` as a 64-byte little-endian integer.

 @param ctx     SPAKE2+ context
 @param length  Length to hash
 */
CC_NONNULL_ALL
static void ccspake_transcript_append_length(ccspake_ctx_t ctx, uint64_t length)
{
    uint8_t le_length[8];
    CC_STORE64_LE(length, le_length);
    ccdigest_update(ccspake_ctx_mac(ctx)->di(), ccspake_ctx_hash(ctx), sizeof(le_length), le_length);
}

void ccspake_transcript_append(ccspake_ctx_t ctx, size_t nbytes, const uint8_t *data)
{
    ccspake_transcript_append_length(ctx, nbytes);

    if (nbytes > 0) {
        ccdigest_update(ccspake_ctx_mac(ctx)->di(), ccspake_ctx_hash(ctx), nbytes, data);
    }
}

void ccspake_transcript_begin(ccspake_ctx_t ctx,
                              size_t context_nbytes,
                              const uint8_t *context,
                              size_t id_prover_nbytes,
                              const uint8_t *id_prover,
                              size_t id_verifier_nbytes,
                              const uint8_t *id_verifier)
{
    // TT += len(Context) || Context
    ccspake_transcript_append(ctx, context_nbytes, context);

    // TT += len(idProver) || idProver
    ccspake_transcript_append(ctx, id_prover_nbytes, id_prover);

    // TT += len(idVerifier) || idVerifier
    ccspake_transcript_append(ctx, id_verifier_nbytes, id_verifier);

    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    const cc_unit *M = ccspake_ctx_scp(ctx)->m;
    const cc_unit *N = ccspake_ctx_scp(ctx)->n;

    // TT += len(M) || M
    ccspake_transcript_append_point(ctx, cp, M, M + n);

    // TT += len(N) || N
    ccspake_transcript_append_point(ctx, cp, N, N + n);
}

void ccspake_transcript_append_point(ccspake_ctx_t ctx, ccec_const_cp_t cp, const cc_unit *x, const cc_unit *y)
{
    uint8_t xy[1 + 2 * CCSPAKE_MAX_CURVE_NBYTES] = { CCSPAKE_X963_UNCOMPRESSED, 0x00 };

    size_t len = ccec_cp_prime_size(cp);
    cc_size n = ccec_cp_n(cp);

    ccn_write_uint_padded(n, x, len, xy + 1);
    ccn_write_uint_padded(n, y, len, xy + 1 + len);
    ccspake_transcript_append(ctx, 1 + 2 * len, xy);
}

void ccspake_transcript_append_scalar(ccspake_ctx_t ctx, ccec_const_cp_t cp, const cc_unit *x)
{
    uint8_t num[CCSPAKE_MAX_CURVE_NBYTES] = { 0x00 };

    size_t len = ccec_cp_order_size(cp);
    cc_size n = ccec_cp_n(cp);

    ccn_write_uint_padded(n, x, len, num);
    ccspake_transcript_append(ctx, len, num);
}

void ccspake_transcript_finish(ccspake_ctx_t ctx, uint8_t *main_key)
{
    const struct ccdigest_info *di = ccspake_ctx_mac(ctx)->di();
    ccdigest_final(di, ccspake_ctx_hash(ctx), main_key);
    ccdigest_di_clear(di, ccspake_ctx_hash(ctx));
}
