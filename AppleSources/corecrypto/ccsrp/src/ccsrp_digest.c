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

#include "ccsrp_internal.h"

void ccsrp_digest_ccn_ws(cc_ws_t ws,
                         ccsrp_ctx_t srp,
                         const cc_unit *s,
                         void *dest,
                         bool skip_leading_zeroes)
{
    cc_size n = ccsrp_ctx_n(srp);

    CC_DECL_BP_WS(ws, bp);
    uint8_t *buf = (uint8_t *)CC_ALLOC_WS(ws, n);
    size_t offset = ccsrp_export_ccn(srp, s, buf);

    if (!skip_leading_zeroes) {
        offset = 0; // Leading zeroes will be hashed
    }

    ccdigest(ccsrp_ctx_di(srp), ccsrp_ctx_sizeof_n(srp) - offset, buf + offset, dest);

    CC_FREE_BP_WS(ws, bp);
}

void ccsrp_digest_update_ccn_ws(cc_ws_t ws,
                                ccsrp_ctx_t srp,
                                void *ctx,
                                const cc_unit *s,
                                bool skip_leading_zeroes)
{
    cc_size n = ccsrp_ctx_n(srp);

    CC_DECL_BP_WS(ws, bp);
    uint8_t *buf = (uint8_t *)CC_ALLOC_WS(ws, n);
    size_t offset = ccsrp_export_ccn(srp, s, buf);

    if (!skip_leading_zeroes) {
        offset = 0; // Leading zeroes will be hashed
    }

    ccdigest_update(ccsrp_ctx_di(srp), ctx, ccsrp_ctx_sizeof_n(srp) - offset, buf + offset);

    CC_FREE_BP_WS(ws, bp);
}

void ccsrp_digest_ccn_ccn_ws(cc_ws_t ws,
                             ccsrp_ctx_t srp,
                             cc_unit *r,
                             const cc_unit *a,
                             const cc_unit *b,
                             size_t len,
                             bool skip_leading_zeroes)
{
    const struct ccdigest_info *di = ccsrp_ctx_di(srp);
    uint8_t hash[MAX_DIGEST_OUTPUT_SIZE];
    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);

    CC_DECL_BP_WS(ws, bp);

    if (a) {
        ccsrp_digest_update_ccn_ws(ws, srp, ctx, a, skip_leading_zeroes);
    }

    ccsrp_digest_update_ccn_ws(ws, srp, ctx, b, skip_leading_zeroes);
    ccdigest_final(di, ctx, hash);

    if (len > di->output_size || len <= 0) {
        len = di->output_size;
    }

    ccn_read_uint(ccsrp_ctx_n(srp), r, len, hash);
    cc_clear(di->output_size, hash);
    ccdigest_di_clear(di, ctx);

    CC_FREE_BP_WS(ws, bp);
}
