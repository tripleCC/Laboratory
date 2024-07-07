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

void ccsrp_generate_H_AMK_ws(cc_ws_t ws, ccsrp_ctx_t srp, const cc_unit *A)
{
    const struct ccdigest_info *di = ccsrp_ctx_di(srp);
    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);
    bool skip_leading_zeroes = (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_TOKEN);

    CC_DECL_BP_WS(ws, bp);

    ccsrp_digest_update_ccn_ws(ws, srp, ctx, A, skip_leading_zeroes);
    ccdigest_update(di, ctx, ccsrp_session_size(srp), ccsrp_ctx_M(srp));
    ccdigest_update(di, ctx, ccsrp_get_session_key_length(srp), ccsrp_ctx_K(srp));
    ccdigest_final(di, ctx, ccsrp_ctx_HAMK(srp));
    ccdigest_di_clear(di, ctx);

    CC_FREE_BP_WS(ws, bp);
}
