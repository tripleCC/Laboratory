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

void ccsrp_generate_M_ws(cc_ws_t ws,
                         ccsrp_ctx_t srp,
                         const char *username,
                         size_t salt_len,
                         const void *salt,
                         const cc_unit *A,
                         const cc_unit *B)
{
    const struct ccdigest_info *di = ccsrp_ctx_di(srp);
    size_t hashlen = di->output_size;
    uint8_t hash_n[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t hash_g[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t H_I[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t H_xor[MAX_DIGEST_OUTPUT_SIZE];

    ccdigest_di_decl(di, ctx);
    bool skip_leading_zeroes = (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_TOKEN);

    CC_DECL_BP_WS(ws, bp);

    ccsrp_digest_ccn_ws(ws, srp, ccsrp_ctx_prime(srp), hash_n, skip_leading_zeroes);
    ccsrp_digest_ccn_ws(ws, srp, ccsrp_ctx_gp_g(srp), hash_g, skip_leading_zeroes);

    cc_xor(hashlen, H_xor, hash_n, hash_g);

    ccdigest(di, strlen(username), username, H_I);
    ccdigest_init(di, ctx);
    ccdigest_update(di, ctx, hashlen, H_xor);
    ccdigest_update(di, ctx, hashlen, H_I);
    ccdigest_update(di, ctx, salt_len, salt);
    ccsrp_digest_update_ccn_ws(ws, srp, ctx, A, skip_leading_zeroes);
    ccsrp_digest_update_ccn_ws(ws, srp, ctx, B, skip_leading_zeroes);
    ccdigest_update(di, ctx, ccsrp_get_session_key_length(srp), ccsrp_ctx_K(srp));
    ccdigest_final(di, ctx, ccsrp_ctx_M(srp));
    ccdigest_di_clear(di, ctx);

    cc_clear(sizeof(hash_n), hash_n);
    cc_clear(sizeof(hash_g), hash_g);
    cc_clear(sizeof(H_xor), H_xor);
    cc_clear(sizeof(H_I), H_I);

    CC_FREE_BP_WS(ws, bp);
}
