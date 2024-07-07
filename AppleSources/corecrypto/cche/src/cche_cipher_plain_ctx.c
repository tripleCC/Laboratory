/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cche_cipher_plain_ctx.h"
#include "cche_internal.h"

CC_PURE cc_size CCHE_CIPHER_PLAIN_CTX_INIT_WORKSPACE_N(cc_size nmoduli)
{
    const cc_size q_n = ccpolyzp_po2cyc_ctx_q_prod_nof_n((uint32_t)nmoduli);
    return (q_n) + (q_n) +
           CC_MAX_EVAL(
               CCPOLYZP_PO2CYC_CTX_Q_PROD_WORKSPACE_N(nmoduli),
               CC_MAX_EVAL(CCN_DIVMOD_WORKSPACE_N(q_n),
                           CC_MAX_EVAL(CCZP_MODN_WORKSPACE_N(q_n), CCN_SUB_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF))));
}

int cche_cipher_plain_ctx_init_ws(cc_ws_t ws,
                                  cche_cipher_plain_ctx_t cipher_plain_ctx,
                                  cche_param_ctx_const_t param_ctx,
                                  ccpolyzp_po2cyc_ctx_const_t cipher_ctx)
{
    int rv = CCERR_OK;
    const uint32_t nmoduli = cipher_ctx->dims.nmoduli;
    cipher_plain_ctx->param_ctx = param_ctx;
    cipher_plain_ctx->cipher_ctx = cipher_ctx;

    CC_DECL_BP_WS(ws, bp);

    const cc_size q_n = ccpolyzp_po2cyc_ctx_q_prod_nof_n(nmoduli);
    cc_unit *q = CC_ALLOC_WS(ws, q_n);
    ccpolyzp_po2cyc_ctx_q_prod_ws(ws, q, cipher_ctx);

    cc_unit t_units[CCPOLYZP_PO2CYC_NUNITS_PER_COEFF];
    ccpolyzp_po2cyc_rns_int_to_units(t_units, cche_param_ctx_plaintext_modulus(param_ctx));

    cc_unit *q_div_t = CC_ALLOC_WS(ws, q_n);

    // compute `q % t` and `q / t`
    ccn_divmod_ws(ws, q_n, q, q_n, q_div_t, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, cipher_plain_ctx->q_mod_t, t_units);

    ccpolyzp_po2cyc_rns_int_to_units(cipher_plain_ctx->t_half, (cche_param_ctx_plaintext_modulus(param_ctx) + 1) / 2);

    cc_unit *delta = CCHE_CIPHER_PLAIN_CTX_DELTA(cipher_plain_ctx);
    cc_unit *plain_increment = CCHE_CIPHER_PLAIN_CTX_PLAIN_INCREMENT(cipher_plain_ctx);
    for (uint32_t i = 0; i < nmoduli; ++i) {
        cczp_const_t q_i = ccpolyzp_po2cyc_ctx_cczp_modulus_const(cipher_ctx, i);
        cczp_modn_ws(ws, q_i, delta, q_n, q_div_t);
        cc_unit borrow = ccn_sub_ws(ws, CCPOLYZP_PO2CYC_NUNITS_PER_COEFF, plain_increment, CCZP_PRIME(q_i), t_units);
        cc_require_action(borrow == 0, errOut, rv = CCERR_INTERNAL);
        delta += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
        plain_increment += CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}
