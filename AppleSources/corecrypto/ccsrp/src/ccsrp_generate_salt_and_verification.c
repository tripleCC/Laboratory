/* Copyright (c) (2010-2016,2018,2019,2021,2022) Apple Inc. All rights reserved.
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
#include "ccsrp_internal.h"
#include "cc_macros.h"

/******************************************************************************
 *  Salt and Verification Generation - used to setup an account.
 *****************************************************************************/

int ccsrp_generate_v_ws(cc_ws_t ws, ccsrp_ctx_t srp, const cc_unit *x)
{
    size_t xbitlen = ccsrp_ctx_di(srp)->output_size * 8;
    return ccdh_power_blinded_ws(ws,
                                 SRP_RNG(srp),
                                 ccsrp_ctx_gp(srp),
                                 ccsrp_ctx_v(srp),
                                 ccsrp_ctx_gp_g(srp),
                                 xbitlen,
                                 x);
}

int ccsrp_generate_salt_and_verification(ccsrp_ctx_t srp,
                                         struct ccrng_state *rng,
                                         const char *username,
                                         size_t password_len,
                                         const void *password,
                                         size_t salt_len,
                                         void *salt,
                                         void *verifier)
{
    CC_ENSURE_DIT_ENABLED

    int status = ccrng_generate(rng, salt_len, salt);
    if (status) {
        return status;
    }

    return ccsrp_generate_verifier(srp, username, password_len, password, salt_len, salt, verifier);
}

static int ccsrp_generate_verifier_ws(cc_ws_t ws,
                                      ccsrp_ctx_t srp,
                                      const char *username,
                                      size_t password_len,
                                      const void *password,
                                      size_t salt_len,
                                      const void *salt,
                                      void *verifier)
{
    cc_size n = ccsrp_ctx_n(srp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *x = CC_ALLOC_WS(ws, n);

    ccn_clear(n, ccsrp_ctx_v(srp));
    ccn_clear(n, x);

    int status = ccsrp_generate_x(srp, x, username, salt_len, salt, password_len, password);
    cc_require(status == CCERR_OK, errOut);

    status = ccsrp_generate_v_ws(ws, srp, x);
    cc_require(status == CCERR_OK, errOut);

    ccsrp_export_ccn(srp, ccsrp_ctx_v(srp), verifier);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccsrp_generate_verifier(ccsrp_ctx_t srp,
                            const char *username,
                            size_t password_len,
                            const void *password,
                            size_t salt_len,
                            const void *salt,
                            void *verifier)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccsrp_ctx_n(srp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSRP_GENERATE_VERIFIER_WORKSPACE_N(n));
    int rv = ccsrp_generate_verifier_ws(ws, srp, username, password_len, password, salt_len, salt, verifier);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
