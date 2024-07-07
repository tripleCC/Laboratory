/* Copyright (c) (2012-2022) Apple Inc. All rights reserved.
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
#include "ccdh_internal.h"
#include "cc_workspaces.h"
#include "cc_macros.h"

/******************************************************************************
 *  Client Side Routines
 *****************************************************************************/

int ccsrp_generate_client_pubkey_ws(cc_ws_t ws, ccsrp_ctx_t srp)
{
    return ccdh_power_blinded_ws(ws,
                                 SRP_RNG(srp),
                                 ccsrp_ctx_gp(srp),
                                 ccsrp_ctx_public(srp),
                                 ccsrp_ctx_gp_g(srp),
                                 ccsrp_private_key_bitlen(srp),
                                 ccsrp_ctx_private(srp));
}

int ccsrp_generate_client_S_ws(cc_ws_t ws,
                               ccsrp_ctx_t srp,
                               cc_unit *S,
                               const cc_unit *k,
                               const cc_unit *x,
                               const cc_unit *u,
                               const cc_unit *B)
{
    /* Client Side S = (B - k*(g^x)) ^ (a + ux) */
    cc_size n = ccsrp_ctx_n(srp);
    int status = CCERR_OK;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp1 = CC_ALLOC_WS(ws, 2 * n);
    cc_unit *tmp2 = CC_ALLOC_WS(ws, n);

    cc_unit c;
    // In ccsrp_init
    // tmp1 = a + ux
    ccn_mul_ws(ws, n, tmp1, u, x);
    c = ccn_add_ws(ws, n, tmp1, ccsrp_ctx_private(srp), tmp1);

    size_t xbitlen = ccsrp_ctx_di(srp)->output_size * 8;
    size_t tmp1_bitlen = xbitlen + ccsrp_generate_u_nbytes(srp) * 8;
    tmp1_bitlen = CC_MAX_EVAL(tmp1_bitlen, ccsrp_private_key_bitlen(srp)) + 1;

    if (tmp1_bitlen >= ccdh_gp_prime_bitlen(ccsrp_ctx_gp(srp))) {
        // if a + u*x is bigger than p in size, need to handle carry
        // and reduction mod p-1
        ccn_add1_ws(ws, n, &tmp1[n], &tmp1[n], c);
        ccn_sub1(n, tmp2, ccsrp_ctx_prime(srp), 1); // p-1
        ccn_mod_ws(ws, 2 * n, tmp1, n, tmp1, tmp2);
        tmp1_bitlen = ccdh_gp_prime_bitlen(ccsrp_ctx_gp(srp));
    } else {
        cc_assert(c == 0); // Carry is not possible here
    }

    // tmp2 = (g^x)
    status = ccdh_power_blinded_ws(ws, SRP_RNG(srp), ccsrp_ctx_gp(srp), tmp2, ccsrp_ctx_gp_g(srp), xbitlen, x);
    cc_require(status == CCERR_OK, errOut);

    // tmp2 = k * (g^x)
    if ((SRP_FLG(srp).variant & CCSRP_OPTION_VARIANT_MASK) == CCSRP_OPTION_VARIANT_SRP6a) {
        cczp_mul_ws(ws, ccsrp_ctx_zp(srp), tmp2, k, tmp2);
    }

    // tmp2 = (B - k*(g^x))
    cczp_sub_ws(ws, ccsrp_ctx_zp(srp), tmp2, B, tmp2);

    // S = tmp2 ^ tmp1
    status = ccdh_power_blinded_ws(ws, SRP_RNG(srp), ccsrp_ctx_gp(srp), S, tmp2, tmp1_bitlen, tmp1);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

static int ccsrp_client_start_authentication_ws(cc_ws_t ws,
                                                ccsrp_ctx_t srp,
                                                struct ccrng_state *rng,
                                                void *A_bytes)
{
    CC_DECL_BP_WS(ws, bp);

    int status = ccdh_generate_private_key_ws(ws, ccsrp_ctx_gp(srp), ccsrp_ctx_private(srp), rng);
    cc_require(status == CCERR_OK, errOut);

    status = ccsrp_generate_client_pubkey_ws(ws, srp);
    cc_require(status == CCERR_OK, errOut);

    ccsrp_export_ccn(srp, ccsrp_ctx_public(srp), A_bytes);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccsrp_client_start_authentication(ccsrp_ctx_t srp, struct ccrng_state *rng, void *A_bytes)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccsrp_ctx_n(srp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSRP_CLIENT_START_AUTHENTICATION_WORKSPACE_N(n));
    int rv = ccsrp_client_start_authentication_ws(ws, srp, rng, A_bytes);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

CC_NONNULL_ALL
static int ccsrp_client_process_challenge_ws(cc_ws_t ws,
                                             ccsrp_ctx_t srp,
                                             const char *username,
                                             size_t password_len,
                                             const void *password,
                                             size_t salt_len,
                                             const void *salt,
                                             const void *B_bytes,
                                             void *M_bytes)
{
    cc_size n = ccsrp_ctx_n(srp);
    cc_unit *S = ccsrp_ctx_S(srp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *B = CC_ALLOC_WS(ws, n);
    cc_unit *u = CC_ALLOC_WS(ws, n);
    cc_unit *x = CC_ALLOC_WS(ws, n);
    cc_unit *k = CC_ALLOC_WS(ws, n);
    cc_unit *tmp = CC_ALLOC_WS(ws, n);

    if (8 * ccsrp_ctx_di(srp)->output_size > ccdh_gp_prime_bitlen(ccsrp_ctx_gp(srp))) {
        // u.x is of size hash output length * 2
        // this implementation requires sizeof(u)=sizeof(x)=hash_size <= sizeof(prime)
        return CCSRP_NOT_SUPPORTED_CONFIGURATION;
    }

    int status = ccsrp_import_ccn(srp, B, B_bytes);
    cc_require(status == CCERR_OK, errOut);

    cczp_mod_ws(ws, ccsrp_ctx_zp(srp), tmp, B);
    // SRP-6a safety check
    cc_require_action(!ccn_is_zero(n, tmp), errOut, status = CCSRP_SAFETY_CHECK);

    ccsrp_generate_u_ws(ws, srp, u, ccsrp_ctx_public(srp), B);

    cczp_mod_ws(ws, ccsrp_ctx_zp(srp), tmp, u);
    // SRP-6a safety check
    cc_require_action(!ccn_is_zero(n, tmp), errOut, status = CCSRP_SAFETY_CHECK);

    status = ccsrp_generate_x(srp, x, username, salt_len, salt, password_len, password);
    cc_require(status == CCERR_OK, errOut);

    ccsrp_generate_k_ws(ws, srp, k);

    /* Client Side S = (B - k*(g^x)) ^ (a + ux) */
    status = ccsrp_generate_client_S_ws(ws, srp, S, k, x, u, B);
    cc_require(status == CCERR_OK, errOut);

    /* K = f(S) where f is a function which depends on the variant */
    status = ccsrp_generate_K_from_S_ws(ws, srp, S);
    cc_require(status == CCERR_OK, errOut);

    ccsrp_generate_M_ws(ws, srp, username, salt_len, salt, ccsrp_ctx_public(srp), B);
    ccsrp_generate_H_AMK_ws(ws, srp, ccsrp_ctx_public(srp));
    cc_memcpy(M_bytes, ccsrp_ctx_M(srp), ccsrp_ctx_M_HAMK_size(srp));

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccsrp_client_process_challenge(ccsrp_ctx_t srp,
                                   const char *username,
                                   size_t password_len,
                                   const void *password,
                                   size_t salt_len,
                                   const void *salt,
                                   const void *B_bytes,
                                   void *M_bytes)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccsrp_ctx_n(srp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSRP_CLIENT_PROCESS_CHALLENGE_WORKSPACE_N(n));
    int rv = ccsrp_client_process_challenge_ws(ws, srp, username, password_len, password, salt_len, salt, B_bytes, M_bytes);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

bool ccsrp_client_verify_session(ccsrp_ctx_t srp, const uint8_t *HAMK_bytes)
{
    CC_ENSURE_DIT_ENABLED

    int cmp = cc_cmp_safe(ccsrp_ctx_M_HAMK_size(srp), ccsrp_ctx_HAMK(srp), HAMK_bytes);
    return SRP_FLG(srp).authenticated = ((cmp == 0) && SRP_FLG(srp).sessionkey);
}
