/* Copyright (c) (2012,2014-2019,2021,2022) Apple Inc. All rights reserved.
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
#include "cc_macros.h"

/******************************************************************************
 *  Server Side Routines
 *****************************************************************************/

int ccsrp_generate_server_pubkey_ws(cc_ws_t ws, ccsrp_ctx_t srp, const cc_unit *k)
{
    cc_size n = ccsrp_ctx_n(srp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp1 = CC_ALLOC_WS(ws, n);
    cc_unit *tmp2 = CC_ALLOC_WS(ws, n);

    /* B = kv + g^b */
    cc_unit *kv;

    if ((SRP_FLG(srp).variant & CCSRP_OPTION_VARIANT_MASK) == CCSRP_OPTION_VARIANT_SRP6a) {
        cczp_mul_ws(ws, ccsrp_ctx_zp(srp), tmp1, k, ccsrp_ctx_v(srp));
        kv = tmp1;
    } else {
        kv = ccsrp_ctx_v(srp); // k=1
    }

    size_t pk_bitlen = ccsrp_private_key_bitlen(srp);
    int status = ccdh_power_blinded_ws(
        ws, SRP_RNG(srp), ccsrp_ctx_gp(srp), tmp2, ccsrp_ctx_gp_g(srp), pk_bitlen, ccsrp_ctx_private(srp));
    cc_require(status == CCERR_OK, errOut);

    cczp_add_ws(ws, ccsrp_ctx_zp(srp), ccsrp_ctx_public(srp), kv, tmp2);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccsrp_generate_server_S_ws(cc_ws_t ws, ccsrp_ctx_t srp, cc_unit *S, const cc_unit *u, const cc_unit *A)
{
    cc_size n = ccsrp_ctx_n(srp);

    /* S = (A *(v^u)) ^ b */
    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp1 = CC_ALLOC_WS(ws, n);
    cc_unit *tmp2 = CC_ALLOC_WS(ws, n);

    // u is public, ok to use non secure exponentiation
    int status = cczp_mm_power_fast_ws(ws, ccsrp_ctx_zp(srp), tmp1, ccsrp_ctx_v(srp), u);
    cc_require(status == CCERR_OK, errOut);

    cczp_mul_ws(ws, ccsrp_ctx_zp(srp), tmp2, A, tmp1);

    size_t pk_bitlen = ccsrp_private_key_bitlen(srp);
    status = ccdh_power_blinded_ws(ws, SRP_RNG(srp), ccsrp_ctx_gp(srp), S, tmp2, pk_bitlen, ccsrp_ctx_private(srp));

errOut:
    if (status) {
        ccn_zero(n, S);
    }

    CC_FREE_BP_WS(ws, bp);
    return status;
}

static int ccsrp_server_generate_public_key_ws(cc_ws_t ws,
                                               ccsrp_ctx_t srp,
                                               struct ccrng_state *rng,
                                               const void *verifier,
                                               void *B_bytes)
{
    int status = CCSRP_ERROR_DEFAULT;
    cc_size n = ccsrp_ctx_n(srp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *k = CC_ALLOC_WS(ws, n);

    status = ccsrp_import_ccn(srp, ccsrp_ctx_v(srp), verifier);
    cc_require(status == CCERR_OK, errOut);

    SRP_FLG(srp).authenticated = false;

    // Create b (ccsrp_ctx_private)
    status = ccdh_generate_private_key_ws(ws, ccsrp_ctx_gp(srp), ccsrp_ctx_private(srp), rng);
    cc_require(status == CCERR_OK, errOut);

    // Generate parameter k
    if ((SRP_FLG(srp).variant & CCSRP_OPTION_VARIANT_MASK) == CCSRP_OPTION_VARIANT_SRP6a) {
        ccsrp_generate_k_ws(ws, srp, k);
    }

    /* B = kv + g^b */
    status = ccsrp_generate_server_pubkey_ws(ws, srp, k);
    cc_require(status == CCERR_OK, errOut);

    ccsrp_export_ccn(srp, ccsrp_ctx_public(srp), B_bytes);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccsrp_server_generate_public_key(ccsrp_ctx_t srp,
                                     struct ccrng_state *rng,
                                     const void *verifier,
                                     void *B_bytes)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccsrp_ctx_n(srp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSRP_SERVER_GENERATE_PUBLIC_KEY_WORKSPACE_N(n));
    int rv = ccsrp_server_generate_public_key_ws(ws, srp, rng, verifier, B_bytes);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

static int ccsrp_server_compute_session_ws(cc_ws_t ws,
                                           ccsrp_ctx_t srp,
                                           const char *username,
                                           size_t salt_len,
                                           const void *salt,
                                           const void *A_bytes)
{
    cc_size n = ccsrp_ctx_n(srp);

    if (ccn_is_zero(n, ccsrp_ctx_public(srp))) {
        return CCSRP_PUBLIC_KEY_MISSING;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *A = CC_ALLOC_WS(ws, n);
    cc_unit *u = CC_ALLOC_WS(ws, n);

    cc_unit *S = ccsrp_ctx_S(srp);

    // Import A and sanity check on it
    int status = ccsrp_import_ccn(srp, A, A_bytes);
    cc_require(status == CCERR_OK, errOut);

    cczp_mod_ws(ws, ccsrp_ctx_zp(srp), u, A);
    cc_require_action(!ccn_is_zero(n, u), errOut, status = CCSRP_SAFETY_CHECK);

    /* u = H(A,B) */
    ccsrp_generate_u_ws(ws, srp, u, A, ccsrp_ctx_public(srp));

    /* S = (A *(v^u)) ^ b */
    status = ccsrp_generate_server_S_ws(ws, srp, S, u, A);
    cc_require(status == CCERR_OK, errOut);

    /* K = f(S) where f is a function which depends on the variant */
    status = ccsrp_generate_K_from_S_ws(ws, srp, S);
    cc_require(status == CCERR_OK, errOut);

    ccsrp_generate_M_ws(ws, srp, username, salt_len, salt, A, ccsrp_ctx_public(srp));
    ccsrp_generate_H_AMK_ws(ws, srp, A);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccsrp_server_compute_session(ccsrp_ctx_t srp,
                                 const char *username,
                                 size_t salt_len,
                                 const void *salt,
                                 const void *A_bytes)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccsrp_ctx_n(srp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSRP_SERVER_COMPUTE_SESSION_WORKSPACE_N(n));
    int rv = ccsrp_server_compute_session_ws(ws, srp, username, salt_len, salt, A_bytes);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccsrp_server_start_authentication(ccsrp_ctx_t srp,
                                      struct ccrng_state *rng,
                                      const char *username,
                                      size_t salt_len,
                                      const void *salt,
                                      const void *verifier,
                                      const void *A_bytes,
                                      void *B_bytes)
{
    CC_ENSURE_DIT_ENABLED

    int status = CCSRP_ERROR_DEFAULT;
    SRP_RNG(srp) = rng;

    // Generate server public key B
    cc_require((status = ccsrp_server_generate_public_key(srp, rng, verifier, B_bytes)) == 0,
               errOut);
    /* We're done with that part of the handshake the rest now computes the remaining
     * handshake values K, M, and HAMK
     */

    // Generate session key material
    cc_require((status = ccsrp_server_compute_session(srp, username, salt_len, salt, A_bytes)) == 0,
               errOut);

errOut:
    return status;
}

bool ccsrp_server_verify_session(ccsrp_ctx_t srp, const void *user_M, void *HAMK_bytes)
{
    CC_ENSURE_DIT_ENABLED

    int cmp = cc_cmp_safe(ccsrp_ctx_M_HAMK_size(srp), ccsrp_ctx_M(srp), user_M);
    SRP_FLG(srp).authenticated = (cmp == 0) && SRP_FLG(srp).sessionkey;

    if (SRP_FLG(srp).authenticated) {
        cc_memcpy(HAMK_bytes, ccsrp_ctx_HAMK(srp), ccsrp_ctx_M_HAMK_size(srp));
    }

    return SRP_FLG(srp).authenticated;
}
