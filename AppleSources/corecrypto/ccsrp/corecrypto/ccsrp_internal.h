/* Copyright (c) (2012-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSRP_INTERNAL_H_
#define _CORECRYPTO_CCSRP_INTERNAL_H_

#include <corecrypto/ccsrp.h>
#include "ccdh_internal.h"
#include "cczp_internal.h"

/* Accessors to the context structure. */
#define ccsrp_ctx_zp(KEY) ccdh_gp_zp((ccsrp_ctx_gp(KEY)))

CC_NONNULL_ALL
CC_INLINE size_t ccsrp_export_ccn(ccsrp_ctx_t srp, const cc_unit *a, void *bytes)
{
    return (size_t)ccn_write_uint_padded_ct(ccsrp_ctx_n(srp), a, ccsrp_ctx_sizeof_n(srp), bytes);
}

CC_NONNULL_ALL CC_INLINE
int ccsrp_import_ccn(ccsrp_ctx_t srp, cc_unit *a, const void *bytes)
{
    return ccn_read_uint(ccsrp_ctx_n(srp), a, ccsrp_ctx_sizeof_n(srp), bytes);
}

CC_NONNULL_ALL CC_INLINE
int ccsrp_import_ccn_with_len(ccsrp_ctx_t srp, cc_unit *a, size_t len, const void *bytes)
{
    return ccn_read_uint(ccsrp_ctx_n(srp), a, len, bytes);
}

CC_NONNULL_ALL
void ccsrp_digest_ccn_ws(cc_ws_t ws,
                         ccsrp_ctx_t srp,
                         const cc_unit *s,
                         void *dest,
                         bool skip_leading_zeroes);

CC_NONNULL_ALL
void ccsrp_digest_update_ccn_ws(cc_ws_t ws,
                                ccsrp_ctx_t srp,
                                void *ctx,
                                const cc_unit *s,
                                bool skip_leading_zeroes);

// Len is the number of bytes of the digest to be used for "r".
// If len==0 or len> digest length, take the entire digest
CC_NONNULL((1, 2, 3, 5))
void ccsrp_digest_ccn_ccn_ws(cc_ws_t ws,
                             ccsrp_ctx_t srp,
                             cc_unit *r,
                             const cc_unit *a,
                             const cc_unit *b,
                             size_t len,
                             bool skip_leading_zeroes);

CC_NONNULL_ALL
void ccsrp_generate_k_ws(cc_ws_t ws, ccsrp_ctx_t srp, cc_unit *k);

CC_NONNULL_ALL
int ccsrp_generate_v_ws(cc_ws_t ws, ccsrp_ctx_t srp, const cc_unit *x);

CC_NONNULL_ALL CC_INLINE
size_t ccsrp_generate_u_nbytes(ccsrp_ctx_t srp)
{
    if ((SRP_FLG(srp).variant & CCSRP_OPTION_VARIANT_MASK) == CCSRP_OPTION_VARIANT_SRP6a) {
        return ccsrp_ctx_di(srp)->output_size;
    }

    return 4; /* 32 bits */
}

CC_NONNULL_ALL
void ccsrp_generate_u_ws(cc_ws_t ws, ccsrp_ctx_t srp, cc_unit *u, const cc_unit *A, const cc_unit *B);

CC_NONNULL_ALL
CC_INLINE size_t ccsrp_private_key_bitlen(ccsrp_ctx_t srp)
{
    size_t nbits_default = ccdh_generate_private_key_bitlen(ccsrp_ctx_gp(srp));
    size_t nbits_actual = ccn_bitlen(ccsrp_ctx_n(srp), ccsrp_ctx_private(srp));

    // If the private key is larger than what we would generate,
    // then it must be a test vector value injected after setup.
    if (CC_UNLIKELY(nbits_actual > nbits_default)) {
        return ccdh_gp_prime_bitlen(ccsrp_ctx_gp(srp));
    }

    return nbits_default;
}

CC_NONNULL_ALL
int ccsrp_generate_server_S_ws(cc_ws_t ws,
                               ccsrp_ctx_t srp,
                               cc_unit *S,
                               const cc_unit *u,
                               const cc_unit *A);

CC_NONNULL_ALL
int ccsrp_generate_client_S_ws(cc_ws_t ws,
                               ccsrp_ctx_t srp,
                               cc_unit *S,
                               const cc_unit *k,
                               const cc_unit *x,
                               const cc_unit *u,
                               const cc_unit *B);

CC_NONNULL_ALL
void ccsrp_generate_H_AMK_ws(cc_ws_t ws, ccsrp_ctx_t srp, const cc_unit *A);

CC_NONNULL_ALL
int ccsrp_generate_client_pubkey_ws(cc_ws_t ws, ccsrp_ctx_t srp);

CC_NONNULL_ALL
int ccsrp_generate_server_pubkey_ws(cc_ws_t ws, ccsrp_ctx_t srp, const cc_unit *k);

/*!
 @function   ccsrp_generate_K_from_S_ws
 @abstract   Generate the key K from the shared secret S

 @param      ws         Workspace
 @param      srp        SRP
 @param      S          Number represented as a cc_unit array of size ccsrp_ctx_sizeof_n(srp)

 @result SRP structure is updated with value S
 */
CC_NONNULL_ALL
int ccsrp_generate_K_from_S_ws(cc_ws_t ws, ccsrp_ctx_t srp, const cc_unit *S);

// x = SHA(s | SHA(U | ":" | p))
CC_NONNULL_ALL
int ccsrp_generate_x(ccsrp_ctx_t srp,
                     cc_unit *x,
                     const char *username,
                     size_t salt_len,
                     const void *salt,
                     size_t password_len,
                     const void *password);

CC_NONNULL_ALL
void ccsrp_generate_M_ws(cc_ws_t ws,
                         ccsrp_ctx_t srp,
                         const char *username,
                         size_t salt_len,
                         const void *salt,
                         const cc_unit *A,
                         const cc_unit *B);

int ccsrp_test_calculations(const struct ccdigest_info *di,
                            ccsrp_const_gp_t gp,
                            struct ccrng_state *blinding_rng,
                            const char *username,
                            uint32_t options,
                            size_t password_len,
                            const void *password,
                            size_t salt_len,
                            const void *salt,
                            size_t k_len,
                            const void *k,
                            size_t x_len,
                            const void *x,
                            size_t v_len,
                            const void *v,
                            size_t a_len,
                            const void *a,
                            size_t b_len,
                            const void *b,
                            size_t A_len,
                            const void *A,
                            size_t B_len,
                            const void *B,
                            size_t u_len,
                            const void *u,
                            size_t S_len,
                            const void *S,
                            size_t K_len,
                            const void *K,
                            size_t M_len,
                            const void *M,
                            size_t HAMK_len,
                            const void *HAMK);

#endif // _CORECRYPTO_CCSRP_INTERNAL_H_
