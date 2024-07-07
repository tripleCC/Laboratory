/* Copyright (c) (2018,2019,2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSPAKE_H_
#define _CORECRYPTO_CCSPAKE_H_

#include <corecrypto/ccec.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccn.h>
#include <corecrypto/ccrng.h>

/*
 * The corecrypto SPAKE2+ API, as per RFC 9383.
 */

struct ccspake_ctx;
typedef struct ccspake_ctx *ccspake_ctx_t;
typedef const struct ccspake_ctx *ccspake_const_ctx_t;

struct ccspake_cp;
typedef const struct ccspake_cp *ccspake_const_cp_t;

CC_CONST ccspake_const_cp_t ccspake_cp_256(void);
CC_CONST ccspake_const_cp_t ccspake_cp_384(void);
CC_CONST ccspake_const_cp_t ccspake_cp_521(void);
CC_CONST ccspake_const_cp_t ccspake_cp_256_rfc(void);
CC_CONST ccspake_const_cp_t ccspake_cp_384_rfc(void);
CC_CONST ccspake_const_cp_t ccspake_cp_521_rfc(void);

struct ccspake_mac;
typedef const struct ccspake_mac *ccspake_const_mac_t;

CC_CONST ccspake_const_mac_t ccspake_mac_hkdf_cmac_aes128_sha256(void);
CC_CONST ccspake_const_mac_t ccspake_mac_hkdf_hmac_sha256(void);
CC_CONST ccspake_const_mac_t ccspake_mac_hkdf_hmac_sha512(void);

typedef uint8_t ccspake_state_t;

// SHA-512 is the largest supported digest.
#define CCSPAKE_MAX_DIGEST_BLOCK_NBYTES  CCSHA512_BLOCK_SIZE
#define CCSPAKE_MAX_DIGEST_STATE_NBYTES  CCSHA512_STATE_SIZE
#define CCSPAKE_MAX_DIGEST_OUTPUT_NBYTES CCSHA512_OUTPUT_SIZE

#define CCSPAKE_MAX_AAD_NBYTES 20

struct ccspake_ctx {
    ccspake_const_cp_t scp;
    ccspake_const_mac_t mac;
    struct ccrng_state *rng;
    bool is_prover;
    size_t aad_nbytes;
    uint8_t aad[CCSPAKE_MAX_AAD_NBYTES];
    ccspake_state_t state;
    cc_ctx_decl_field(struct ccdigest_ctx, ccdigest_ctx_size(CCSPAKE_MAX_DIGEST_BLOCK_NBYTES, CCSPAKE_MAX_DIGEST_STATE_NBYTES), hash);
    uint8_t main_key[CCSPAKE_MAX_DIGEST_OUTPUT_NBYTES];
    CC_ALIGNED(CCN_UNIT_SIZE) cc_unit ccn[];
};

/*! @function ccspake_sizeof_ctx
 @abstract Returns the size of a SPAKE2+ context

 @param cp SPAKE2+ curve parameters

 @return Size of a SPAKE2+ context
 */
CC_NONNULL((1))
size_t ccspake_sizeof_ctx(ccspake_const_cp_t cp);

/*! @function ccspake_sizeof_w
 @abstract Returns the size of scalars w0/w1

 @param cp SPAKE2+ curve parameters

 @return Size of w0/w1
 */
CC_NONNULL((1))
size_t ccspake_sizeof_w(ccspake_const_cp_t cp);

/*! @function ccspake_sizeof_point
 @abstract Returns the size of public shares transmitted between peers

 @param cp EC curve parameters

 @return Size of a public share
 */
CC_NONNULL((1))
size_t ccspake_sizeof_point(ccspake_const_cp_t cp);

#define ccspake_ctx_decl(_cp_, _name_) cc_ctx_decl(struct ccspake_ctx, ccspake_sizeof_ctx(_cp_), _name_)
#define ccspake_ctx_clear(_cp_, _name_) cc_clear(ccspake_sizeof_ctx(_cp_), _name_)

/*! @function ccspake_generate_L
 @abstract Generate the L-part of a verifier from w1

 @param cp        SPAKE2+ curve parameters
 @param w1_nbytes Length of scalars w1 in bytes
                      Must be equal to ccspake_sizeof_w().
 @param w1        Scalar w1, first part of the verifier
 @param L_nbytes  Length of L in bytes
                      Must be equal to ccspake_sizeof_point().
 @param L         L, second part of the verifier
 @param rng       RNG state

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int ccspake_generate_L(ccspake_const_cp_t cp,
                       size_t w1_nbytes,
                       const uint8_t *w1,
                       size_t L_nbytes,
                       uint8_t *L,
                       struct ccrng_state *rng);

/*! @function ccspake_prover_init
 
 @abstract Initialize a SPAKE2+ prover context. This does NOT implement RFC 9383.

 @param ctx        SPAKE2+ context
 @param scp        SPAKE2+ curve parameters
 @param mac        MAC parameters
 @param rng        RNG state
 @param aad_nbytes Length of the additional authenticated data in bytes
                       Limited to 20 bytes.
 @param aad        Pointer to additional authenticated data
 @param w_nbytes   Length of the scalars w0/w1 in bytes
 @param w0         Scalar w0
 @param w1         Scalar w1

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 3, 4, 8, 9))
int ccspake_prover_init(ccspake_ctx_t ctx,
                        ccspake_const_cp_t scp,
                        ccspake_const_mac_t mac,
                        struct ccrng_state *rng,
                        size_t aad_nbytes,
                        const uint8_t *aad,
                        size_t w_nbytes,
                        const uint8_t *w0,
                        const uint8_t *w1);

/*! @function ccspake_prover_initialize
 
 @abstract Initialize a SPAKE2+ prover context. This implements RFC 9383.

 @param ctx                SPAKE2+ context
 @param scp                SPAKE2+ curve parameters
 @param mac                MAC parameters
 @param rng                RNG state
 @param context_nbytes     Length of the transcript context in bytes
                               Limited to 20 bytes for use with CCC variants.
 @param context            Transcript context for domain separation
 @param id_prover_nbytes   Length of the prover ID in bytes
 @param id_prover          ID of the proving party (optional)
 @param id_verifier_nbytes Length of the verifier ID in bytes
 @param id_verifier        ID of the verifying party (optional)
 @param w_nbytes           Length of scalars w0/w1 in bytes
 @param w0                 Scalar w0 (reduced mod q)
                               Use ccspake_reduce_w() to compute w0 from w0s,
                               where (w0s,w1s) := PBKDF(pw).
 @param w1                 Scalar w1 (reduced mod q)
                               Use ccspake_reduce_w() to compute w1 from w1s,
                               where (w0s,w1s) := PBKDF(pw).

 @discussion    The context should be an application-specific string that
                includes the name of the application or the higher-level
                protocol name and version number. It may additionally include
                PBKDF parameters used to derive w0s,w1s.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 3, 4, 6, 12, 13))
int ccspake_prover_initialize(ccspake_ctx_t ctx,
                              ccspake_const_cp_t scp,
                              ccspake_const_mac_t mac,
                              struct ccrng_state *rng,
                              size_t context_nbytes,
                              const uint8_t *context,
                              size_t id_prover_nbytes,
                              const uint8_t *id_prover,
                              size_t id_verifier_nbytes,
                              const uint8_t *id_verifier,
                              size_t w_nbytes,
                              const uint8_t *w0,
                              const uint8_t *w1);

/*! @function ccspake_verifier_init
 
 @abstract Initialize a SPAKE2+ verifier context. This does NOT implement RFC 9383.

 @param ctx        SPAKE2+ context
 @param scp        SPAKE2+ curve parameters
 @param mac        MAC parameters
 @param rng        RNG state
 @param aad_nbytes Length of the additional authenticated data in bytes
                       Limited to 20 bytes.
 @param aad        Pointer to additional authenticated data
 @param w0_nbytes  Length of scalar w0 in bytes
 @param w0         Scalar w0, first part of the verifier
 @param L_nbytes   Length of L in bytes
 @param L          L, second part of the verifier

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 3, 4, 8, 10))
int ccspake_verifier_init(ccspake_ctx_t ctx,
                          ccspake_const_cp_t scp,
                          ccspake_const_mac_t mac,
                          struct ccrng_state *rng,
                          size_t aad_nbytes,
                          const uint8_t *aad,
                          size_t w0_nbytes,
                          const uint8_t *w0,
                          size_t L_nbytes,
                          const uint8_t *L);

/*! @function ccspake_verifier_initialize
 @abstract      Initialize a SPAKE2+ verifier context. This implements RFC 9383.

 @param ctx                SPAKE2+ context
 @param scp                SPAKE2+ curve parameters
 @param mac                MAC parameters
 @param rng                RNG state
 @param context_nbytes     Length of the transcript context in bytes
                               Limited to 20 bytes for use with CCC variants.
 @param context            Transcript context for domain separation
 @param id_prover_nbytes   Length of the prover ID in bytes
 @param id_prover          ID of the proving party (optional)
 @param id_verifier_nbytes Length of the verifier ID in bytes
 @param id_verifier        ID of the verifying party (optional)
 @param w0_nbytes          Length of scalar w0 in bytes
 @param w0                 Scalar w0 (reduced mod q), first part of the verifier
                               Use ccspake_reduce_w() to compute w0 from w0s,
                               where (w0s,w1s) := PBKDF(pw).
 @param L_nbytes           Length of L in bytes
 @param L                  L, second part of the verifier

 @discussion    The context should be an application-specific string that
                includes the name of the application or the higher-level
                protocol name and version number. It may additionally include
                PBKDF parameters used to derive w0s,w1s.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 3, 4, 6, 12, 14))
int ccspake_verifier_initialize(ccspake_ctx_t ctx,
                                ccspake_const_cp_t scp,
                                ccspake_const_mac_t mac,
                                struct ccrng_state *rng,
                                size_t context_nbytes,
                                const uint8_t *context,
                                size_t id_prover_nbytes,
                                const uint8_t *id_prover,
                                size_t id_verifier_nbytes,
                                const uint8_t *id_verifier,
                                size_t w0_nbytes,
                                const uint8_t *w0,
                                size_t L_nbytes,
                                const uint8_t *L);

/*! @function ccspake_kex_generate
 @abstract Generate a public share for key exchange

 @param ctx   SPAKE2+ context
 @param x_len Length of the X buffer (MUST be equal to ccspake_sizeof_point(ctx))
 @param x     Output buffer for the public share

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3))
int ccspake_kex_generate(ccspake_ctx_t ctx, size_t x_len, uint8_t *x);

/*! @function ccspake_kex_process
 @abstract Process a public share for key exchange

 @param ctx   SPAKE2+ context
 @param y_len Length of the Y buffer (MUST be equal to ccspake_sizeof_point(ctx))
 @param y     Public share sent by the peer

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3))
int ccspake_kex_process(ccspake_ctx_t ctx, size_t y_len, const uint8_t *y);

/*! @function ccspake_mac_compute
 @abstract Generate a MAC for key confirmation. If additional authenticated data was passed to the initializer, the passed pointer still needs to be valid.

 @param ctx   SPAKE2+ context
 @param t_len Desired length of the MAC
 @param t     Output buffer for the MAC

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3))
int ccspake_mac_compute(ccspake_ctx_t ctx, size_t t_len, uint8_t *t);

/*! @function ccspake_mac_verify_and_get_session_key
 @abstract Verify a MAC to confirm and derive the shared key. If additional authenticated data was passed to the initializer, the passed pointer still needs to be valid.

 @param ctx    SPAKE2+ context
 @param t_len  Length of the MAC
 @param t      MAC sent by the peer
 @param sk_len Desired length of the shared key
 @param sk     Output buffer for the shared key

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3, 5))
int ccspake_mac_verify_and_get_session_key(ccspake_ctx_t ctx, size_t t_len, const uint8_t *t, size_t sk_len, uint8_t *sk);

/*! @function ccspake_reduce_w

 @abstract  Interprets the input w0s/w1s as an integer and reduces it mod q,
            where (w0s,w1s) := PBKDF(pw) and pw is known to the prover.

            Computes w0/w1 := w0s/w1s (mod q-1) + 1. To control bias, the
            input w0s/w1s must be of at least ccspake_sizeof_w() + 8 bytes.
            The bias is at most 2^-64 and thus negligible.

 @param cp           SPAKE2+ curve parameters
 @param w_in_nbytes  Length of w0s/w1s in bytes
                         Must be at least ccspake_sizeof_w() + 8 bytes.
 @param w_in         w0s/w1s to be safely reduced (mod q-1) + 1
 @param w_out_nbytes Length of output w0/w1 in bytes
                         Must be equal to ccspake_sizeof_w().
 @param w_out        Output w0/w1 = w0s/w1s reduced (mod q-1) + 1

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_WARN_RESULT CC_NONNULL_ALL
int ccspake_reduce_w(ccspake_const_cp_t cp,
                     size_t w_in_nbytes,
                     const uint8_t *w_in,
                     size_t w_out_nbytes,
                     uint8_t *w_out);

#endif /* _CORECRYPTO_CCSPAKE_H_ */
