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

#ifndef _CORECRYPTO_CCSRP_H_
#define _CORECRYPTO_CCSRP_H_

#include <corecrypto/ccn.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccdh.h>
#include <corecrypto/ccrng.h>

CC_PTRCHECK_CAPABLE_HEADER()

/* Aliases for DH-style group params for SRP */

typedef struct ccdh_gp ccsrp_gp;
#define CCSRP_HDR_PAD 32

typedef ccdh_gp_t ccsrp_gp_t;
typedef ccdh_const_gp_t ccsrp_const_gp_t;

struct ccsrp_ctx {
    const struct ccdigest_info *di;
    ccsrp_const_gp_t gp;
    struct ccrng_state *blinding_rng;
    struct {
        unsigned int authenticated : 1;
        unsigned int noUsernameInX : 1;
        unsigned int sessionkey : 1;
        unsigned int variant : 16;
    } flags;
    CC_ALIGNED(CCN_UNIT_SIZE) cc_unit ccn[1];
} CC_ALIGNED(16);
typedef struct ccsrp_ctx *ccsrp_ctx_t;

#define ccsrp_gpbuf_size(_gp_) (ccdh_ccn_size(_gp_) * 4)
#define ccsrp_dibuf_size(_di_) ((_di_)->output_size * 4)

/* Size of the context structure for the di and gp combo */
#define ccsrp_sizeof_srp(_di_, _gp_) \
    sizeof(struct ccsrp_ctx) + ccsrp_gpbuf_size(_gp_) + ccsrp_dibuf_size(_di_)

/* Use this to declare a context on the stack
 Use ccsrp_ctx_clear when done to prevent exposing key material */
#define ccsrp_ctx_decl(_di_, _gp_, _name_) \
    cc_ctx_decl(struct ccsrp_ctx, ccsrp_sizeof_srp(_di_, _gp_), _name_)

#define ccsrp_ctx_clear(_di_, _gp_, _name_) cc_clear(ccsrp_sizeof_srp(_di_, _gp_), _name_)

/* Accessors to the context structure. */
#define HDR(srp) (srp)
#define SRP_DI(srp) (HDR(srp)->di)
#define SRP_GP(srp) (HDR(srp)->gp)
#define SRP_FLG(srp) (HDR(srp)->flags)
#define SRP_CCN(srp) (HDR(srp)->ccn)
#define SRP_RNG(srp) (HDR(srp)->blinding_rng)

#define ccsrp_ctx_gp(KEY) SRP_GP((ccsrp_ctx_t)(KEY))
#define ccsrp_ctx_di(KEY) SRP_DI((ccsrp_ctx_t)(KEY))
#define ccsrp_ctx_gp_g(KEY) (ccdh_gp_g(ccsrp_ctx_gp(KEY)))
#define ccsrp_ctx_gp_l(KEY) (ccdh_gp_l(ccsrp_ctx_gp(KEY)))
#define ccsrp_ctx_n(KEY) (ccdh_gp_n(ccsrp_ctx_gp(KEY)))
#define ccsrp_ctx_prime(KEY) (ccdh_gp_prime(ccsrp_ctx_gp(KEY)))
#define ccsrp_ctx_ccn(KEY) SRP_CCN((ccsrp_ctx_t)(KEY))
#define ccsrp_ctx_pki_key(KEY, _N_) (ccsrp_ctx_ccn(KEY) + ccsrp_ctx_n(KEY) * _N_)
#define ccsrp_ctx_public(KEY) (ccsrp_ctx_pki_key(KEY, 0))
#define ccsrp_ctx_private(KEY) (ccsrp_ctx_pki_key(KEY, 1))
#define ccsrp_ctx_v(KEY) (ccsrp_ctx_pki_key(KEY, 2))
#define ccsrp_ctx_S(KEY) (ccsrp_ctx_pki_key(KEY, 3))
#define ccsrp_ctx_K(KEY) ((uint8_t *)(ccsrp_ctx_pki_key(KEY, 4)))
#define ccsrp_ctx_M(KEY) (uint8_t *)(ccsrp_ctx_K(KEY) + 2 * ccsrp_ctx_di(KEY)->output_size)
#define ccsrp_ctx_HAMK(KEY) (uint8_t *)(ccsrp_ctx_K(KEY) + 3 * ccsrp_ctx_di(KEY)->output_size)

#define ccsrp_gp_sizeof_n(GP) (ccn_sizeof_n(ccdh_gp_n(GP)))
#define ccsrp_ctx_sizeof_n(KEY) (ccsrp_gp_sizeof_n(ccsrp_ctx_gp(KEY)))

/* Session Keys and M and HAMK are returned in this many bytes */
#define ccsrp_ctx_keysize(KEY) ccsrp_get_session_key_length(KEY)
#define ccsrp_ctx_M_HAMK_size(KEY) (ccsrp_sizeof_M_HAMK(ccsrp_ctx_di(KEY)))

CC_NONNULL_ALL
size_t ccsrp_sizeof_verifier(ccsrp_const_gp_t gp);

CC_NONNULL_ALL
size_t ccsrp_sizeof_public_key(ccsrp_const_gp_t gp);

CC_NONNULL_ALL
size_t ccsrp_sizeof_M_HAMK(const struct ccdigest_info *di);

/******************************************************************************
 *  Variant (main difference is key derivation after DH di
 *****************************************************************************/
/* OPTION
     [0..2]: KDF to compute K from S
     [3..5]: Variant (value of k in the computation of B)
     [6..7]: Padding in Hash (leading zeroes hashed or skipped in hashes) */

// Do Not use these flags directly. Please use one of the "combo" flags.
// and request a new combo flag is needed.

// Selection of KDF for the session key
#define CCSRP_OPTION_KDF_MASK (7 << 0)
// K = H(S), size of K is the size of the digest output
#define CCSRP_OPTION_KDF_HASH (0 << 0)
// K = MGF1(S), size of K is TWICE the size of the digest output
#define CCSRP_OPTION_KDF_MGF1 (1 << 0)
// K = H_Interleave(S), size of K is TWICE the size of the digest output
#define CCSRP_OPTION_KDF_INTERLEAVED (2 << 0)

// Selection of the variant for internal computation
#define CCSRP_OPTION_VARIANT_MASK (7 << 3)
// k = HASH(N | PAD(g)) and u = HASH(PAD(A) | PAD(B))
#define CCSRP_OPTION_VARIANT_SRP6a (0 << 3)
// K = 1 and u=MSB32bit(HASH(PAD(B))
#define CCSRP_OPTION_VARIANT_RFC2945 (1 << 3)

// Selection of leading zeroes in integer hashes
#define CCSRP_OPTION_PAD_MASK (3 << 6)
// Skip zeroes of A and B during hashes for the computation of k, U and X
#define CCSRP_OPTION_PAD_SKIP_ZEROES_k_U_X (1 << 6)
// Skip leading zeroes when hashing A,B in M and HAMK only
// This is a hack to be compatible with AppleSRP implementation
#define CCSRP_OPTION_PAD_SKIP_ZEROES_TOKEN (2 << 6)

// Higher level combos:
//  Corecrypto default
#define CCSRP_OPTION_SRP6a_HASH (CCSRP_OPTION_VARIANT_SRP6a | CCSRP_OPTION_KDF_HASH)

// Improved SRP6a (with MGF1) compatible with SRP
// The domain parameter (g) is hashed on the exact number of bytes instead hashing
// modlen bytes.
#define CCSRP_OPTION_SRP6a_MGF1 \
    (CCSRP_OPTION_VARIANT_SRP6a | CCSRP_OPTION_KDF_MGF1 | CCSRP_OPTION_PAD_SKIP_ZEROES_TOKEN)

//  TLS-SRP. Not recommended except when interoperability is required
#define CCSRP_OPTION_RFC2945_INTERLEAVED                           \
    (CCSRP_OPTION_VARIANT_RFC2945 | CCSRP_OPTION_KDF_INTERLEAVED | \
     CCSRP_OPTION_PAD_SKIP_ZEROES_k_U_X | CCSRP_OPTION_PAD_SKIP_ZEROES_TOKEN)

/*!
 @function   ccsrp_ctx_init_with_size_option
 @abstract   Initialize the SRP context

 @param  srp            SRP
 @param  srp_size       Size of SRP
 @param  di             handle on the digest to be used (ex. ccsha1_di())
 @param  gp             handle on DH group parameters (requires group with no small subgroups)
 @param  option         Define variant, key derivation and padding of integers being hashed.
 @param  blinding_rng   For randomization of internal computations, rng may be used for as long as
 the "srp" context is used.

 @result 0 if no error
 */
/* Init context structures with this function */
CC_NONNULL((1, 3, 4))
int ccsrp_ctx_init_with_size_option(struct ccsrp_ctx * cc_sized_by(srp_size) srp,
                                    size_t srp_size,
                                    const struct ccdigest_info *di,
                                    ccsrp_const_gp_t gp,
                                    uint32_t option,
                                    struct ccrng_state *blinding_rng);

#if CC_PTRCHECK

cc_unavailable() // Use ccsrp_ctx_init_with_size_option().
int ccsrp_ctx_init_option(ccsrp_ctx_t srp,
                          const struct ccdigest_info *di,
                          ccsrp_const_gp_t gp,
                          uint32_t option,
                          struct ccrng_state *blinding_rng);

cc_unavailable()
// Use ccsrp_ctx_init_with_size_option().
void ccsrp_ctx_init(ccsrp_ctx_t srp, const struct ccdigest_info *di, ccsrp_const_gp_t gp);

#else

/*!
 @function   ccsrp_ctx_init_option
 @abstract   Initialize the SRP context

 @param  srp            SRP
 @param  di             handle on the digest to be used (ex. ccsha1_di())
 @param  gp             handle on DH group parameters (requires group with no small subgroups)
 @param  option         Define variant, key derivation and padding of integers being hashed.
 @param  blinding_rng   For randomization of internal computations, rng may be used for as long as
 the "srp" context is used.

 @result 0 if no error
 */
/* Init context structures with this function */
CC_NONNULL((1, 2, 3))
int ccsrp_ctx_init_option(ccsrp_ctx_t srp,
                          const struct ccdigest_info *di,
                          ccsrp_const_gp_t gp,
                          uint32_t option,
                          struct ccrng_state *blinding_rng);

// Legacy function, initialize for the RFC5054 variant.
CC_NONNULL((1, 2, 3))
void ccsrp_ctx_init(ccsrp_ctx_t srp, const struct ccdigest_info *di, ccsrp_const_gp_t gp);

#endif

/******************************************************************************
 *  Salt and Verification Generation - used to setup an account.
 *****************************************************************************/

/*!
 @function   ccsrp_generate_salt_and_verification
 @abstract   Generate the salt and the verification token to be used for future
                authentications

 @param      srp        SRP
 @param      rng        handle on rng for ephemeral key generation
 @param      username   identity
 @param      password_len length in byte of the password
 @param      password   password of length password_len
 @param      salt_len   length in byte of the salt
 @param      salt       salt of length salt_len (output)
 @param      verifier   password verifier known to the server (output)

 @result 0 if no error
 */
CC_NONNULL((1, 2, 3, 5, 7, 8))
int ccsrp_generate_salt_and_verification(ccsrp_ctx_t srp,
                                         struct ccrng_state *rng,
                                         const char *cc_cstring username,
                                         size_t password_len,
                                         const void *cc_sized_by(password_len) password,
                                         size_t salt_len,
                                         void *cc_sized_by(salt_len) salt,
                                         void *cc_unsafe_indexable verifier);

/*!
 @function   ccsrp_generate_verifier
 @abstract   Generate the verification token to be used for future
 authentications

 @param      srp        SRP
 @param      username   identity
 @param      password_len length in byte of the password
 @param      password   password of length password_len
 @param      salt_len   length in byte of the salt
 @param      salt       salt of length salt_len (input)
 @param      verifier   password verifier known to the server (output)

 @result 0 if no error
 */
CC_NONNULL((1, 2, 4, 6, 7))
int ccsrp_generate_verifier(ccsrp_ctx_t srp,
                            const char *cc_cstring username,
                            size_t password_len,
                            const void *cc_sized_by(password_len) password,
                            size_t salt_len,
                            const void *cc_sized_by(salt_len) salt,
                            void *cc_unsafe_indexable verifier);

/******************************************************************************
 *  Server Side Routines
 *****************************************************************************/

/*!
 @function   ccsrp_server_generate_public_key
 @abstract   Generate the server value B.
             If A is known, call directly ccsrp_server_start_authentication

 @param      srp        SRP
 @param      rng        handle on rng for ephemeral key generation
 @param      verifier   password verifier known to the server
 @param      B_bytes    Value B which is the challenge to send to the client (output)

 @result 0 if no error
 */
CC_NONNULL((1, 2, 3, 4))
int ccsrp_server_generate_public_key(ccsrp_ctx_t srp,
                                     struct ccrng_state *rng,
                                     const void *cc_unsafe_indexable verifier,
                                     void *cc_unsafe_indexable B_bytes);

/*!
 @function   ccsrp_server_compute_session
 @abstract   Generate the session key material and tokens for authentication

 @param      srp        SRP
 @param      username   identity
 @param      salt_len   length in byte of the salt
 @param      salt       salt of length salt_len
 @param      A_bytes    Ephemeral public key received from the client

 @result 0 if no error
 */
CC_NONNULL((1, 2, 4, 5))
int ccsrp_server_compute_session(ccsrp_ctx_t srp,
                                 const char *cc_cstring username,
                                 size_t salt_len,
                                 const void *cc_sized_by(salt_len) salt,
                                 const void *cc_unsafe_indexable A_bytes);

/*!
 @function   ccsrp_server_start_authentication
 @abstract   Performs in one shot the server public key and the session key material

 @param      srp        SRP
 @param      rng        handle on rng for ephemeral key generation
 @param      username   identity
 @param      salt_len   length in byte of the salt
 @param      salt       salt of length salt_len
 @param      verifier   password verifier known to the server
 @param      A_bytes    Ephemeral public key received from the client
 @param      B_bytes    Value B which is the challenge to send to the client (output)

 @result 0 if no error
 */
CC_NONNULL((1, 2, 3, 5, 6, 7, 8))
int ccsrp_server_start_authentication(ccsrp_ctx_t srp,
                                      struct ccrng_state *rng,
                                      const char *cc_cstring username,
                                      size_t salt_len,
                                      const void *cc_sized_by(salt_len) salt,
                                      const void *cc_unsafe_indexable verifier,
                                      const void *cc_unsafe_indexable A_bytes,
                                      void *cc_unsafe_indexable B_bytes);

/*!
 @function   ccsrp_server_verify_session
 @abstract   Verify that the token received from the client is correct and that
            therefore authentication succeeded.

 @param      srp            SRP
 @param      user_M         Authentication token received from the client
 @param      HAMK_bytes     Authentication token generated to be sent to the client (output)

 @result true if client is authenticated, false otherwise (fail or incomplete protocol)
 */
CC_NONNULL((1, 2, 3))
bool ccsrp_server_verify_session(ccsrp_ctx_t srp, const void *cc_unsafe_indexable user_M, void *cc_unsafe_indexable HAMK_bytes);

/******************************************************************************
 *  Client Side Routines
 *****************************************************************************/

/*!
 @function   ccsrp_client_start_authentication
 @abstract   Initiate protocol with an ephemeral public key

 @param      srp        SRP
 @param      rng        handle on random for key generation
 @param      A_bytes    Output public key to send to the server

 @result 0 if no error
 */
CC_NONNULL((1, 2, 3))
int ccsrp_client_start_authentication(ccsrp_ctx_t srp, struct ccrng_state *rng, void *cc_unsafe_indexable A_bytes);

/*!
 @function   ccsrp_client_process_challenge
 @abstract   Process the challenge receive from the server

 @param      srp        SRP
 @param      username   identity
 @param      password_len length in byte of the password
 @param      password   password of length password_len
 @param      salt_len   length in byte of the salt
 @param      salt       salt of length salt_len
 @param      B_bytes    Value B received from the server
 @param      M_bytes    Response to the challenge (output)

 @result 0 if no error
 */
CC_NONNULL((1, 2, 4, 6, 7, 8))
int ccsrp_client_process_challenge(ccsrp_ctx_t srp,
                                   const char *cc_cstring username,
                                   size_t password_len,
                                   const void *cc_sized_by(password_len) password,
                                   size_t salt_len,
                                   const void *cc_sized_by(salt_len) salt,
                                   const void *cc_unsafe_indexable B_bytes,
                                   void *cc_unsafe_indexable M_bytes);

/*!
 @function   ccsrp_client_verify_session
 @abstract   Verify that the token received from the server is correct and that
             therefore authentication succeeded.

 @param      srp            SRP
 @param      HAMK_bytes     Authentication token received from the server

 @result true if authenticated, false otherwise (fail or incomplete protocol)
 */
CC_NONNULL((1, 2)) bool ccsrp_client_verify_session(ccsrp_ctx_t srp, const uint8_t *cc_unsafe_indexable HAMK_bytes);

CC_NONNULL((1))
bool ccsrp_client_set_noUsernameInX(ccsrp_ctx_t srp, bool flag);

/******************************************************************************
 *  Functions for both sides
 *****************************************************************************/

/*!
 @function   ccsrp_is_authenticated
 @abstract   Returns whether authentication was successful

 @param      srp        SRP

 @result true if authenticated, false otherwise (fail or incomplete protocol)
 */
CC_NONNULL((1))
bool ccsrp_is_authenticated(ccsrp_ctx_t srp);

/*!
 @function   ccsrp_exchange_size
 @abstract   Returns the size of the public keys exchanged

 @param      srp        SRP

 @result The length of the public key in bytes
 */
CC_NONNULL((1))
size_t ccsrp_exchange_size(ccsrp_ctx_t srp);

/*!
 @function   ccsrp_session_size
 @abstract   Returns the size of the session authentication tokens M and HAMK

 @param      srp        SRP

 @result The length of M and HAMK in bytes
 */
CC_NONNULL((1))
size_t ccsrp_session_size(ccsrp_ctx_t srp);

CC_NONNULL_ALL
size_t ccsrp_sizeof_session_key(const struct ccdigest_info *di,
                                uint32_t option);

/*!
 @function   ccsrp_get_session_key_length
 @abstract   Returns the size of the session key K, which depends on the variant

 @param      srp        SRP

 @result The length of K
 */
CC_NONNULL((1))
size_t ccsrp_get_session_key_length(ccsrp_ctx_t srp);

/*!
 @function   ccsrp_get_session_key
 @abstract   Returns a pointer to the session key and its size

 @param      srp            SRP context
 @param      key_length     pointer to output the size of the session key

 @result pointer to the session key in SRP context. NULL if the key has not been
            computed yet
 */
CC_NONNULL((1, 2))
const void *ccsrp_get_session_key(ccsrp_ctx_t srp, size_t *key_length);

/*!
 @function   ccsrp_get_premaster_secret
 @abstract   Returns a pointer to the premaster secret key
                use for TLS-SRP
                This value is not a cryptographic key. A KDF is needed before
                use.

 @param      srp            SRP context

 @result pointer to the premaster secret in SRP context.
        The secret is an array of ccsrp_ctx_n(srp) cc_units */
CC_NONNULL((1))
cc_unit *ccsrp_get_premaster_secret(ccsrp_ctx_t srp);

#endif // _CORECRYPTO_CCSRP_H_
