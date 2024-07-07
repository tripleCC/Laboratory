/* Copyright (c) (2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCKYBER_INTERNAL_H_
#define _CORECRYPTO_CCKYBER_INTERNAL_H_

#include "cc_internal.h"
#include "cc_memory.h"

#include <corecrypto/cckyber.h>

#define CCKYBER_N 256
#define CCKYBER_Q 3329

#define CCKYBER_SYM_NBYTES 32 // size in bytes of hashes, and seeds
#define CCKYBER_SK_NBYTES  32 // size in bytes of shared key
#define CCKYBER_MSG_NBYTES CCKYBER_SK_NBYTES

// 256 x 12-bit coefficients
#define CCKYBER_POLY_NBYTES 384

// k encoded polynomials
#define CCKYBER_POLYVEC_NBYTES(params) \
    (params->k * CCKYBER_POLY_NBYTES)

// k x 256 x d_u-bit coefficients
#define CCKYBER_POLYVEC_COMPRESSED_NBYTES(params) \
    (32 * params->du * params->k)

// k encoded polynomials + 32-bit seed
#define CCKYBER_INDCPA_PUBKEY_NBYTES(params) \
    (CCKYBER_POLYVEC_NBYTES(params) + CCKYBER_SYM_NBYTES)

// k encoded polynomials
#define CCKYBER_INDCPA_PRIVKEY_NBYTES(params) \
    CCKYBER_POLYVEC_NBYTES(params)

// k encoded polynomials + 32-bit seed
#define CCKYBER_PUBKEY_NBYTES(params) \
    CCKYBER_INDCPA_PUBKEY_NBYTES(params)

// k encoded polynomials + pubkey + hash(pubkey) + z (pseudo-random output on reject)
#define CCKYBER_PRIVKEY_NBYTES(params) (    \
    CCKYBER_INDCPA_PRIVKEY_NBYTES(params) + \
    CCKYBER_PUBKEY_NBYTES(params)         + \
    2 * CCKYBER_SYM_NBYTES                  \
)

// 256 x d_v-bit coefficients + k x 256 x d_u-bit coefficients
#define CCKYBER_EK_NBYTES(params) \
    (32 * (params->du * params->k + params->dv))

// For Kyber768, with k=3:
//   256 x 4-bit coefficients + 3 x 256 x 10-bit coefficients = 1088 bytes
//
// For Kyber1024, with k=4:
//   256 x 5-bit coefficients + 4 x 256 x 11-bit coefficients = 1568 bytes
//
// For Kyber768, we report 1216 bytes (128 more than needed) because
// workspace generation would otherwise become quite a bit more complex.
#define cckyber_ek_ws(k) \
    ccn_nof((CCKYBER_N * 5) + (k * CCKYBER_N * 11))

#define cckyber_indcpa_pubkey_ws(k) \
    ccn_nof_size(k * CCKYBER_POLY_NBYTES + CCKYBER_SYM_NBYTES)

#define cckyber_poly_ws() ccn_nof_size(CCKYBER_N * sizeof(uint16_t))
#define cckyber_polyvec_ws(k) ccn_nof_size(k * CCKYBER_N * sizeof(uint16_t))

#define CCKYBER_ALLOC_INDCPA_PUBKEY_WS(ws, k) \
    (uint8_t *)CC_ALLOC_WS(ws, cckyber_indcpa_pubkey_ws(k))

#define CCKYBER_ALLOC_EK_WS(ws, k) \
    (uint8_t *)CC_ALLOC_WS(ws, cckyber_ek_ws(k))

#define CCKYBER_ALLOC_POLY_WS(ws) \
    (int16_t *)CC_ALLOC_WS(ws, cckyber_poly_ws())

#define CCKYBER_ALLOC_POLYVEC_WS(ws, k, n) \
    (int16_t *)CC_ALLOC_WS(ws, cckyber_polyvec_ws(k * n))

typedef struct cckyber_params {
    // Dimension of the module.
    // k=3 for Kyber768 and k=4 for Kyber1024.
    unsigned k;

    // No. of bits to retain per coefficient of polynomial v,
    // the private-key dependent part of the ciphertext.
    // d_v=4 for Kyber768 and d_v=5 for Kyber1024.
    unsigned dv;

    // No. of bits to retain per coefficient of vector u,
    // the private-key independent part of the ciphertext.
    // d_u=10 for Kyber768 and d_u=11 for Kyber1024.
    unsigned du;

    // Function pointers for (de-)compression of a single polynomial.
    void (*CC_SPTR(cckyber_params, poly_compress))(uint8_t *out, const int16_t coeffs[CCKYBER_N]);
    void (*CC_SPTR(cckyber_params, poly_decompress))(int16_t coeffs[CCKYBER_N], const uint8_t *in);

    // Function pointers for (de-)compression of a vector of polynomials.
    void (*CC_SPTR(cckyber_params, polyvec_compress))(uint8_t *out, const int16_t coeffs[CCKYBER_N]);
    void (*CC_SPTR(cckyber_params, polyvec_decompress))(int16_t coeffs[CCKYBER_N], const uint8_t *in);
} cckyber_params_t;

extern const cckyber_params_t cckyber768_params;
extern const cckyber_params_t cckyber1024_params;

/*! @function cckyber_sample_ntt
 @abstract Deterministically generate (the transpose of) matrix A from a given
           public seed. Polynomials of the vectors of matrix A are chosen via
           rejection sampling on the output of SHAKE128(seed, ...).

 @param params     Kyber parameters.
 @param seed       Public seed.
 @param transposed Pass 0 to generate A. Pass 1 to generate AˆT.
 @param a          Output matrix A.
 */
CC_NONNULL_ALL
void cckyber_sample_ntt(const cckyber_params_t *params,
                        const uint8_t *seed,
                        int transposed,
                        int16_t *a);

/*! @function cckyber_sample_cbd_eta2
 @abstract Given an array of uniformly random bytes, compute coefficients
           distributed according to a centered binomial distribution with
           parameter eta=2.

 @param coeffs  Output coefficients.
 @param buf     Uniform random bytes to sample from.
 */
CC_NONNULL_ALL
void cckyber_sample_cbd_eta2(int16_t coeffs[CCKYBER_N], const uint8_t buf[128]);

/*! @function cckyber_poly_getnoise
 @abstract Sample a polynomial deterministically from a seed and a nonce, with
           the output polynomial close to a centered binomial distribution
           with parameter eta=2.

 @param coeffs  Output coefficients.
 @param seed    Seed.
 @param nonce   Nonce.
 */
CC_NONNULL_ALL
void cckyber_poly_getnoise(int16_t coeffs[CCKYBER_N], const uint8_t seed[CCKYBER_SYM_NBYTES], uint8_t nonce);

/*! @function cckyber_poly_to_msg
 @abstract Serializes a given polynomial to a 256-bit message.

 @param msg    Output message.
 @param coeffs Coefficients of the polynomial to serialize.
 */
CC_NONNULL_ALL
void cckyber_poly_to_msg(uint8_t msg[CCKYBER_MSG_NBYTES], const int16_t coeffs[CCKYBER_N]);

/*! @function cckyber_poly_from_msg
 @abstract Deserializes a 256-bit message to a polynomial.

 @param coeffs Output coefficients.
 @param msg    Message to deserialize.
 */
CC_NONNULL_ALL
void cckyber_poly_from_msg(int16_t coeffs[CCKYBER_N], const uint8_t msg[CCKYBER_MSG_NBYTES]);

/*! @function cckyber_poly_encode
 @abstract Serializes a given polynomial to bytes.

 @param out    Output byte array.
 @param coeffs Coefficients of the polynomial to serialize.
 */
CC_NONNULL_ALL
void cckyber_poly_encode(uint8_t out[CCKYBER_POLY_NBYTES], const int16_t coeffs[CCKYBER_N]);

/*! @function cckyber_poly_decode
 @abstract Deserializes a given array of bytes to a polynomial.

 @param coeffs Output coefficients.
 @param in     Bytes to deserialize the polynomial from.
 */
CC_NONNULL_ALL
void cckyber_poly_decode(int16_t coeffs[CCKYBER_N], const uint8_t in[CCKYBER_POLY_NBYTES]);

/*! @function cckyber_poly_compress
 @abstract Compresses and serializes a given polynomial to bytes.

 @param params Kyber parameters.
 @param out    Output byte array.
 @param coeffs Coefficients of the polynomial to compress and serialize.
 */
CC_NONNULL_ALL
void cckyber_poly_compress(const cckyber_params_t *params,
                           uint8_t *out,
                           const int16_t coeffs[CCKYBER_N]);

/*! @function cckyber_poly_decompress
 @abstract Decompresses and deserializes a given array of bytes to a polynomial.

 @param params Kyber parameters.
 @param coeffs Output coefficients.
 @param in     Bytes to decompress and deserialize the polynomial from.
 */
CC_NONNULL_ALL
void cckyber_poly_decompress(const cckyber_params_t *params,
                             int16_t coeffs[CCKYBER_N],
                             const uint8_t *in);

/*! @function cckyber_poly_add
 @abstract Adds coefficients of the given polynomials.
           No reduction (mod q) is performed.

 @param coeffs Output coefficients.
 @param a      Coefficients of the first polynomial.
 @param b      Coefficients of the second polynomial.
 */
void cckyber_poly_add(int16_t coeffs[CCKYBER_N], const int16_t a[CCKYBER_N], const int16_t b[CCKYBER_N]);

/*! @function cckyber_poly_sub
 @abstract Subtracts coefficients of the given polynomials.
           No reduction (mod q) is performed.

 @param coeffs Output coefficients.
 @param a      Coefficients of the first polynomial.
 @param b      Coefficients of the second polynomial.
 */
void cckyber_poly_sub(int16_t coeffs[CCKYBER_N], const int16_t a[CCKYBER_N], const int16_t b[CCKYBER_N]);

/*! @function cckyber_poly_reduce
 @abstract Reduces coefficients of the given polynomial mod± q, computing
           centered representatives in { -(q-1)/2, ... , (q-1)/2 },
           congruent to x_i (mod q).

 @param coeffs Coefficients to reduce.
 */
void cckyber_poly_reduce(int16_t coeffs[CCKYBER_N]);

/*! @function cckyber_poly_toplant
 @abstract Converts coefficients of the given polynomial to Plantard domain,
           computing centered representatives in { -(q-1)/2, ... , (q-1)/2 },
           congruent to x_i * -2^32 (mod q).

 @param coeffs Coefficients to convert.
 */
void cckyber_poly_toplant(int16_t coeffs[CCKYBER_N]);

/*! @function cckyber_poly_compress_d1
 @abstract Compresses and serializes coefficients to 1 bit each.

 @param out    Output byte array.
 @param coeffs Coefficients to compress and serialize.
 */
CC_NONNULL_ALL
void cckyber_poly_compress_d1(uint8_t out[32], const int16_t coeffs[CCKYBER_N]);

/*! @function cckyber_poly_compress_d4
 @abstract Compresses and serializes coefficients to 4 bits each.

 @param out    Output byte array.
 @param coeffs Coefficients to compress and serialize.
 */
CC_NONNULL_ALL
void cckyber_poly_compress_d4(uint8_t out[128], const int16_t coeffs[CCKYBER_N]);

/*! @function cckyber_poly_compress_d5
 @abstract Compresses and serializes coefficients to 5 bits each.

 @param out    Output byte array.
 @param coeffs Coefficients to compress and serialize.
 */
CC_NONNULL_ALL
void cckyber_poly_compress_d5(uint8_t out[160], const int16_t coeffs[CCKYBER_N]);

/*! @function cckyber_poly_compress_d10
 @abstract Compresses and serializes coefficients to 10 bits each.

 @param out    Output byte array.
 @param coeffs Coefficients to compress and serialize.
 */
CC_NONNULL_ALL
void cckyber_poly_compress_d10(uint8_t out[320], const int16_t coeffs[CCKYBER_N]);

/*! @function cckyber_poly_compress_d11
 @abstract Compresses and serializes coefficients to 11 bits each.

 @param out    Output byte array.
 @param coeffs Coefficients to compress and serialize.
 */
CC_NONNULL_ALL
void cckyber_poly_compress_d11(uint8_t out[352], const int16_t coeffs[CCKYBER_N]);

/*! @function cckyber_poly_decompress_d1
 @abstract Decompresses and deserializes a given array of bytes to a polynomial
           where each coefficient is recovered from 1 input bit.

 @param coeffs Output coefficients.
 @param in     Bytes to decompress and deserialize the polynomial from.
 */
CC_NONNULL_ALL
void cckyber_poly_decompress_d1(int16_t coeffs[CCKYBER_N], const uint8_t in[32]);

/*! @function cckyber_poly_decompress_d4
 @abstract Decompresses and deserializes a given array of bytes to a polynomial
           where each coefficient is recovered from 4 input bits.

 @param coeffs Output coefficients.
 @param in     Bytes to decompress and deserialize the polynomial from.
 */
CC_NONNULL_ALL
void cckyber_poly_decompress_d4(int16_t coeffs[CCKYBER_N], const uint8_t in[128]);

/*! @function cckyber_poly_decompress_d5
 @abstract Decompresses and deserializes a given array of bytes to a polynomial
           where each coefficient is recovered from 5 input bits.

 @param coeffs Output coefficients.
 @param in     Bytes to decompress and deserialize the polynomial from.
 */
CC_NONNULL_ALL
void cckyber_poly_decompress_d5(int16_t coeffs[CCKYBER_N], const uint8_t in[160]);

/*! @function cckyber_poly_decompress_d10
 @abstract Decompresses and deserializes a given array of bytes to a polynomial
           where each coefficient is recovered from 10 input bits.

 @param coeffs Output coefficients.
 @param in     Bytes to decompress and deserialize the polynomial from.
 */
CC_NONNULL_ALL
void cckyber_poly_decompress_d10(int16_t coeffs[CCKYBER_N], const uint8_t in[320]);

/*! @function cckyber_poly_decompress_d11
 @abstract Decompresses and deserializes a given array of bytes to a polynomial
           where each coefficient is recovered from 11 input bits.

 @param coeffs Output coefficients.
 @param in     Bytes to decompress and deserialize the polynomial from.
 */
CC_NONNULL_ALL
void cckyber_poly_decompress_d11(int16_t coeffs[CCKYBER_N], const uint8_t in[352]);

/*! @function cckyber_polyvec_encode
 @abstract Serializes a given vector of k polynomials to bytes.

 @param params Kyber parameters.
 @param out    Output byte array.
 @param coeffs Coefficients of the polynomials to serialize.
 */
CC_NONNULL_ALL
void cckyber_polyvec_encode(const cckyber_params_t *params,
                            uint8_t *out,
                            const int16_t *coeffs);

/*! @function cckyber_polyvec_decode
 @abstract Deserializes a given array of bytes to a vector of k polynomials.

 @param params Kyber parameters.
 @param coeffs Output coefficients.
 @param in     Bytes to deserialize the polynomials from.
 */
CC_NONNULL_ALL
void cckyber_polyvec_decode(const cckyber_params_t *params,
                            int16_t *coeffs,
                            const uint8_t *in);

/*! @function cckyber_polyvec_compress
 @abstract Compresses and serializes a given vector of k polynomials to bytes.

 @param params Kyber parameters.
 @param out    Output byte array.
 @param coeffs Coefficients of the polynomial to compress and serialize.
 */
CC_NONNULL_ALL
void cckyber_polyvec_compress(const cckyber_params_t *params,
                              uint8_t *out,
                              const int16_t *coeffs);

/*! @function cckyber_polyvec_decompress
 @abstract Decompresses and deserializes a given array of bytes to a vector of
           k polynomials.

 @param params Kyber parameters.
 @param coeffs Output coefficients.
 @param in     Bytes to decompress and deserialize the polynomials from.
 */
CC_NONNULL_ALL
void cckyber_polyvec_decompress(const cckyber_params_t *params,
                                int16_t *coeffs,
                                const uint8_t *in);

/*! @function cckyber_polyvec_add
 @abstract Adds coefficients of the given vector of k polynomials.
           No reduction (mod q) is performed.

 @param params Kyber parameters.
 @param coeffs Output coefficients.
 @param a      Coefficients of the first vector of k polynomials.
 @param b      Coefficients of the second vector of k polynomials.
 */
CC_NONNULL_ALL
void cckyber_polyvec_add(const cckyber_params_t *params,
                         int16_t *coeffs,
                         const int16_t *a,
                         const int16_t *b);

/*! @function cckyber_polyvec_reduce
 @abstract Reduces coefficients of all k polynomials of a given vector mod± q,
           computing centered representatives in { -(q-1)/2, ... , (q-1)/2 },
           congruent to x_i (mod q).

 @param params Kyber parameters.
 @param coeffs Coefficients to reduce.
 */
CC_NONNULL_ALL
void cckyber_polyvec_reduce(const cckyber_params_t *params, int16_t *coeffs);

/*! @function cckyber_polyvec_ntt_forward
 @abstract Applies in-place forward NTT to the given vector of k polynomials.

 @param params Kyber parameters.
 @param coeffs Coefficients.
 */
CC_NONNULL_ALL
void cckyber_polyvec_ntt_forward(const cckyber_params_t *params, int16_t *coeffs);

/*! @function cckyber_polyvec_basemul
 @abstract Multiply and accumulate two vectors of polynomials in NTT domain.

           The resulting coefficients will be congruent to x_i / -2^32 (mod q).
           Values x_i (mod q) can be recovered by converting coefficients to
           Plantard domain.

 @param params Kyber parameters.
 @param coeffs Output coefficients.
 @param a      Coefficients of the first vector of k polynomials.
 @param b      Coefficients of the second vector of k polynomials.
 */
CC_NONNULL_ALL
void cckyber_polyvec_basemul(const cckyber_params_t *params,
                             int16_t *coeffs,
                             const int16_t *a,
                             const int16_t *b);

/*! @function cckyber_ntt_forward
 @abstract In-place forward NTT.

           The resulting coefficients are congruent to x_i (mod q)
           but not fully reduced.

 @param coeffs Coefficients.
 */
CC_NONNULL_ALL
void cckyber_ntt_forward(int16_t coeffs[256]);

/*! @function cckyber_ntt_inverse
 @abstract In-place inverse NTT.

           Input coefficients must be congruent to x_i / -2^32 (mod q). The
           final values will be recovered by converting to Plantard
           domain after the inverse NTT.

           The resulting coefficients will be centered representatives
           in { -(q-1)/2, ... , (q-1)/2 }, congruent to x_i (mod q).

 @param coeffs Coefficients.
 */
CC_NONNULL_ALL
void cckyber_ntt_inverse(int16_t coeffs[256]);

/*! @function cckyber_ntt_basemul
 @abstract Base multiplication of 128 degree-1 polynomials in NTT domain.

           The resulting coefficients will be in (-q, q), congruent to
           x_i / -2^32 (mod q). Values x_i (mod q) can be recovered by
           converting coefficients to Plantard domain.

 @param coeffs Coefficients of the resulting degree-1 polynomials.
 @param a      Coefficients of the first polynomial.
 @param b      Coefficients of the second polynomial.
 */
CC_NONNULL_ALL
void cckyber_ntt_basemul(int16_t coeffs[256], const int16_t a[256], const int16_t b[256]);

/*! @function cckyber_hash_h
 @abstract Computes the SHA3-256 digest for the given input bytes.

 @param nbytes Number of bytes to hash.
 @param bytes  Bytes to hash.
 @param out    32-byte output of SHA3-256.
 */
CC_NONNULL_ALL
void cckyber_hash_h(size_t nbytes, const uint8_t *bytes, uint8_t out[32]);

/*! @function cckyber_hash_g
 @abstract Computes the SHA3-512 digest for the given input bytes.

 @param nbytes Number of bytes to hash.
 @param bytes  Bytes to hash.
 @param out    64-byte output of SHA3-512.
 */
CC_NONNULL_ALL
void cckyber_hash_g(size_t nbytes, const uint8_t *bytes, uint8_t out[64]);

/*! @function cckyber_prf
 @abstract Computes SHAKE256(seed || nonce, 128) which is used to sample
           polynomials with small coefficients.

 @param seed  Random seed.
 @param nonce Single-byte nonce.
 @param out   Output buffer.
 */
CC_NONNULL_ALL
void cckyber_prf(const uint8_t seed[CCKYBER_SYM_NBYTES],
                 uint8_t nonce,
                 uint8_t out[128]);

/*! @function cckyber_rkprf
 @abstract Computes SHAKE256(z || ek, 32) to derive the implicit rejection key.

 @param z         Implicit rejection value.
 @param ek_nbytes Length of the encapsulated key in bytes.
 @param ek        Encapsulated key.
 @param out       Output buffer.
 */
CC_NONNULL_ALL
void cckyber_rkprf(const uint8_t z[CCKYBER_SYM_NBYTES],
                   size_t ek_nbytes,
                   const uint8_t *ek,
                   uint8_t out[CCKYBER_SK_NBYTES]);

/*! @function cckyber_indcpa_keypair
 @abstract Computes a public and private key as part of the CPA-secure
           public-key encryption scheme underlying Kyber.

 @param params  Kyber parameters.
 @param pubkey  Public key.
 @param privkey Private key.
 @param coins   Coins (randomness).
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cckyber_indcpa_keypair(const cckyber_params_t *params,
                           uint8_t *pubkey,
                           uint8_t *privkey,
                           const uint8_t coins[CCKYBER_SYM_NBYTES]);

/*! @function cckyber_indcpa_encrypt
 @abstract Encrypts a given message as part of the CPA-secure
           public-key encryption scheme underlying Kyber.

 @param params Kyber parameters.
 @param pubkey Public key.
 @param msg    Message to encrypt.
 @param coins  Coins (randomness).
 @param ct     Ciphertext.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cckyber_indcpa_encrypt(const cckyber_params_t *params,
                           const uint8_t *pubkey,
                           const uint8_t msg[CCKYBER_MSG_NBYTES],
                           const uint8_t coins[CCKYBER_SYM_NBYTES],
                           uint8_t *ct);

/*! @function cckyber_indcpa_encrypt_ws
 @abstract Encrypts a given message as part of the CPA-secure
           public-key encryption scheme underlying Kyber.

 @param ws     Workspace
 @param params Kyber parameters.
 @param pubkey Public key.
 @param msg    Message to encrypt.
 @param coins  Coins (randomness).
 @param ct     Ciphertext.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cckyber_indcpa_encrypt_ws(cc_ws_t ws,
                              const cckyber_params_t *params,
                              const uint8_t *pubkey,
                              const uint8_t msg[CCKYBER_MSG_NBYTES],
                              const uint8_t coins[CCKYBER_SYM_NBYTES],
                              uint8_t *ct);

/*! @function cckyber_indcpa_decrypt_ws
 @abstract Decrypts a given ciphertext as part of the CPA-secure
           public-key encryption scheme underlying Kyber.

 @param ws      Workspace
 @param params  Kyber parameters.
 @param privkey Private key.
 @param ct      Ciphertext to decrypt.
 @param msg     Decrypted output message.
 */
CC_NONNULL_ALL
void cckyber_indcpa_decrypt_ws(cc_ws_t ws,
                               const cckyber_params_t *params,
                               const uint8_t *privkey,
                               const uint8_t *ct,
                               uint8_t msg[CCKYBER_MSG_NBYTES]);

/*! @function cckyber_kem_keypair
 @abstract Generates a public and private key.

 @param params  Kyber parameters.
 @param pubkey  Output public key.
 @param privkey Output private key.
 @param rng     RNG instance.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cckyber_kem_keypair(const cckyber_params_t *params,
                        unsigned char *pubkey,
                        unsigned char *privkey,
                        struct ccrng_state *rng);

/*! @function cckyber_kem_keypair_coins
 @abstract Computes a public and private key for given coins (randomness).

 @param params  Kyber parameters.
 @param pubkey  Output public key.
 @param privkey Output private key.
 @param coins   Coins (randomness).

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cckyber_kem_keypair_coins(const cckyber_params_t *params,
                              uint8_t *pubkey,
                              uint8_t *privkey,
                              const uint8_t coins[2 * CCKYBER_SYM_NBYTES]);

/*! @function cckyber_kem_encapsulate
 @abstract Generates an encapsulated and shared key for a given public key.

 @param params Kyber parameters.
 @param pubkey Public key.
 @param ek     Output encapsulated key.
 @param sk     Output shared key.
 @param rng    RNG instance.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cckyber_kem_encapsulate(const cckyber_params_t *params,
                            const uint8_t *pubkey,
                            uint8_t *ek,
                            uint8_t *sk,
                            struct ccrng_state *rng);

/*! @function cckyber_kem_encapsulate_msg
 @abstract Computes an encapsulated and shared key for a given public key
           and message.

 @param params Kyber parameters.
 @param pubkey Public key.
 @param ek     Output encapsulated key.
 @param sk     Output shared key.
 @param msg    Message.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cckyber_kem_encapsulate_msg(const cckyber_params_t *params,
                                const uint8_t *pubkey,
                                uint8_t *ek,
                                uint8_t *sk,
                                const uint8_t msg[CCKYBER_SYM_NBYTES]);

/*! @function cckyber_kem_decapsulate
 @abstract Generates a shared key from a given encapsulated and private key.

 @param params  Kyber parameters.
 @param privkey Private key.
 @param ek      Encapsulated key.
 @param sk      Output shared key.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cckyber_kem_decapsulate(const cckyber_params_t *params,
                            const uint8_t *privkey,
                            const uint8_t *ek,
                            uint8_t *sk);

#endif /* _CORECRYPTO_CCKYBER_INTERNAL_H_ */
