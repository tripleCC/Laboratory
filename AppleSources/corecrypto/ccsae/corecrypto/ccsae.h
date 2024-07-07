/* Copyright (c) (2018-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#ifndef _CORECRYPTO_CCSAE_H_
#define _CORECRYPTO_CCSAE_H_

#include <corecrypto/ccec.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cch2c.h>

/*
 * The CoreCrypto SAE API.
 *
 * This protocol conforms to SAE authentication protocol as described in
 * [WPA3] IEEE P802.11-REVmdTM/D1.6, October 2018 part 11 which is based upon the
 * Dragonfly Key Exchange described in <https://tools.ietf.org/html/rfc7664>
 */

/*
 * SAE Output Key Sizes
 * If hunt-and-peck:
 *    len(kck) == 32
 *    len(pmk) == 32
 * If hash-to-curve:
 *    len(kck) == len(hash)
 *    len(pmk) == 32
 */
#define CCSAE_PMK_SIZE   32
#define CCSAE_PMKID_SIZE 16
#define CCSAE_HAP_KCK_SIZE 32

typedef enum {
    CCSAE_ALG_NONE, // Default value
    CCSAE_ALG_HAP,  // Hunt-and-peck
    CCSAE_ALG_H2C   // Hash-to-curve
} CCSAE_ALG_T;

#define CCSAE_NUM_CTX_CCN 9
#define CCSAE_MAX_IDENTITY_SIZE 16
#define CCSAE_MAX_PASSWORD_IDENTIFIER_SIZE 64

struct ccsae_ctx;
typedef struct ccsae_ctx *ccsae_ctx_t;
typedef const struct ccsae_ctx *ccsae_const_ctx_t;

/*
    The ccsae_ctx structure contains the core parameters necessary to perform the SAE
    protocol and should *NOT* be accessed directly.
*/
struct ccsae_ctx {
    ccec_const_cp_t cp;
    struct ccrng_state *rng;
    const struct ccdigest_info *di;
    uint8_t state;
    uint8_t iterations;
    CCSAE_ALG_T algorithm;
    const char *kck_pmk_label;
    const char *hunt_peck_label;
    uint8_t kck[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t pmk[CCSAE_PMK_SIZE];
    CC_ALIGNED(CCN_UNIT_SIZE) cc_unit ccn[];
};

/*! @function ccsae_sizeof_ctx
 @abstract Returns the size of a SAE context

 @param cp ECC parameters

 @return Size of a SAE context
 */
CC_NONNULL((1))
size_t ccsae_sizeof_ctx(ccec_const_cp_t cp);

/*! @function ccsae_sizeof_pt
 @abstract Returns the size of the PT value

 @param info Parameter for the hash-to-curve method

 @return Size of the PT value
 */
CC_NONNULL_ALL
size_t ccsae_sizeof_pt(const struct cch2c_info *info);

/*
 The below definition is provided for clients who declare their context as a global variable. Therefore,
 they cannot call a function to determine the correct size.

 sizeof(struct ccsae_ctx) + CCSAE_NUM_CTX_CCN * ccn_sizeof(256) is equivalent to ccsae_sizeof_ctx(ccec_cp_256()).
 */
#define CCSAE_SIZE_P256_SHA256 cc_ctx_n(struct ccsae_ctx, sizeof(struct ccsae_ctx) + CCSAE_NUM_CTX_CCN * ccn_sizeof_n(CCN256_N))

#define CCSAE_SIZE_P384_SHA384 cc_ctx_n(struct ccsae_ctx, sizeof(struct ccsae_ctx) + CCSAE_NUM_CTX_CCN * ccn_sizeof_n(CCN384_N))

#define ccsae_ctx_decl(_cp_, _name_) cc_ctx_decl(struct ccsae_ctx, ccsae_sizeof_ctx(_cp_), _name_)
#define ccsae_ctx_clear(_cp_, _name_) cc_clear(ccsae_sizeof_ctx(_cp_), _name_)

/*! @function ccsae_init
 @abstract Initialize a SAE context

 @param ctx SAE context
 @param cp  ECC parameters
 @param rng RNG state
 @param di  Digest paramaters

 @return CCERR_OK on success, non-zero on failure.

 @discussion P224 does not have a constant time square root operation and should not be used with
 the SAE protocol at this time.
 */
CC_NONNULL((1, 2, 3, 4))
int ccsae_init(ccsae_ctx_t ctx, ccec_const_cp_t cp, struct ccrng_state *rng, const struct ccdigest_info *di);

/*! @function ccsae_init_p256_sha256
 @abstract Initialize a SAE context using group 19 (NIST P-256) and sha256.

 @param ctx SAE context
 @param rng RNG state

 @return CCERR_OK on success, non-zero on failure.
 */
CC_NONNULL((1, 2))
int ccsae_init_p256_sha256(ccsae_ctx_t ctx, struct ccrng_state *rng);

/*! @function ccsae_init_p384_sha384
 @abstract Initialize a SAE context using group 20 (NIST P-384) and sha384.

 @param ctx SAE context
 @param rng RNG state

 @return CCERR_OK on success, non-zero on failure.
 */
CC_NONNULL((1, 2))
int ccsae_init_p384_sha384(ccsae_ctx_t ctx, struct ccrng_state *rng);

/*! @function ccsae_generate_h2c_pt
 @abstract Generate the secret element PT for use in H2C operations.

 @param info              Parameter for the hash-to-curve method
 @param ssid              The input SSID
 @param ssid_nbytes       Length of input SSID
 @param password          The input password
 @param password_nbytes   Length of the input password
 @param identifier        Optional password identifier
 @param identifier_nbytes Length of the input password identifier
 @param pt                The output PT

 @return CCERR_OK on success and any other value on failure.
*/
CC_NONNULL((1, 2, 4, 8))
int ccsae_generate_h2c_pt(const struct cch2c_info *info,
                          const uint8_t *ssid,
                          size_t ssid_nbytes,
                          const uint8_t *password,
                          size_t password_nbytes,
                          const uint8_t *identifier,
                          size_t identifier_nbytes,
                          uint8_t *pt);

/*! @function ccsae_generate_h2c_commit
 @abstract Generate a SAE commit given the PT

 @param ctx        SAE context
 @param A          Identity of the first participating party
 @param A_nbytes   Length of A
 @param B          Identity of the second participating party
 @param B_nbytes   Length of B
 @param pt         The input PT.
 @param pt_nbytes  Length of PT.
 @param commitment Output buffer for the commitment. Must have length equal to `ccsae_sizeof_commitment(ctx)`

 @return CCERR_OK on success and any other value on failure.
*/
CC_NONNULL_ALL
int ccsae_generate_h2c_commit(ccsae_ctx_t ctx,
                              const uint8_t *A,
                              size_t A_nbytes,
                              const uint8_t *B,
                              size_t B_nbytes,
                              const uint8_t *pt,
                              size_t pt_nbytes,
                              uint8_t *commitment);

/*! @function ccsae_generate_h2c_commit_init
 @abstract Start the commitment process

 @param ctx        SAE context
 @param A          Identity of the first participating party
 @param A_nbytes   Length of A
 @param B          Identity of the second participating party
 @param B_nbytes   Length of B
 @param pt         The input PT.
 @param pt_nbytes  Length of PT.

 @return CCERR_OK on success and any other value on failure.

 @discussion In contexts in which the execution time of a single function call is unimportant (i.e. most contexts), the function
 `ccsae_generate_h2c_commit` SHOULD be used instead. If execution time of a single function call is important, the init & finalize
 sequence of h2c commitment generation functions should be used.

 The proper sequence of function calls is as follows:
    int error = ccsae_generate_h2c_commit_init(ctx, A, A_nbytes, B, B_nbytes, pt, pt_nbytes);
    handle_error(error);
    error = ccsae_generate_h2c_commit_finalize(ctx, commitment);
    handle_error(error);
 */
CC_NONNULL_ALL
int ccsae_generate_h2c_commit_init(ccsae_ctx_t ctx,
                                   const uint8_t *A,
                                   size_t A_nbytes,
                                   const uint8_t *B,
                                   size_t B_nbytes,
                                   const uint8_t *pt,
                                   size_t pt_nbytes);

/*! @function ccsae_generate_h2c_commit_finalize
 @abstract Finalize the commitment process and output the commitment

 @param ctx        SAE context
 @param commitment Output buffer for the commitment. Must have length equal to `ccsae_sizeof_commitment(ctx)`

 @return CCERR_OK on success and any other value on failure.
 */
CC_NONNULL_ALL
int ccsae_generate_h2c_commit_finalize(ccsae_ctx_t ctx, uint8_t *commitment);

/*! @function ccsae_generate_commitment
 @abstract Generates a SAE commitment

 @param ctx               SAE context
 @param A                 Identity of the first participating party
 @param A_nbytes          Length of A
 @param B                 Identity of the second participating party
 @param B_nbytes          Length of B
 @param password          The input password
 @param password_nbytes   Length of the input password
 @param identifier        Optional password identifier
 @param identifier_nbytes Length of the input password identifier
 @param commitment        Output buffer for the commitment. Must have length equal to `ccsae_sizeof_commitment(ctx)`

 @return CCERR_OK on success, non-zero on failure.
 */
CC_NONNULL((1, 2, 4, 6, 10))
int ccsae_generate_commitment(ccsae_ctx_t ctx,
                              const uint8_t *A,
                              size_t A_nbytes,
                              const uint8_t *B,
                              size_t B_nbytes,
                              const uint8_t *password,
                              size_t password_nbytes,
                              const uint8_t *identifier,
                              size_t identifier_nbytes,
                              uint8_t *commitment);

/*! @function ccsae_generate_commitment_init
 @abstract Initialize a SAE context for partial commitment generation.

 @param ctx                   SAE context

 @return CCERR_OK on success, non-zero on failure.

 @discussion In contexts in which the execution time of a single function call is unimportant (i.e. most contexts), the function
 `ccsae_generate_commitment` SHOULD be used instead. If execution time of a single function call is important, the init, partial,
 finalize sequence of commitment generation functions should be used. `ccsae_generate_commitment_partial` will be called
 repeatedly as it returns `CCSAE_GENERATE_COMMIT_CALL_AGAIN`. When it returns `CCERR_OK`, the commitment value can be extracted by
 calling `ccsae_generate_commitment_finalize`.

 The proper sequence of function calls is as follows:
    int error = ccsae_generate_commitment_init(ctx);
    handle_error(error);
    int max_iterations_per_call = <x>; // Some number used to reduce the amount of work in each
 `ccsae_generate_commitment_partial`. A smaller number implies a larger number of function calls

    int rv;
    do
    {
        rv = ccsae_generate_commitment_partial(ctx, ..., max_iterations_per_call);
    } while (rv == CCSAE_GENERATE_COMMIT_CALL_AGAIN);

    if (rv == CCERR_OK) {
        ccsae_generate_commitment_finalize(ctx, out_buffer);
    } else {
        handle_error(rv);
    }
 */
CC_NONNULL_ALL
int ccsae_generate_commitment_init(ccsae_ctx_t ctx);

/*! @function ccsae_generate_commitment_partial
 @abstract Generates a SAE commitment

 @param ctx                  SAE context
 @param A                    Identity of the first participating party
 @param A_nbytes             Length of A
 @param B                    Identity of the second participating party
 @param B_nbytes             Length of B
 @param password             The input password
 @param password_nbytes      Length of the input password
 @param identifier           Optional password identifier
 @param identifier_nbytes    Length of the input password identifier
 @param max_num_iterations   Maximum number of hash-to-curve loop iterations to perform in this call.

 @return CCERR_OK on completion, CCSAE_GENERATE_COMMIT_CALL_AGAIN to indicate further calls are necessary, and non-zero on
 failure.

 @discussion See `ccsae_generate_commitment_init`
 */
CC_NONNULL((1, 2, 4, 6))
int ccsae_generate_commitment_partial(ccsae_ctx_t ctx,
                                      const uint8_t *A,
                                      size_t A_nbytes,
                                      const uint8_t *B,
                                      size_t B_nbytes,
                                      const uint8_t *password,
                                      size_t password_nbytes,
                                      const uint8_t *identifier,
                                      size_t identifier_nbytes,
                                      uint8_t max_num_iterations);

/*! @function ccsae_generate_commitment_finalize
@abstract Finalize and output a SAE commitment

@param ctx         SAE context
@param commitment  Output buffer for the commitment. Must have length equal to `ccsae_sizeof_commitment(ctx)`

@return CCERR_OK on success, non-zero on failure.

@discussion See `ccsae_generate_commitment_init`
 */
int ccsae_generate_commitment_finalize(ccsae_ctx_t ctx, uint8_t *commitment);

/*! @function ccsae_verify_commitment
 @abstract Verifies a SAE commitment

 @param ctx                 SAE context
 @param peer_commitment     Input peer commitment. This is the peer scalar concatenated with the peer element.
                            Must have length equal to `ccsae_sizeof_commitment(ctx)`

 @return CCERR_OK on verification success, non-zero on failure.
 */
CC_NONNULL((1, 2))
int ccsae_verify_commitment(ccsae_ctx_t ctx, const uint8_t *peer_commitment);

/*! @function ccsae_generate_confirmation
 @abstract Generates a SAE confirmation

 @param ctx                  SAE context
 @param send_confirm_counter Send-Confirm field (see 9.4.1.37 of [WPA3])
 @param confirmation         Output buffer for the confirmation. Must have length equal to `ccsae_sizeof_confirmation(ctx)`.

 @return CCERR_OK on success, non-zero on failure.
 */
CC_NONNULL((1, 2, 3))
int ccsae_generate_confirmation(ccsae_ctx_t ctx, const uint8_t *send_confirm_counter, uint8_t *confirmation);

/*! @function ccsae_verify_confirmation
 @abstract Verifies a SAE confirmation

 @param ctx                        SAE context
 @param peer_send_confirm_counter  Send-Confirm field (see 9.4.1.37 of [WPA3])
 @param peer_confirmation          Input peer confirmation. Must have length equal to `ccsae_sizeof_confirmation(ctx)`.

 @return CCERR_OK on verification success, non-zero on failure.
 */
CC_NONNULL((1, 2, 3))
int ccsae_verify_confirmation(ccsae_ctx_t ctx, const uint8_t *peer_send_confirm_counter, const uint8_t *peer_confirmation);

/*! @function ccsae_sizeof_kck
 
 @param ctx SAE Context
 
 @return The size of the key `kck` in bytes when `ccsae_generate_commitment` or `ccsae_generate_commitment_init/ccsae_generate_commitment_partial/ccsae_generate_commitment_finalize` are utilized.
 */
CC_NONNULL_ALL
size_t ccsae_sizeof_kck(ccsae_const_ctx_t ctx);

/*! @function ccsae_sizeof_kck_h2c
 
 @param ctx SAE Context
 
 @return The size of the key `kck` in bytes when `ccsae_generate_h2c_commit` or `ccsae_generate_h2c_commit_init/ccsae_generate_h2c_commit_finalize` are utilized.
 */
CC_NONNULL_ALL
size_t ccsae_sizeof_kck_h2c(ccsae_const_ctx_t ctx);

/*! @function ccsae_get_keys
 @abstract Grab the keys from a SAE context

 @param ctx   SAE context
 @param kck   Output buffer for the KCK with size `ccsae_sizeof_kck` or `ccsae_sizeof_kck_h2c`  bytes. See the documentation of `ccsae_sizeof_kck` and `ccsae_sizeof_kck_h2c` for more info.
 @param pmk   Output buffer for the PMK with size CCSAE_PMK_SIZE bytes.
 @param pmkid Output buffer for the PMKID with size CCSAE_PMKID_SIZE bytes.

 @return CCERR_OK on verification success, non-zero on failure.
 */
CC_NONNULL((1, 2, 3, 4))
int ccsae_get_keys(ccsae_const_ctx_t ctx, uint8_t *kck, uint8_t *pmk, uint8_t *pmkid);

/*! @function ccsae_sizeof_commitment
 @abstract Get the byte size of a commitment

 @param ctx SAE context

 @return Byte size of a commitment.
 */
CC_NONNULL((1))
size_t ccsae_sizeof_commitment(ccsae_const_ctx_t ctx);

/*! @function ccsae_sizeof_confirmation
 @abstract Get the byte size of a confirmation

 @param ctx SAE context

 @return Byte size of a confirmation.
 */
CC_NONNULL((1))
size_t ccsae_sizeof_confirmation(ccsae_const_ctx_t ctx);

#endif /* _CORECRYPTO_CCSAE_H_ */
