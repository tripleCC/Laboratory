/* Copyright (c) (2011,2015-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDH_INTERNAL_H_
#define _CORECRYPTO_CCDH_INTERNAL_H_

#include <corecrypto/ccdh.h>
#include "cczp_internal.h"

#define ccdh_gp_decl_n(_n_)                                 \
struct {                                                    \
    struct cczp_hd hp;                                      \
    cc_unit p[(_n_)];         /* Prime */                   \
    cc_unit p0inv;            /* -p[0]^(-1) mod 2^w */      \
    cc_unit r2[(_n_)];        /* R^(2*n*w) (mod p) */       \
    cc_unit g[(_n_)];         /* Generator */               \
    cc_unit q[(_n_)];         /* Order */                   \
    cc_size l;                /* Size of the private key */ \
}

#define ccdh_gp_decl_static(_bits_) ccdh_gp_decl_n(ccn_nof(_bits_))
#define CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH (cc_size)160
#define CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH (cc_size)0 // 0 represents the largest possible exponent size

#define CCDH_GP_ZP(_gp_)        ((cczp_t)(_gp_))

#define ccdh_pub_ctx_ws(_n_)   (ccn_nof_sizeof(struct ccdh_pub_ctx) + 1 * (_n_))
#define ccdh_full_ctx_ws(_n_)  (ccn_nof_sizeof(struct ccdh_full_ctx) + 2 * (_n_))

// Workspace helpers.
#define CCDH_ALLOC_PUB_WS(ws, n) (ccdh_pub_ctx_t)CC_ALLOC_WS(ws, ccdh_pub_ctx_ws(n))
#define CCDH_ALLOC_FULL_WS(ws, n) (ccdh_full_ctx_t)CC_ALLOC_WS(ws, ccdh_full_ctx_ws(n))

CC_INLINE CC_NONNULL_ALL
cczp_const_t ccdh_gp_zp(ccdh_const_gp_t gp)
{
    return (cczp_const_t)gp;
}

int ccdh_generate_private_key(ccdh_const_gp_t gp, cc_unit *x, struct ccrng_state *rng);

int ccdh_generate_private_key_ws(cc_ws_t ws, ccdh_const_gp_t gp, cc_unit *x, struct ccrng_state *rng);

int ccdh_check_pub_ws(cc_ws_t ws, ccdh_const_gp_t gp, ccdh_pub_ctx_t public_key);

int ccdh_power_blinded_ws(cc_ws_t ws, struct ccrng_state *blinding_rng,
                          ccdh_const_gp_t gp, cc_unit *r, const cc_unit *s,
                          size_t ebitlen, const cc_unit *e);

/*!
 @function   ccdh_pairwise_consistency_check_ws
 @abstract   Does a DH with a constant key to confirm the newly generated key is
 correct.
 @param      ws             Workspace
 @param      gp             Group parameters
 @param      rng            For key generation and internal countermeasures
 @param      key            DH key pair
 @return     true if no error, false otherwise.
 */
bool ccdh_pairwise_consistency_check_ws(cc_ws_t ws,
                                        ccdh_const_gp_t gp,
                                        struct ccrng_state *rng,
                                        ccdh_full_ctx_t key);

int ccdh_compute_shared_secret_ws(cc_ws_t ws,
                                  ccdh_full_ctx_t private_key,
                                  ccdh_pub_ctx_t public_key,
                                  size_t *computed_shared_secret_len,
                                  uint8_t *computed_shared_secret,
                                  struct ccrng_state *blinding_rng);

/*!
 * @function ccdh_copy_gp
 *
 *  Function to copy a source group to a pre-declared dest group of the same size.
 *
 * @param dest
 * ccdh_gp_t of size n where you'd like the group copied.
 *
 * @param src
 * ccdh_gp_t of size n which you would like copied from
 *
 * @return CCDH_DOMAIN_PARAMETER_MISMATCH on non-matching group sizes or CCERROK otherwise.
 */
int ccdh_copy_gp(ccdh_gp_t dest, const ccdh_const_gp_t src);

/*!
 * @function ccdh_gp_ramp_exponent
 *
 *  Function to ramp a groups exponent bit-length to at least l. More precisely,
 *  If the group secret-key bit-length is already set to max-length, or a value greater than l, the current is maintained
 *  If the group secret-key bit length is less than l, the value is set to l
 *  Finally, regardless of value, if the secret-key bit-length returned would be less than a predefined secure value (currently 160),
 *  then the value is set to 160.
 
 * @param l
 * The number of bits in DH secret-keys
 *
 * @param gp
 * The group whose exponent you would like to ramp.
 */
void ccdh_ramp_gp_exponent(cc_size l, ccdh_gp_t gp);

/*!
 * @function ccdh_lookup_gp
 *
 *   Lookup a list of known `ccdh_const_gp_t` structs given prime `p` and generator `g`.
 *   Function to verify that group parameters prime p and generator g are on a list of known DH group paramters.
 *   Returns the known group if it exists, or NULL otherwise.
 *
 * @param pn
 * Length of prime `p` in cc_unit
 *
 * @param p
 * Pointer to cc_unit array containing the group prime. Prime p is provisioned in corecrypto cc_unit format.
 *
 * @param gn
 * Length of generator `g` in cc_unit
 *
 * @param g
 * Pointer to cc_unit array containing the group generator. Generator g is provisioned in cc_unit format.
 *
 * @return `ccdh_const_gp_t` if `p` and `g` are from a known group, and NULL otherwise.
 */
CC_NONNULL((2,4))

ccdh_const_gp_t ccdh_lookup_gp(cc_size pn, const cc_unit *p, cc_size gn, const cc_unit *g);

/*
 * Group parameters must be well chosen to avoid serious security issues.
 *  a) ccdh_init_gp with l>0 is to be used for group parameter where p is a safe prime.
 *     l should be at least twice the security level desired (128bit security => l=256).
 *     If you are not sure, set l=0, it is slow but it is safe against attacks using the
 *     Pohlig-Hellman algorithm for example.
 *  b) ccdh_init_gp_with_order is to be used when the group prime is not a safe prime:
 *     the order is necessary to avoid small subgroup attacks and generate the private key
 *     efficiently
 */
CC_NONNULL((1, 3, 4))
int ccdh_init_gp(ccdh_gp_t gp, cc_size n,
                 const cc_unit *p,
                 const cc_unit *g,
                 cc_size l);

CC_NONNULL((1, 3, 4, 5))
int ccdh_init_gp_with_order(ccdh_gp_t gp, cc_size n,
                            const cc_unit *p,
                            const cc_unit *g,
                            const cc_unit *q);

/*!
 * @function ccdh_valid_shared_secret
 *
 *  Function to ensure a computed DH shared secret is not 0,1 or p-1 for the prime p defining the modulus in which operations are performed.
 
 * @param n
 * The size of the shared secret s
 *
 * @param s
 * The computed shared secret.
 *
 * @param gp
 * The group defining arithment for the DH operation
 *
 * @return true if p is not 0, 1 or p-1, false otherwise.
 */
CC_NONNULL_ALL
bool ccdh_valid_shared_secret(cc_size n, const cc_unit *s, ccdh_const_gp_t gp);

/*!
 * @function ccdh_generate_private_key_bitlen
 *
 *  Returns the bit length of a private key generated for group gp.
 
 * @param gp
 * Group to generate a private key for.
 */
CC_NONNULL_ALL
size_t ccdh_generate_private_key_bitlen(ccdh_const_gp_t gp);

#endif /* _CORECRYPTO_CCDH_INTERNAL_H_ */
