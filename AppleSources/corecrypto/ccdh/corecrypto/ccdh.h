/* Copyright (c) (2011-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDH_H_
#define _CORECRYPTO_CCDH_H_

#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>

CC_PTRCHECK_CAPABLE_HEADER()

struct ccdh_gp {
    __CCZP_ELEMENTS_DEFINITIONS()
} CC_ALIGNED(CCN_UNIT_SIZE);

/* A ccdh_gp_t is a pointer to a set of DH parameters.
 The first entry is a (short) prime field. */
typedef struct ccdh_gp *ccdh_gp_t;

/* A ccdh_const_gp_t is a const pointer to a set of DH parameters.
 The first entry is a const prime field. */
typedef const struct ccdh_gp *ccdh_const_gp_t;

/* The ccdh_full_ctx_decl macro allocates an array of ccdh_full_ctx */
struct ccdh_full_ctx {
    ccdh_const_gp_t gp;
    CC_ALIGNED(16) cc_unit xy[];
} CC_ALIGNED(16);

/* The ccdh_pub_ctx_decl macro allocates an array of ccdh_pub_ctx */
struct ccdh_pub_ctx {
    ccdh_const_gp_t gp;
    CC_ALIGNED(16) cc_unit xy[];
} CC_ALIGNED(16);

/* A ccdh_full_ctx_t is a pointer to a dh key pair.  It should be
 allocated to be sizeof(ccdh_full_ctx_decl()) bytes. Each of the
 ccns within a dh key is always ccdh_ctx_n() cc_units long. */

typedef struct ccdh_full_ctx *ccdh_full_ctx_t;
typedef struct ccdh_pub_ctx *ccdh_pub_ctx_t;


/* Return the size of an ccdh_full_ctx where each ccn is _size_ bytes. */
/* Full has x and y */
#define ccdh_full_ctx_size(_size_)  (sizeof(struct ccdh_full_ctx) + 2 * (_size_))
/* Pub has only y */
#define ccdh_pub_ctx_size(_size_)   (sizeof(struct ccdh_pub_ctx) + 1 * (_size_))

/* Declare a fully scheduled dh key.  Size is the size in bytes each ccn in
   the key.  For example to declare (on the stack or in a struct) a 1024 bit
   dh public key named foo use ccdh_pub_ctx_decl(ccn_sizeof(1024), foo). */
#define ccdh_full_ctx_decl(_size_, _name_)  cc_ctx_decl(struct ccdh_full_ctx, ccdh_full_ctx_size(_size_), _name_)
#define ccdh_pub_ctx_decl(_size_, _name_)   cc_ctx_decl(struct ccdh_pub_ctx, ccdh_pub_ctx_size(_size_), _name_)


#define ccdh_pub_ctx_clear(_size_, _name_)   cc_clear(ccdh_pub_ctx_size(_size_), _name_)
#define ccdh_full_ctx_clear(_size_, _name_)  cc_clear(ccdh_full_ctx_size(_size_), _name_)
/* Declare storage for a fully scheduled dh key for a given set of dh parameters. */
#define ccdh_full_ctx_decl_gp(_gp_, _name_) ccdh_full_ctx_decl(ccdh_ccn_size(_gp_), _name_)
#define ccdh_pub_ctx_decl_gp(_gp_, _name_)  ccdh_pub_ctx_decl(ccdh_ccn_size(_gp_), _name_)

/* Return the length of the prime for gp in bits. */
#define ccdh_gp_prime_bitlen(GP)  (cczp_bitlen((cczp_const_t)(GP)))

/* Return the sizeof the prime for gp. */
#define ccdh_gp_prime_size(GP)  (ccdh_ccn_size(GP))

/* Group parameters accessors */
/* If you set the structure manually, you must set it to zero to be
 future proof */
#define CCDH_GP_N(_gp_)         (CCZP_N(_gp_))
#define CCDH_GP_PRIME(_gp_)     (CCZP_PRIME(_gp_))

#define CCDH_GP_G(_gp_)         (CCDH_GP_PRIME(_gp_) + CCDH_GP_N(_gp_) + 1 + CCDH_GP_N(_gp_))
#define CCDH_GP_Q(_gp_)         (CCDH_GP_G(_gp_) + CCDH_GP_N(_gp_))
#define CCDH_GP_L(_gp_)         (*((CCDH_GP_Q(_gp_) + CCDH_GP_N(_gp_)))) // Size of the private key in bit.
/* l must be chosen wisely to avoid the private key to be recoverable with the Pohlig-Hellman algorithm for example. "Small" l is only possible for special groups for example when p is a safe prime. */

/* Return the size of a ccdh_gp where the prime is of _size_ bytes. */
size_t ccdh_gp_size(size_t nbytes);

/* Declare a gp  */
#define ccdh_gp_decl(_size_, _name_)  cc_ctx_decl(struct ccdh_gp, ccdh_gp_size(_size_), _name_)

/* lvalue accessors to ccdh_ctx fields. (only a ccdh_full_ctx_t has y). */
/* gp: group parameter */
#define ccdh_ctx_gp(KEY)     (((ccdh_pub_ctx_t)(KEY))->gp)
/* n: size of group */
#define ccdh_ctx_n(KEY)      (ccdh_gp_n(ccdh_ctx_gp(KEY)))
/* prime: group prime */
#define ccdh_ctx_prime(KEY)  (ccdh_gp_prime(ccdh_ctx_gp(KEY)))
/* y: the public key */
#define ccdh_ctx_y(KEY)    ((KEY)->xy)
/* x: the private key */
#define ccdh_ctx_x(KEY)    (ccdh_ctx_y(KEY) + 1 * ccdh_ctx_n(KEY))  

/*!
 @function ccdh_ctx_public
 @return Return the public context associated with the full context input
 */
CC_NONNULL_ALL
ccdh_pub_ctx_t ccdh_ctx_public(ccdh_full_ctx_t key);

/*!
 @function ccdh_ctx_init
 @abstract Initialize a public or public portion of a full context with the given gp.
 This must be called before using other functions.
 */
CC_NONNULL((1))
void ccdh_ctx_init(ccdh_const_gp_t gp, ccdh_pub_ctx_t key);


/*!
 @function ccdh_gp_n
 @return The count of cc_units for the given gp.
 */
CC_NONNULL((1))
cc_size ccdh_gp_n(ccdh_const_gp_t gp);

#if CC_PTRCHECK

cc_unavailable()
const cc_unit *cc_indexable ccdh_gp_prime(ccdh_const_gp_t gp);

cc_unavailable()
const cc_unit *cc_indexable ccdh_gp_g(ccdh_const_gp_t gp);

cc_unavailable()
const cc_unit *cc_indexable ccdh_gp_order(ccdh_const_gp_t gp);

cc_unavailable()
size_t ccdh_gp_l(ccdh_const_gp_t gp);

cc_unavailable()
size_t ccdh_gp_order_bitlen(ccdh_const_gp_t gp);

#else

/*!
 @function ccdh_gp_prime
 @return The prime for a given gp.
 */
CC_NONNULL((1))
const cc_unit *cc_indexable ccdh_gp_prime(ccdh_const_gp_t gp);

/*!
 @function ccdh_gp_g
 @return The generator for a given gp.
 */
CC_NONNULL((1))
const cc_unit *cc_indexable ccdh_gp_g(ccdh_const_gp_t gp);

/*!
 @function ccdh_gp_order
 @return The order for a given gp.
 */
CC_NONNULL((1))
const cc_unit *cc_indexable ccdh_gp_order(ccdh_const_gp_t gp);

/*!
 @function ccdh_gp_l
 @return The bitlength of exponents for a given gp.
 */
CC_NONNULL((1))
size_t ccdh_gp_l(ccdh_const_gp_t gp);

/*!
 @function ccdh_gp_order_bitlen
 @return The bitlength of the order for a given gp.
 */
CC_NONNULL((1))
size_t ccdh_gp_order_bitlen(ccdh_const_gp_t gp);

#endif

/*!
 @function ccdh_ccn_size
 @return The bytelength of a cc_unit* for a given gp.
 */
CC_NONNULL((1))
size_t ccdh_ccn_size(ccdh_const_gp_t gp);

/*! @function ccdh_init_gp_from_bytes
 @abstract Import group parameters from big endian byte array to corecrypto representation

 @discussion
    Group parameters must be well chosen to avoid serious security issues.
      If the group prime is not a safe prime, the order MUST be provided to avoid small subgroup attacks
      If the group prime is a safe prime, l should be at least twice the security level desired (128bit security => l=256).
          If you are not sure, set l=0, it is slow but it is safe against attacks using the
          Pohlig-Hellman algorithm for example.

 @param gp allocated buffer for the group parameter. Typically defined as ccdh_gp_decl(ccn_sizeof_n(n), gp);
 @param n number of cc_units holding the prime, typically ccn_nof(<bit size>) or ccn_nof_size(<byte size>)
 @param p_nbytes number of bytes in `p` storage.
 @param p pointer to p, the group prime, in big endian
 @param g_nbytes number of bytes in `g` storage.
 @param g pointer to g, the group generator, in big endian
 @param q_nbytes number of bytes in `q` storage.
 @param q pointer to q, the group order, in big endian (optional)
 @param l size of the private exponent, if you are not sure, set l=0, it is slow but it is safe against attacks

 @return CCERR_OK on success, and non-zero on failure. See cc_error.h for details.
*/
CC_NONNULL((1, 4, 6))
int ccdh_init_gp_from_bytes(ccdh_gp_t gp, cc_size n,
                            size_t p_nbytes, const uint8_t *cc_counted_by(p_nbytes) p,
                            size_t g_nbytes, const uint8_t *cc_counted_by(g_nbytes) g,
                            size_t q_nbytes, const uint8_t *cc_counted_by(q_nbytes) q,
                            cc_size l);

/* 
 * Generate a DH private/public key pair from the group parameter 
 */
CC_NONNULL((1, 2))
int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng,
                      ccdh_full_ctx_t key);

/* Leading bytes of computed_shared_secret (a.k.a. Z) that contain all zero bits 
 are stripped before it is used as the shared secret. Match common specs such as TLS */
CC_NONNULL_ALL
int ccdh_compute_shared_secret(ccdh_full_ctx_t private_key,
                               ccdh_pub_ctx_t public_key,
                               size_t *computed_shared_secret_nbytes,
                               uint8_t *computed_shared_secret,
                               struct ccrng_state *blinding_rng);

/* Import a public key. The imported key is an Octet String, as defined in PKCS#3 */
CC_NONNULL((1, 3))
int ccdh_import_pub(ccdh_const_gp_t gp, size_t in_nbytes, const uint8_t *cc_counted_by(in_nbytes) in,
                    ccdh_pub_ctx_t key);

/* Import a private key. The imported key is an Octet String, as defined in PKCS#3 */
CC_NONNULL((1, 3))
int ccdh_import_priv(ccdh_const_gp_t gp, size_t in_nbytes, const uint8_t *cc_counted_by(in_nbytes) in,
                     ccdh_full_ctx_t key);

/* Import a private key. The imported key is an Octet String, as defined in PKCS#3 */
CC_NONNULL((1, 3))
int ccdh_import_full(ccdh_const_gp_t gp,
                     size_t in_priv_nbytes, const uint8_t *cc_counted_by(in_priv_nbytes) in_priv,
                     size_t in_pub_nbytes,  const uint8_t *cc_counted_by(in_pub_nbytes) in_pub,
                     ccdh_full_ctx_t key);

/* Return the sizeof a buffer needed to exported public key to. */
/*!
 @function ccdh_export_pub_size
 @returns Return the size of a buffer in bytes needed to exported public key
 */
CC_NONNULL((1))
size_t ccdh_export_pub_size(ccdh_pub_ctx_t key);

/* Export public key to out. Out must be ccdh_export_pub_size(key) bytes long.
   The key is exported as an Octet String, as defined in PKCS#3 */
CC_NONNULL((1, 2))
void ccdh_export_pub(ccdh_pub_ctx_t key, void *cc_unsafe_indexable out);

/* 
 * ASN.1/DER glue from PKCS #3 :
 * prime p, generator g, and optional privateValueLength l
 */

CC_NONNULL((1))
size_t ccder_encode_dhparams_size(const ccdh_const_gp_t gp);

CC_NONNULL((1, 2, 3))
uint8_t * ccder_encode_dhparams(const ccdh_const_gp_t gp, uint8_t *cc_ended_by(der_end) der, uint8_t *der_end);

/* CCZP_N(gpfoo.zp) must be set before decoding */
CC_NONNULL((1, 2))
const uint8_t *ccder_decode_dhparams(ccdh_gp_t gp, const uint8_t *cc_ended_by(der_end) der, const uint8_t *der_end);

/* returns the n needed for ccdh_gp_decl/heap allocation of a ccdh_gp_t, can be larger then the actual size used */
CC_NONNULL((1))
cc_size ccder_decode_dhparam_n(const uint8_t *cc_ended_by(der_end) der, const uint8_t *der_end);

#endif /* _CORECRYPTO_CCDH_H_ */
