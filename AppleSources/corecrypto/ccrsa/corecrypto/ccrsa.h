/* Copyright (c) (2010-2012,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRSA_H_
#define _CORECRYPTO_CCRSA_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include <corecrypto/cc_fault_canary.h>

CC_PTRCHECK_CAPABLE_HEADER()

// Apple does not generate keys of greater than 4096 bits
// This limit is relaxed to accommodate potential third-party consumers
#define CCRSA_KEYGEN_MAX_NBITS 8192

struct ccrsa_full_ctx {
    __CCZP_ELEMENTS_DEFINITIONS(pb_)
} CC_ALIGNED(CCN_UNIT_SIZE);

struct ccrsa_pub_ctx {
    __CCZP_ELEMENTS_DEFINITIONS(pb_)
} CC_ALIGNED(CCN_UNIT_SIZE);

typedef struct ccrsa_full_ctx* ccrsa_full_ctx_t;
typedef struct ccrsa_pub_ctx* ccrsa_pub_ctx_t;

/*
 struct ccrsa_pub_ctx {
     cczp zm;
     cc_unit m[n];
     cc_unit m0inv;
     cc_unit mr2[n];
     cc_unit e[n];
 }

 struct ccrsa_priv_ctx {
     cc_unit d[n];        // e^(-1) mod lcm(p-1, q-1)

     cczp zp;
     cc_unit p[n/2+1];
     cc_unit p0inv;
     cc_unit pr2[n/2+1];

     cczp zq;
     cc_unit q[n/2+1];
     cc_unit q0inv;
     cc_unit qr2[n/2+1];

     cc_unit dp[n/2+1];   // d mod (p-1)
     cc_unit dq[n/2+1];   // d mod (q-1)
     cc_unit qinv[n/2+1]; // q^(-1) mod p
 }

 struct ccrsa_full_ctx {
     struct ccrsa_pub_ctx;
     struct ccrsa_priv_ctx;
 }
 */

// Compute the internal structure size in bytes based on key (i.e. modulus) byte size.
#define ccrsa_pub_ctx_size(_nbytes_)   (sizeof(struct cczp) + CCN_UNIT_SIZE + 3 * ccn_sizeof_size(_nbytes_))
#define ccrsa_priv_ctx_size(_nbytes_)  (ccn_sizeof_size(_nbytes_) + (sizeof(struct cczp) + CCN_UNIT_SIZE) * 2 + 7 * ccn_sizeof_n(ccn_nof_size(_nbytes_) / 2 + 1))
#define ccrsa_full_ctx_size(_nbytes_)  (ccrsa_pub_ctx_size(_nbytes_) + ccrsa_priv_ctx_size(_nbytes_))

#define ccrsa_pub_ctx_ws(_n_) ccn_nof_size(ccrsa_pub_ctx_size(ccn_sizeof_n(_n_)))
#define ccrsa_full_ctx_ws(_n_) ccn_nof_size(ccrsa_full_ctx_size(ccn_sizeof_n(_n_)))

// Declare structure based on key byte size.
#define ccrsa_full_ctx_decl(_nbytes_, _name_)   cc_ctx_decl(struct ccrsa_full_ctx, ccrsa_full_ctx_size(_nbytes_), _name_)
#define ccrsa_full_ctx_clear(_nbytes_, _name_)  cc_clear(ccrsa_full_ctx_size(_nbytes_), _name_)
#define ccrsa_pub_ctx_decl(_nbytes_, _name_)    cc_ctx_decl(struct ccrsa_pub_ctx, ccrsa_pub_ctx_size(_nbytes_), _name_)
#define ccrsa_pub_ctx_clear(_nbytes_, _name_)   cc_clear(ccrsa_pub_ctx_size(_nbytes_), _name_)

// Declare structure based on key bit size.
#define ccrsa_full_ctx_decl_nbits(_nbits_, _name_)   cc_ctx_decl(struct ccrsa_full_ctx, ccrsa_full_ctx_size(ccn_sizeof(_nbits_)), _name_)
#define ccrsa_full_ctx_clear_nbits(_nbits_, _name_)  cc_clear(ccrsa_full_ctx_size(ccn_sizeof(_nbits_)), _name_)
#define ccrsa_pub_ctx_decl_nbits(_nbits_, _name_)    cc_ctx_decl(struct ccrsa_pub_ctx, ccrsa_pub_ctx_size(ccn_sizeof(_nbits_)), _name_)
#define ccrsa_pub_ctx_clear_nbits(_nbits_, _name_)   cc_clear(ccrsa_pub_ctx_size(ccn_sizeof(_nbits_)), _name_)

// Declare structure based number of cc_units. Not a typical use case. Size depends on processor.
#define ccrsa_full_ctx_decl_n(_nunits_, _name_)   cc_ctx_decl(struct ccrsa_full_ctx, ccrsa_full_ctx_size(ccn_sizeof_n(_nunits_)), _name_)
#define ccrsa_full_ctx_clear_n(_nunits_, _name_)  cc_clear(ccrsa_full_ctx_size(ccn_sizeof_n(_nunits_)), _name_)
#define ccrsa_pub_ctx_decl_n(_nunits_, _name_)    cc_ctx_decl(struct ccrsa_pub_ctx, ccrsa_pub_ctx_size(ccn_sizeof_n(_nunits_)), _name_)
#define ccrsa_pub_ctx_clear_n(_nunits_, _name_)   cc_clear(ccrsa_pub_ctx_size(ccn_sizeof_n(_nunits_)), _name_)

// Accessors to ccrsa full and public key fields. */
// The offsets are computed using pb_ccn. If any object other than ccrsa_full_ctx_t
// or ccrsa_pub_ctx_t is passed to the macros, compiler error is generated.



#define ccrsa_ctx_zm(_ctx_)        ((struct cczp* cc_single)(_ctx_))
#define ccrsa_ctx_n(_ctx_)         (ccrsa_ctx_zm(_ctx_)->n)

#define ccrsa_ctx_m(_ctx_)         ((cc_unit *)cc_unsafe_forge_bidi_indexable((_ctx_)->pb_ccn, ccn_sizeof_n(ccrsa_ctx_n(_ctx_))))

// Forge a bixi indexable at (_ctx_->pb_cnn + _offset_), of size in bytes _nbytes_.
#define ccrsa_unsafe_forge_bidi_indexable(_ctx_, _nbytes_, _offset_) ((cc_unit *)cc_unsafe_forge_bidi_indexable((cc_unit *)cc_unsafe_forge_bidi_indexable((_ctx_)->pb_ccn, _nbytes_ + ccn_sizeof_n(_offset_)) + _offset_, _nbytes_))

#define ccrsa_ctx_e(_ctx_)         ccrsa_unsafe_forge_bidi_indexable(_ctx_, ccn_sizeof_n(ccrsa_ctx_n(_ctx_)), 2 * ccrsa_ctx_n(_ctx_) + 1)
#define ccrsa_ctx_d(_ctx_)         ccrsa_unsafe_forge_bidi_indexable(_ctx_, ccn_sizeof_n(ccrsa_ctx_n(_ctx_)), 3 * ccrsa_ctx_n(_ctx_) + 1)



// accessors to ccrsa private key fields
#define ccrsa_ctx_private_zq(FK)   ((cczp_t)(ccrsa_ctx_private_zp(FK)->ccn + 2 * ccrsa_ctx_private_zp(FK)->n + 1))
#define ccrsa_ctx_private_dp(FK)   (ccrsa_ctx_private_zq(FK)->ccn + 2 * ccrsa_ctx_private_zp(FK)->n + 1)
#define ccrsa_ctx_private_dq(FK)   (ccrsa_ctx_private_dp(FK) + ccrsa_ctx_private_zp(FK)->n)
#define ccrsa_ctx_private_qinv(FK) (ccrsa_ctx_private_dq(FK) + ccrsa_ctx_private_zp(FK)->n)

cczp_t ccrsa_ctx_private_zp(ccrsa_full_ctx_t fk);

/*!
 @function   ccrsa_ctx_public
 @abstract   gets the public key from full key
 @param      fk      RSA full key
 @result     Returns RSA public ker
 */

ccrsa_pub_ctx_t ccrsa_ctx_public(ccrsa_full_ctx_t fk);

/*!
@function   ccrsa_pubkeylength
@abstract   Compute the actual bit length of the RSA key (bit length of the modulus)
@param      pubk  An initialized RSA public key
@result     bit length of the RSA key
*/
CC_NONNULL_ALL
size_t ccrsa_pubkeylength(ccrsa_pub_ctx_t pubk);

/* PKCS1 pad_markers */
#define CCRSA_PKCS1_PAD_SIGN     1
#define CCRSA_PKCS1_PAD_ENCRYPT  2

/*!
@function   ccrsa_init_pub
@abstract   Initialize an RSA public key structure based on modulus and exponent. Values are copied into the structure.
@param      pubk   allocated public key structure (see requirements below)
@param      modulus  cc_unit array of the modulus
@param      exponent  cc_unit array of the exponent
@result     CCERR_OK if no error
 
@discussion ccrsa_ctx_n(pubk) must have been initialized based on the modulus size, typically using ccn_nof_size(mod_nbytes).
 The public key structure pubk is typically allocated with ccrsa_pub_ctx_decl(mod_nbytes, pubk);
*/
CC_NONNULL_ALL
int ccrsa_init_pub(ccrsa_pub_ctx_t pubk, const cc_unit *modulus,
                    const cc_unit *exponent);

/*! @function ccrsa_make_priv
  @abstract   Initializes an RSA public and private key given the public
              exponent e and prime factors p and q.

  @param      full_ctx   Initialized context with ccrsa_ctx_n(full_ctx) set to 2*ccn_nof_size(p_nbytes)
  @param      e_nbytes   Number of bytes of public exponent e.
  @param      e_bytes    Public exponent e in Big Endian.
  @param      p_nbytes   Number of bytes of prime factor p.
  @param      p_bytes    Prime factor p in Big Endian.
  @param      q_nbytes   Number of bytes of prime factor q.
  @param      q_bytes    Prime factor q in Big Endian.

  @return     0          iff successful.

  @discussion  ccrsa_ctx_n(full_ctx) must already be set to 2*ccn_nof_size(p_mbytes), with the expectation that p_nbytes>q_nbytes.
  e is the public exponent, and e_nbytes<= 2*p_nbytes.
  The output is a fully formed RSA context with N=pq, d=e^{-1} mod lambda(N), and appropriate inverses of different associated values precomputed
  to speed computation.
*/
int ccrsa_make_priv(ccrsa_full_ctx_t full_ctx,
                    size_t e_nbytes, const uint8_t *cc_counted_by(e_nbytes) e_bytes,
                    size_t p_nbytes, const uint8_t *cc_counted_by(p_nbytes) p_bytes,
                    size_t q_nbytes, const uint8_t *cc_counted_by(q_nbytes) q_bytes);

/*! @function ccrsa_recover_priv
  @abstract   Initializes an RSA public and private key given the modulus m,
              the public exponent e and the private exponent d.

  @discussion Follows the algorithm described by
              NIST SP 800-56B, Appendix C, "Prime Factory Recovery".

  @param      full_ctx   Initialized context with ccrsa_ctx_n(full_ctx) set to ccn_nof_size(m_nbytes)
  @param      m_nbytes   Number of bytes of modulus m.
  @param      m_bytes    Modulus m in Big Endian.
  @param      e_nbytes   Number of bytes of public exponent e.
  @param      e_bytes    Public exponent e in Big Endian.
  @param      d_nbytes   Number of bytes of private exponent d.
  @param      d_bytes    Private exponent d in Big Endian.
  @param      rng        RNG instance.

  @return     0          iff successful.
*/
int ccrsa_recover_priv(ccrsa_full_ctx_t full_ctx,
                       size_t m_nbytes, const uint8_t *cc_counted_by(m_nbytes) m_bytes,
                       size_t e_nbytes, const uint8_t *cc_counted_by(e_nbytes) e_bytes,
                       size_t d_nbytes, const uint8_t *cc_counted_by(d_nbytes) d_bytes,
                       struct ccrng_state *rng);

/*!
@function   ccrsa_make_pub
@abstract   Initialize public key based on modulus and public exponent  as big endian byte arrays;

@param      pubk   allocated public key structure (see requirements below)
@param      exp_nbytes Number of bytes in big endian exponent.
@param      exp     Pointer to big endian exponent e (may have leading 0's).
@param      mod_nbytes  Number of bytes in big endian modulus.
@param      mod     Pointer to big endian to rsa modulus  N.
@result     0    iff successful.

@discussion ccrsa_ctx_n(pubk) must have been initialized based on the modulus size, typically using ccn_nof_size(mod_nbytes).
    The public key structure pubk is typically allocated with ccrsa_pub_ctx_decl(mod_nbytes, pubk);
*/

CC_NONNULL((1, 3, 5))
int ccrsa_make_pub(ccrsa_pub_ctx_t pubk,
                   size_t exp_nbytes, const uint8_t *cc_counted_by(exp_nbytes) exp,
                   size_t mod_nbytes, const uint8_t *cc_counted_by(mod_nbytes) mod);

/*!
@function   ccrsa_pub_crypt
@abstract   Perform an RSA public key operation: (in)^e mod m
@param      key   initialized public key defining e and m
@param      out   result of the operation, at least ccrsa_key_n(key) cc_units must have been allocated
@param      in     base of the exponentiation, of size ccrsa_key_n(key)
@result     CCERR_OK if no error
 
@discussion Input to this function must not be secrets as the execution flow may expose their values
        Clients can use ccn_read_uint() to convert bytes to cc_units to use for this API.
*/
CC_NONNULL((1, 2, 3))
int ccrsa_pub_crypt(ccrsa_pub_ctx_t key, cc_unit *cc_unsafe_indexable out, const cc_unit *cc_unsafe_indexable in);

/*!
@function   ccrsa_generate_key
@abstract   Generate a nbit RSA key pair.

@param      nbits      Bit size requested for the key
@param      fk         Allocated context where the generated key will be stored
@param      e_nbytes   Byte size of the input public exponent
@param      e_bytes    Input public exponent in big endian. Recommend value is {0x01, 0x00, 0x01}
@param      rng        Random Number generator used.
@result     CCERR_OK if no error

@discussion
    fk should be allocated using ccrsa_full_ctx_decl_nbits(nbits, fk).
    The unsigned big endian byte array exponent e of length e_size is used as the exponent. It's an error to call this function with an exponent larger than nbits
*/
CC_NONNULL_ALL
int ccrsa_generate_key(size_t nbits, ccrsa_full_ctx_t fk,
                       size_t e_nbytes, const void *cc_sized_by(e_nbytes) e_bytes, struct ccrng_state *rng) CC_WARN_RESULT;

/*!
@function   ccrsa_generate_key_deterministic
@abstract   Generate a deterministic nbit RSA key pair.

@param      nbits          Bit size requested for the key.
@param      fk             Allocated context where the generated key will be stored.
@param      e_nbytes       Byte length of public exponent.
@param      e              Public exponent in big endian. Recommend value is {0x01, 0x00, 0x01}.
@param      entropy_nbytes Byte length of entropy.
@param      entropy        Entropy, initial DRBG seed.
@param      nonce_nbytes   Byte length of nonce.
@param      nonce          Unique value combined with the entropy/seed.
@param      flags          Bitmap for options.
                           (Only CCRSA_GENKEY_DETERMINISTIC_LEGACY currently supported.)
@param      rng            Random Number generator for primality testing.
@result     CCERR_OK if no error

@discussion
    fk should be allocated using ccrsa_full_ctx_decl_nbits(nbits, fk).
    The unsigned big endian byte array exponent e of length e_size is used as the exponent. It's an error to call this function with an exponent larger than nbits
*/
CC_NONNULL((2, 4, 6, 10))
int ccrsa_generate_key_deterministic(size_t nbits, ccrsa_full_ctx_t fk,
                                     size_t e_nbytes, const uint8_t *cc_sized_by(e_nbytes) e,
                                     size_t entropy_nbytes, const uint8_t *cc_sized_by(entropy_nbytes) entropy,
                                     size_t nonce_nbytes, const uint8_t *cc_sized_by(nonce_nbytes) nonce,
                                     uint32_t flags,
                                     struct ccrng_state *rng);

#define CCRSA_GENKEY_DETERMINISTIC_LEGACY 0b1

/*!
@function   ccrsa_generate_fips186_key
@abstract   Generate a nbit RSA key pair in conformance with FIPS186-4 standard.

@param      nbits      Bit size requested for the key
@param      fk         Allocated context where the generated key will be stored
@param      e_nbytes   Byte size of the input public exponent
@param      e_bytes    Input public exponent in big endian. Recommend value is {0x01, 0x00, 0x01}
@param      rng        Random Number generator used for p and q
@param      rng_mr     Random Number generator only used for the primality check
@result     CCERR_OK if no error

@discussion
   fk should be allocated using ccrsa_full_ctx_decl_nbits(nbits, fk).
   rng and rng_mr shoud be set to the same value. The distinction is only relevant for testing
*/
CC_NONNULL_ALL int
ccrsa_generate_fips186_key(size_t nbits, ccrsa_full_ctx_t fk,
                           size_t e_nbytes, const void *cc_sized_by(e_nbytes) e_bytes,
                           struct ccrng_state *rng, struct ccrng_state *rng_mr) CC_WARN_RESULT;

/*
 Signing and Verification algorithms
*/

/*!
@function ccrsa_sign_pss

@brief  ccrsa_sign_pss() generates RSASSA-PSS signature in PKCS1-V2 format given an input digest

@param  key               The RSA key
@param  hashAlgorithm    The hash algorithm used to generate mHash from the original message. It is also used inside the PSS encoding function.
@param  MgfHashAlgorithm The hash algorithm for thr mask generation function
@param  rng              Random number geberator to generate salt in PSS encoding
@param  salt_nbytes     Intended length of the salt
@param  digest_nbytes   Length of message hash . Must be equal to hashAlgorithm->output_size
@param  digest           The input that needs to be signed. This is the hash of message M with length of hLen
@param  sig_nbytes       The length of generated signature in bytes, which equals the size of the RSA modulus.
@param  sig               The signature output
@return 0:ok, non-zero:error
 
@discussion
  note that in RSASSA-PSS, salt length is part of the signature as specified in ASN1
  RSASSA-PSS-params ::= SEQUENCE {
  hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
  maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
  saltLength         [2] INTEGER            DEFAULT 20,
  trailerField       [3] TrailerField       DEFAULT trailerFieldBC
 
  • If nlen = 1024 bits (i.e., 128 bytes), and the output length of the approved hash function output block is 512 bits (i.e., 64 bytes), then the length (in bytes) of the salt (sLen) shall satisfy 0 ≤ sLen ≤ hLen – 2,
  • Otherwise, the length (in bytes) of the salt (sLen) shall satisfy 0 ≤ sLen ≤ hLen, where hLen is the length of the hash function output block (in bytes).
 */
CC_NONNULL((1, 2, 3, 5, 7, 8, 9))
int ccrsa_sign_pss(ccrsa_full_ctx_t key,
                   const struct ccdigest_info* hashAlgorithm, const struct ccdigest_info* MgfHashAlgorithm,
                   size_t salt_nbytes, struct ccrng_state *rng,
                   size_t digest_nbytes, const uint8_t *cc_counted_by(digest_nbytes) digest,
                   size_t *sig_nbytes, uint8_t *cc_unsafe_indexable sig);

/*!
@function ccrsa_sign_pss_msg

@brief  ccrsa_sign_pss_msg() generates a RSASSA-PSS signature in PKCS1-V2 format given an input message

@param  key               The RSA key
@param  hashAlgorithm     The hash algorithm used to generate mHash from the input message. It is also used inside the PSS encoding function.
@param  MgfHashAlgorithm  The hash algorithm for thr mask generation function
@param  rng               Random number generator to generate salt in PSS encoding
@param  salt_nbytes       Intended length of the salt
@param  msg_nbytes        Length of message.
@param  msg               The input that needs to be signed. This will be hashed using `hashAlgorithm`
@param  sig_nbytes        The length of generated signature in bytes, which equals the size of the RSA modulus.
@param  sig               The signature output
@return 0:ok, non-zero:error
 
@discussion
  note that in RSASSA-PSS, salt length is part of the signature as specified in ASN1
  RSASSA-PSS-params ::= SEQUENCE {
  hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
  maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
  saltLength         [2] INTEGER            DEFAULT 20,
  trailerField       [3] TrailerField       DEFAULT trailerFieldBC
 
  • If nlen = 1024 bits (i.e., 128 bytes), and the output length of the approved hash function output block is 512 bits (i.e., 64 bytes), then the length (in bytes) of the salt (sLen) shall satisfy 0 ≤ sLen ≤ hLen – 2,
  • Otherwise, the length (in bytes) of the salt (sLen) shall satisfy 0 ≤ sLen ≤ hLen, where hLen is the length of the hash function output block (in bytes).
 */
CC_NONNULL((1, 2, 3, 5, 7, 8, 9))
int ccrsa_sign_pss_msg(ccrsa_full_ctx_t key,
                   const struct ccdigest_info* hashAlgorithm, const struct ccdigest_info* MgfHashAlgorithm,
                   size_t salt_nbytes, struct ccrng_state *rng,
                   size_t msg_nbytes, const uint8_t *cc_counted_by(msg_nbytes) msg,
                   size_t *sig_nbytes, uint8_t *cc_unsafe_indexable sig);

/*!
@function   ccrsa_verify_pss_digest
 
@brief ccrsa_verify_pss_digest() verifies RSASSA-PSS signature in PKCS1-V2 format, given the digest

@param   key               The RSA public key
@param   di                The hash algorithm used to generate the hash of the message.
@param   mgfdi             The hash algorithm for the mask generation function
@param   digest_nbytes     Length of digest. Must be equal to di->output_size
@param   digest            The signed message hash
@param   sig_nbytes        The length of generated signature in bytes, which equals the size of the RSA modulus.
@param   sig               The signature to verify
@param   salt_nbytes       Length of the salt as used during signature generation.
@param   fault_canary_out  OPTIONAL cc_fault_canary_t (see discussion)

@result   CCERR_VALID_SIGNATURE on signature success.
         CCERR_INVALID_SIGNATURE on signature failure.
         other on some other signature verification issue.
 
@discussion If the fault_canary_out argument is not NULL, the value `CCRSA_PSS_FAULT_CANARY` will be placed into fault_canary_out
 if the salted input hash is equal to the decoded hash (which strongly implies the signature is valid). Callers can then securely compare this output buffer against CCRSA_PSS_FAULT_CANARY, using CC_FAULT_CANARY_EQUAL, as an additional check of signature validity: if the two canary values are equal, the signature is valid otherwise it is not. If the signature is valid and the canary values are NOT equal this may indicate a potentially injected computational fault.
*/

CC_NONNULL((1, 2, 3, 5, 7))
int ccrsa_verify_pss_digest(ccrsa_pub_ctx_t key,
                            const struct ccdigest_info* di,
                            const struct ccdigest_info* mgfdi,
                            size_t digest_nbytes, const uint8_t *cc_counted_by(digest_nbytes) digest,
                            size_t sig_nbytes, const uint8_t *cc_unsafe_indexable sig,
                            size_t salt_nbytes, cc_fault_canary_t fault_canary_out);

/*!
@function   ccrsa_verify_pss_msg
 
@brief ccrsa_verify_pss_msg() verifies RSASSA-PSS signature in PKCS1-V2 format, given the message

@param   key               The RSA public key
@param   di                The hash algorithm used to generate the hash of the message.
@param   mgfdi             The hash algorithm for the mask generation function
@param   msg_nbytes        Length of message
@param   msg               The signed message
@param   sig_nbytes        The length of generated signature in bytes, which equals the size of the RSA modulus.
@param   sig               The signature to verify
@param   salt_nbytes       Length of the salt as used during signature generation.
@param   fault_canary_out  OPTIONAL cc_fault_canary_t (see discussion)

@result  CCERR_VALID_SIGNATURE on signature success.
        CCERR_INVALID_SIGNATURE on signature failure.
        other on some other signature verification issue.
 
@discussion If the fault_canary_out argument is not NULL, the value `CCRSA_PSS_FAULT_CANARY` will be placed into fault_canary_out
if the salted input hash is equal to the decoded hash (which strongly implies the signature is valid). Callers can then securely compare this output buffer against CCRSA_PSS_FAULT_CANARY, using CC_FAULT_CANARY_EQUAL, as an additional check of signature validity: if the two canary values are equal, the signature is valid otherwise it is not. If the signature is valid and the canary values are NOT equal this may indicate a potentially injected computational fault.
*/

CC_NONNULL((1, 2, 3, 5, 7))
int ccrsa_verify_pss_msg(ccrsa_pub_ctx_t key,
                         const struct ccdigest_info* di,
                         const struct ccdigest_info* mgfdi,
                         size_t msg_nbytes, const uint8_t *cc_counted_by(msg_nbytes) msg,
                         size_t sig_nbytes, const uint8_t *cc_counted_by(sig_nbytes) sig,
                         size_t salt_nbytes, cc_fault_canary_t fault_canary_out);


/*!
 @function   ccrsa_sign_pkcs1v15
 @abstract   RSA signature with PKCS#1 v1.5 format per PKCS#1 v2.2

 @param      key        Full key
 @param      oid        OID describing the type of digest passed in
 @param      digest_len Byte length of the digest
 @param      digest     Byte array of digest_len bytes containing the digest
 @param      sig_len    Pointer to the number of bytes allocated for sig.
                        Output the exact size of the signature.
 @param      sig        Pointer to the allocated buffer of size *sig_len
                        for the output signature

 @result     CCERR_OK iff successful.
 
  @discussion Null OID is a special case, required to support RFC 4346 where the padding
 is based on SHA1+MD5. In general it is not recommended to use a NULL OID,
 except when strictly required for interoperability

 */
CC_NONNULL((1, 4, 5, 6))
int ccrsa_sign_pkcs1v15(ccrsa_full_ctx_t key, const uint8_t *oid,
                        size_t digest_len, const uint8_t *cc_counted_by(digest_len) digest,
                        size_t *sig_len, uint8_t *cc_unsafe_indexable sig);

/*!
 @function   ccrsa_sign_pkcs1v15_msg
 @abstract   RSA signature with PKCS#1 v1.5 format per PKCS#1 v2.2

 @param      key       Full key
 @param      di        Digest context
 @param      msg_len   Byte length of the message to sign
 @param      msg       Byte array of msg_len bytes containing the message. Will be hashed with di.
 @param      sig_len   Pointer to the number of bytes allocated for sig.
                       Output the exact size of the signature.
 @param      sig       Pointer to the allocated buffer of size *sig_len
                       for the output signature

 @result     CCERR_OK iff successful.
 
 @discussion Null OID is not supported by this API.

 */
CC_NONNULL((1, 2, 4, 5, 6))
int ccrsa_sign_pkcs1v15_msg(ccrsa_full_ctx_t key, const struct ccdigest_info* di,
                            size_t msg_len, const uint8_t *cc_counted_by(msg_len) msg,
                            size_t *sig_len, uint8_t *cc_unsafe_indexable sig);


/*!
  @function   ccrsa_verify_pkcs1v15
  @abstract   RSA signature with PKCS#1 v1.5 format per PKCS#1 v2.2

  @param      key        Public key
  @param      oid        OID describing the type of digest passed in
  @param      digest_len Byte length of the digest
  @param      digest     Byte array of digest_len bytes containing the digest
  @param      sig_len    Number of bytes of the signature sig.
  @param      sig        Pointer to the signature buffer of sig_len
  @param      valid      Output boolean, true if the signature is valid.

  @result     A return value of 0 and valid = True indicates a valid signature.
              A non-zero return value or valid = False indicates an invalid signature.

  @discussion Null OID is a special case, required to support RFC 4346
  where the padding is based on SHA1+MD5. In general it is not
  recommended to use a NULL OID, except when strictly required for
  interoperability.
*/
CC_NONNULL((1, 4, 6, 7))
int ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t key, const uint8_t *oid,
                          size_t digest_len, const uint8_t *cc_counted_by(digest_len) digest,
                          size_t sig_len, const uint8_t *cc_counted_by(sig_len) sig,
                          bool *valid);

/*!
  @function   ccrsa_verify_pkcs1v15_digest
  @abstract   RSA signature with PKCS#1 v1.5 format per PKCS#1 v2.2, given a digest

  @param      key                 Public key
  @param      oid                 OID describing the type of digest passed in
  @param      digest_len          Byte length of the digest
  @param      digest              Byte array of digest_len bytes containing the digest
  @param      sig_len             Number of bytes of the signature sig.
  @param      sig                 Pointer to the signature buffer of sig_len
  @param      fault_canary_out    OPTIONAL cc_fault_canary_t

  @result      CCERR_VALID_SIGNATURE if a valid signature.
              CCERR_INVALID_SIGNATURE if an invalid signature.
              Other if the verification procedure failed.
 
 @discussion If the fault_canary_out argument is not NULL, the value `CCRSA_PKCS1_FAULT_CANARY` will be placed into fault_canary_out
 if the input hash is equal to the decoded hash (which strongly implies the signature is valid). Callers can then securely compare this output buffer against CCRSA_PKCS1_FAULT_CANARY, using CC_FAULT_CANARY_EQUAL, as an additional check of signature validity: if the two canary values are equal, the signature is valid otherwise it is not. If the signature is valid and the canary values are NOT equal this may indicate a potentially injected computational fault.
*/
CC_NONNULL((1, 4, 6))
int ccrsa_verify_pkcs1v15_digest(ccrsa_pub_ctx_t key, const uint8_t *oid,
                          size_t digest_len, const uint8_t *cc_counted_by(digest_len) digest,
                          size_t sig_len, const uint8_t *cc_counted_by(sig_len) sig,
                          cc_fault_canary_t fault_canary_out);

/*!
  @function   ccrsa_verify_pkcs1v15_msg
  @abstract   RSA signature with PKCS#1 v1.5 format per PKCS#1 v2.2

  @param      key                Public key
  @param      di                 Hash function
  @param      msg_len            Byte length of the digest
  @param      msg                Byte array of digest_len bytes containing the digest
  @param      sig_len            Number of bytes of the signature sig.
  @param      sig                Pointer to the signature buffer of sig_len
  @param      fault_canary_out   OPTIONAL cc_fault_canary_t

  @result     CCERR_VALID_SIGNATURE if a valid signature.
             CCERR_INVALID_SIGNATURE if an invalid signature.
             Other if the verification procedure failed.

  @discussion Null OID is not supported by this API.
             If the fault_canary_out argument is not NULL, the value `CCRSA_PKCS1_FAULT_CANARY` will
             be placed into fault_canary_out if the input hash is equal to the decoded hash (which strongly
             implies the signature is valid). Callers can then securely compare this output buffer against CCRSA_PKCS1_FAULT_CANARY, using CC_FAULT_CANARY_EQUAL, as an additional check of signature validity: if the two canary values are equal, the signature is valid otherwise it is not. If the signature is valid and the canary values are NOT equal this may indicate a potentially injected computational fault.
*/
CC_NONNULL((1, 2, 4, 6))
int ccrsa_verify_pkcs1v15_msg(ccrsa_pub_ctx_t key, const struct ccdigest_info* di,
                          size_t msg_len, const uint8_t *cc_counted_by(msg_len) msg,
                          size_t sig_len, const uint8_t *cc_counted_by(sig_len) sig,
                          cc_fault_canary_t fault_canary_out);

/*!
 @function   ccder_encode_rsa_pub_size
 @abstract   Calculate size of public key export format data package.
 
 @param      key        Public key
 
 @result     Returns size required for encoding.
 */

CC_NONNULL((1))
size_t ccder_encode_rsa_pub_size(const ccrsa_pub_ctx_t key);

/*!
 @function   ccrsa_export_priv_pkcs1
 @abstract   Export a public key.
 
 @param      key        Public key
 @param      der        Beginning of output DER buffer
 @param      der_end    End of output DER buffer
 */

CC_NONNULL((1, 2, 3))
uint8_t *ccder_encode_rsa_pub(const ccrsa_pub_ctx_t key, uint8_t *cc_ended_by(der_end) der, uint8_t *der_end);


/*!
 @function   ccder_encode_rsa_priv_size
 @abstract   Calculate size of full key exported in PKCS#1 format.
 
 @param      key        Full key
 
 @result     Returns size required for encoding.
 */

CC_NONNULL((1))
size_t ccder_encode_rsa_priv_size(const ccrsa_full_ctx_t key);

/*!
 @function   ccder_encode_rsa_priv
 @abstract   Export a full key in PKCS#1 format.
 
 @param      key        Full key
 @param      der        Beginning of output DER buffer
 @param      der_end    End of output DER buffer
 */

CC_NONNULL((1, 2, 3))
uint8_t *ccder_encode_rsa_priv(const ccrsa_full_ctx_t key, const uint8_t *cc_ended_by(der_end) der, uint8_t *der_end);

/*!
 @function   ccder_decode_rsa_pub_n
 @abstract   Calculate "n" for a public key imported from a data package.
        PKCS #1 format
 
 @param      der        Beginning of input DER buffer
 @param      der_end    End of input DER buffer
 
 @result the "n" of the RSA key that would result from the import.  This can be used
 to declare the key itself.
 */

CC_NONNULL((1, 2))
cc_size ccder_decode_rsa_pub_n(const uint8_t *cc_ended_by(der_end) der, const uint8_t *der_end);

/*!
 @function   ccder_decode_rsa_pub
 @abstract   Import a public RSA key from a package in public key format.
        PKCS #1 format
 
 @param      key          Public key (n must be set)
 @param      der        Beginning of input DER buffer
 @param      der_end    End of input DER buffer
 
 @result     Key is initialized using the data in the public key message.
 */

CC_NONNULL((1, 2, 3))
const uint8_t *ccder_decode_rsa_pub(const ccrsa_pub_ctx_t key, const uint8_t *cc_ended_by(der_end) der, const uint8_t *der_end);

/*!
 @function   ccder_decode_rsa_pub_x509_n
 @abstract   Calculate "n" for a public key imported from a data package in x509 format

 @param      der        Beginning of input DER buffer
 @param      der_end    End of input DER buffer

 @result the "n" of the RSA key that would result from the import.  This can be used
 to declare the key itself.
 */

CC_NONNULL((1, 2))
cc_size ccder_decode_rsa_pub_x509_n(const uint8_t *cc_ended_by(der_end) der, const uint8_t *der_end);

/*!
 @function   ccder_decode_rsa_pub_x509
 @abstract   Import a public RSA key from a package in x509 format.

 @param      key          Public key (n must be set)
 @param      der        Beginning of input DER buffer
 @param      der_end    End of input DER buffer

 @result     Key is initialized using the data in the public key message.
 */

CC_NONNULL((1, 2, 3))
const uint8_t *ccder_decode_rsa_pub_x509(const ccrsa_pub_ctx_t key, const uint8_t *cc_ended_by(der_end) der, const uint8_t *der_end);


/*!
 @function   ccder_decode_rsa_priv_n
 @abstract   Calculate "n" for a private key imported from a data package.
 
 @param      der        Beginning of input DER buffer
 @param      der_end    End of input DER buffer
 
 @result the "n" of the RSA key that would result from the import.  This can be used
 to declare the key itself.
 */

CC_NONNULL((1, 2))
cc_size ccder_decode_rsa_priv_n(const uint8_t *cc_ended_by(der_end) der, const uint8_t *der_end);

/*!
 @function   ccder_decode_rsa_priv
 @abstract   Import a private RSA key from a package in PKCS#1 format.
 
 @param      key          Full key (n must be set)
 @param      der        Beginning of input DER buffer
 @param      der_end    End of input DER buffer
 
 @result     Key is initialized using the data in the public key message.
 */

CC_NONNULL((1, 2, 3))
const uint8_t *ccder_decode_rsa_priv(const ccrsa_full_ctx_t key, const uint8_t *cc_ended_by(der_end) der, const uint8_t *der_end);

/*!
 @function   ccrsa_export_pub_size
 @abstract   Calculate size of public key exported data package.
 
 @param      key        Public key
 
 @result     Returns size required for encoding.
 */

CC_NONNULL((1))
size_t ccrsa_export_pub_size(const ccrsa_pub_ctx_t key);

/*!
 @function   ccrsa_export_pub
 @abstract   Export a public key in public key format.
 
 @param      key        Public key
 @param      out_len    Allocated size
 @param      out        Output buffer
 */

CC_NONNULL((1, 3))
int ccrsa_export_pub(const ccrsa_pub_ctx_t key, size_t out_len, uint8_t *cc_counted_by(out_len) out);
/*!
 @function   ccrsa_import_pub_n
 @abstract   Calculate "n" for a public key imported from a data package.
 
 @param      inlen        Length of public key package data
 @param      der          pointer to public key package data
 
 @result the "n" of the RSA key that would result from the import.  This can be used
 to declare the key itself.
 */

CC_NONNULL((2))
cc_size ccrsa_import_pub_n(size_t inlen, const uint8_t *cc_sized_by(inlen) der);

/*!
 @function   ccrsa_import_pub
 @abstract   Import a public RSA key from a package in public key format.
 
 @param      key          Public key (n must be set)
 @param      inlen        Length of public key package data
 @param      der           pointer to public key package data
 
 @result     Key is initialized using the data in the public key message.
 */

CC_NONNULL((1, 3))
int ccrsa_import_pub(ccrsa_pub_ctx_t key, size_t inlen, const uint8_t *cc_sized_by(inlen) der);

/*!
 @function   ccrsa_export_priv_size
 @abstract   Calculate size of full key exported in PKCS#1 format.
 
 @param      key        Full key
 
 @result     Returns size required for encoding.
 */

CC_NONNULL((1))
size_t ccrsa_export_priv_size(const ccrsa_full_ctx_t key);

/*!
 @function   ccrsa_export_priv
 @abstract   Export a full key in PKCS#1 format.
 
 @param      key        Full key
 @param      out_len    Allocated size
 @param      out        Output buffer
 */

CC_NONNULL((1, 3))
int ccrsa_export_priv(const ccrsa_full_ctx_t key, size_t out_len, uint8_t *cc_sized_by(out_len) out);

/*!
 @function   ccrsa_import_priv_n
 @abstract   Calculate size of full key exported in PKCS#1 format.
 
 @param      inlen        Length of PKCS#1 package data
 @param      der           pointer to PKCS#1 package data
 
 @result the "n" of the RSA key that would result from the import.  This can be used
 to declare the key itself.
 */

CC_NONNULL((2))
cc_size ccrsa_import_priv_n(size_t inlen, const uint8_t *cc_sized_by(inlen) der);

/*!
 @function   ccrsa_import_priv
 @abstract   Import a full RSA key from a package in PKCS#1 format.
 
 @param      key          Full key (n must be set)
 @param      inlen        Length of PKCS#1 package data
 @param      der           pointer to PKCS#1 package data
 
 @result     Key is initialized using the data in the PKCS#1 message.
 */

CC_NONNULL_ALL
int ccrsa_import_priv(ccrsa_full_ctx_t key, size_t inlen, const uint8_t *cc_sized_by(inlen) der);

/*!
@function   ccrsa_get_pubkey_components
@abstract   Copy each component of the public key to the given buffers

@param      pubkey                       Public key
@param      modulus                     Buffer to the output buffer for the modulus
@param      modulusLength        Pointer to the byte size allocated for the modulus, updated with actual output size
@param      exponent                  Buffer to the output buffer for the exponent
@param      exponentLength     Pointer to the byte size allocated for the exponent, updated with actual output size
 
@return     0 is success, not 0 in case of error
 
@discussion if either allocated buffer length is insufficient, the function returns an error
*/
CC_NONNULL((1, 2))
int ccrsa_get_pubkey_components(const ccrsa_pub_ctx_t pubkey, uint8_t *cc_unsafe_indexable modulus, size_t *modulusLength, uint8_t *cc_unsafe_indexable exponent, size_t *exponentLength);

/*!
@function   ccrsa_get_fullkey_components
@abstract   Copy each component of the public key to the given buffers

@param      key                              Full key
@param      modulus                     Output buffer for the modulus
@param      modulusLength        Pointer to the byte size allocated for the modulus, updated with actual output size
@param      d                                   Output buffer for the private exponent d.
@param      dLength                     Pointer to the byte size allocated for the private exponent d, updated with actual output size
@param      p                                  Output buffer for the first prime factor of the modulus
@param      pLength                     Pointer to the byte size allocated for the prime factor, updated with actual output size
@param      q                                  Output buffer for the second prime factor of the modulus
@param      qLength                     Pointer to the byte size allocated for the prime factor, updated with actual output size

@return     0 is success, not 0 in case of error
 
@discussion if either allocated buffer length is insufficient, the function returns an error
*/
CC_NONNULL((1, 2))
int ccrsa_get_fullkey_components(const ccrsa_full_ctx_t key, uint8_t *cc_unsafe_indexable modulus, size_t *modulusLength,
                                 uint8_t *cc_unsafe_indexable d, size_t *dLength,
                                 uint8_t *cc_unsafe_indexable p, size_t *pLength,
                                 uint8_t *cc_unsafe_indexable q, size_t *qLength);


/*!
 @function   ccrsa_dump_public_key
 @abstract   Print a rsa public key in the console (printf)

 @param      key          Public key
 */
void ccrsa_dump_public_key(ccrsa_pub_ctx_t key);

/*!
 @function   ccrsa_dump_full_key
 @abstract   Print a rsa private key in the console (printf)

 @param      key          Public key
 */
void ccrsa_dump_full_key(ccrsa_full_ctx_t key);

#endif /* _CORECRYPTO_CCRSA_H_ */
