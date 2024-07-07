/* Copyright (c) (2011-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRSA_PRIV_H_
#define _CORECRYPTO_CCRSA_PRIV_H_

#include <corecrypto/ccrsa.h>
#include <corecrypto/cc_priv.h>

CC_PTRCHECK_CAPABLE_HEADER()

/*!
 @brief emsa_pss_encode () encodes message M acording to EMSA-PSS in PKCS 1 V2


 @return 	    0:ok non-zero:error



 @param	di	    hash function (hLen denotes the length in octets of the hash function output)
 @param	sSize	intended length in octets of the salt
 @param   salt    salt for encoding
 @param   hSize    length of hash function. must be equal to di->output_size
 @param	mHash   the input that needs to be encoded. This is the hash of message M with length of hLen
 @param   emBits  maximal bit length of the integer OS2IP (EM) (see Section 4.2), at least 8hLen + 8sLen + 9. It is one bit smalller than modulus.
 @param   EM      encoded message output, an octet string of length emLen = ⎡emBits/8⎤

 <pre>
 @textblock
                                        +-------------+
                                        |  M[2^61-1]  |
                                        +-------------+
                                               |
                                               V
                                            Hash[hLen]
                                               |
                                               V
                               +--------+-------------+------------+
             M'[8+hLen+sLen] = |  0[8]  | mHash[hLen] | salt[sLen] |
                               +--------+-------------+------------+
                  t=emLen-sLen-hLen-2          |
                  +------+---+------------+    V
 DB[emLen-hLen-1]=| 0[t] | 1 | salt[sLen] |  Hash[hLen]
                  +------+---+------------+    |
                             |                 |
                             V dbMask[]        |
          [emLen- hLen-1]  xor <------- MGF <--|
                             |                 |
                             |                 |
                 bit 0       V                 V
                 +------------------------+----------+--+
      EM[emLen]= | maskedDB[emLen-hLen-1] | H[hLen]  |bc|
                 +------------------------+----------+--+
 @/textblock
 </pre>
 */

CC_NONNULL((1, 2, 4, 6, 8))
int ccrsa_emsa_pss_encode(const struct ccdigest_info* di, const struct ccdigest_info* MgfDi,
                          size_t sSize, const uint8_t *cc_counted_by(sSize) salt,
                          size_t hSize, const uint8_t *cc_counted_by(hSize) mHash,
                          size_t emBits, uint8_t *cc_unsafe_indexable EM);
CC_NONNULL((1, 2, 5, 7))
int ccrsa_emsa_pss_decode(const struct ccdigest_info* di, const struct ccdigest_info* MgfDi,
                    size_t sSize,
                    size_t mSize,  const uint8_t *cc_counted_by(mSize) mHash,
                    size_t emBits, const uint8_t *cc_unsafe_indexable EM);


/* EMSA

 Null OID in emsa encode/verify is a special case, only for use by SecKey for legacy purposes
 When oid==NULL, the padding is reduced to "0001FF..FF00", oid and following seperators are skipped.
 it is critical that the caller has set the oid and
 other padding characters in the input "dgst".
 Failing to do so results in weak signatures that may be forgeable */
CC_NONNULL((2, 4))
int ccrsa_emsa_pkcs1v15_encode(size_t emlen, uint8_t *cc_counted_by(emlen) em,
                               size_t dgstlen, const uint8_t *cc_counted_by(dgstlen) dgst,
                               const uint8_t *cc_unsafe_indexable oid);

CC_NONNULL((2, 4))
int ccrsa_emsa_pkcs1v15_verify(size_t emlen, uint8_t *cc_counted_by(emlen) em,
                               size_t dgstlen, const uint8_t *cc_counted_by(dgstlen) dgst,
                               const uint8_t *cc_unsafe_indexable oid);

/*!
  @function   ccrsa_verify_pkcs1v15_allowshortsigs
  @abstract   RSA signature with PKCS#1 v1.5 format per PKCS#1 v2.2

  @param      key        Public key
  @param      oid        OID describing the type of digest passed in
  @param      digest_len Byte length of the digest
  @param      digest     Byte array of digest_len bytes containing the digest
  @param      sig_len    Number of byte of the signature sig.
  @param      sig        Pointer to the signature buffer of sig_len
  @param      valid      Output boolean, true if the signature is valid.

  @result     CCERR_OK iff successful.

  @discussion Do not call this function. Validation of signature length is relaxed
  with respect to the specification. Null OID is a special case, required to support RFC 4346 where the
  padding is based on SHA1+MD5. In general it is not recommended to
  use a NULL OID, except when strictly required for interoperability.
 */
CC_NONNULL((1, 4, 6, 7))
int ccrsa_verify_pkcs1v15_allowshortsigs(ccrsa_pub_ctx_t key, const uint8_t *cc_unsafe_indexable oid,
                                         size_t digest_len, const uint8_t *cc_counted_by(digest_len) digest,
                                         size_t sig_len, const uint8_t *cc_counted_by(sig_len) sig,
                                         bool *valid);

/*!
  @function   ccmgf
  @abstract   Mask Generation Function 1, based on a hash function.
        Used for OAEP and SRP

  @param      di                 Digest info for the hash function
  @param      r_nbytes   Number of bytes for the output (the mask)
  @param      r                   Byte array for the output
  @param      seed_nbytes   Number of bytes for the seed
  @param      seed            Byte array for the seed

  @result     CCERR_OK iff successful.

  @discussion Defined in PKCS #1, section B.2.1. Seed is di->output_size bytes
 */
CC_NONNULL((1, 3, 5))
int ccmgf(const struct ccdigest_info* di,
           size_t r_nbytes, void *cc_sized_by(r_nbytes) r,
           size_t seed_nbytes, const void *cc_sized_by(seed_nbytes) seed);

// OAEP

/*
 r_size is the blocksize of the key for which the encoding is being done.
 */
CC_NONNULL((1, 2, 4, 6))
int ccrsa_oaep_encode_parameter(const struct ccdigest_info* di,
                                struct ccrng_state *rng,
                                size_t r_size, cc_unit *cc_counted_by(r_size) r,
                                size_t message_len, const uint8_t *cc_counted_by(message_len) message,
                                size_t parameter_data_len, const uint8_t *cc_counted_by(parameter_data_len) parameter_data);

/*
 r_size is the blocksize of the key for which the encoding is being done.
 */

CC_NONNULL((1, 2, 4, 6))
int ccrsa_oaep_encode(const struct ccdigest_info* di,
                      struct ccrng_state *rng,
                      size_t r_size, cc_unit *cc_counted_by(r_size) r,
                      size_t message_len, const uint8_t *cc_counted_by(message_len) message);

/*
 r_len is the blocksize of the key for which the decoding is being done.
 */
CC_NONNULL((1, 2, 3, 5))
int ccrsa_oaep_decode_parameter(const struct ccdigest_info* di,
                                size_t *r_len, uint8_t *cc_unsafe_indexable r,
                                size_t s_size, cc_unit *cc_counted_by(s_size) s,
                                size_t parameter_data_len, const uint8_t *cc_counted_by(parameter_data_len) parameter_data);


CC_NONNULL((1, 2, 3, 5))
int ccrsa_oaep_decode(const struct ccdigest_info* di,
                      size_t *r_len, uint8_t *cc_unsafe_indexable r,
                      size_t s_size, cc_unit *cc_counted_by(s_size) s);

/*!
 @function   ccrsa_eme_pkcs1v15_encode
 @abstract   Encode a key in PKCS1 V1.5 EME format prior to encrypting.

 @param      rng        A handle to an initialized rng state structure.
 @param      r_size     (In/Out) Result buffer size.
 @param      r          Result cc_unit buffer.
 @param      s_size     Source (payload) length.
 @param      s          Source buffer to be encoded.

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */

CC_NONNULL((1, 3, 5))
int ccrsa_eme_pkcs1v15_encode(struct ccrng_state *rng,
                              size_t r_size, cc_unit *cc_counted_by(r_size) r,
                              size_t s_size, const uint8_t *cc_counted_by(s_size) s);

/*!
 @function   ccrsa_eme_pkcs1v15_decode
 @abstract   Decode a payload in PKCS1 V1.5 EME format to a key after decrypting.

 @param      r_size     (In/Out) Result buffer size.
 @param      r          Result buffer.
 @param      s_size     Source (PKCS1 EME Payload) length.
 @param      s          Source cc_unit buffer to be decoded.

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */

CC_NONNULL((1, 2, 4))
int ccrsa_eme_pkcs1v15_decode(size_t *r_size, uint8_t *cc_unsafe_indexable r,
                              size_t s_size, cc_unit *cc_counted_by(s_size) s);

/*!
 @function   ccrsa_eme_pkcs1v15_decode_safe
 @abstract   Decode a payload in PKCS1 V1.5 EME format to a key after decrypting.

 @param      key        The private key used to decrypt the payload.
 @param      r_size     (In/Out) Result buffer size.
 @param      r          Result buffer.
 @param      s_size     Source (PKCS1 EME Payload) length.
 @param      s          Source cc_unit buffer to be decoded.

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 3, 5))
int ccrsa_eme_pkcs1v15_decode_safe(ccrsa_full_ctx_t key,
                                   size_t *r_size, uint8_t *cc_unsafe_indexable r,
                                   size_t s_size, cc_unit *cc_counted_by(s_size) s);

/*!
 @function   ccrsa_encrypt_eme_pkcs1v15
 @abstract   Encode a key in PKCS1 V1.5 EME format and encrypt.
             DO NOT USE: THIS ALGORITHM IS NOT SECURE
             This algorithm is vulnerable to practical attacks leading to plaintext recovery (Bleichenbach 98, Coron Joye Naccache Pailler 2000)

 @param      key        A public key to use to encrypt the package.
 @param      rng        A handle to an initialized rng state structure.
 @param      r_size     (In/Out) Result buffer size.
 @param      r          Result cc_unit buffer.
 @param      s_size     Source (payload) length.
 @param      s          Source buffer to be encoded.

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */

CC_NONNULL((1, 2, 3, 4, 6))
int ccrsa_encrypt_eme_pkcs1v15(ccrsa_pub_ctx_t key,
                           struct ccrng_state *rng,
                           size_t *r_size, uint8_t *cc_unsafe_indexable r,
                           size_t s_size, const uint8_t *cc_counted_by(s_size) s);

/*!
 @function   ccrsa_decrypt_eme_pkcs1v15
             DO NOT USE: THIS ALGORITHM IS NOT SECURE
             This algorithm is vulnerable to practical attacks leading to plaintext recovery (Bleichenbach 98, Coron Joye Naccache Pailler 2000)

 @abstract   Decrypt and decode a payload in PKCS1 V1.5 EME format to a key.

 @param      key        A private key to use to decrypt the package.
 @param      r_size     (In/Out) Result buffer size.
 @param      r          Result buffer.
 @param      s_size     Source (PKCS1 EME Payload) length.
 @param      s          Source buffer to be decoded.

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */


CC_NONNULL((1, 2, 3, 5))
int ccrsa_decrypt_eme_pkcs1v15(ccrsa_full_ctx_t key,
                           size_t *r_size, uint8_t *cc_unsafe_indexable r,
                           size_t s_size, const uint8_t *cc_counted_by(s_size) s);

/*!
 @function   ccrsa_encrypt_oaep
 @abstract   Encode a key in PKCS1 V2.1 OAEP format and encrypt.

 @param      key        A public key to use to encrypt the package.
 @param      di         A descriptor for the digest used to encode the package.
 @param      rng        A handle to an initialized rng state structure.
 @param      r_size     (In/Out) Result buffer size.
 @param      r          Result buffer.
 @param      s_size     Source (payload) length.
 @param      s          Source buffer to be encoded.
 @param      parameter_data_len Length of tag data (optional)
 @param      parameter_data Pointer to tag data (optional)

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 3, 4, 5, 7))
int ccrsa_encrypt_oaep(ccrsa_pub_ctx_t key,
                   const struct ccdigest_info* di,
                   struct ccrng_state *rng,
                   size_t *r_size, uint8_t *cc_unsafe_indexable r,
                   size_t s_size, const uint8_t *cc_counted_by(s_size) s,
                   size_t parameter_data_len,
                   const uint8_t *cc_counted_by(parameter_data_len) parameter_data);

/*!
 @function   ccrsa_decrypt_oaep
 @abstract   Decrypt and decode a payload in PKCS1 V2.1 OAEP format to a key.

 @param      key        A private key to use to decrypt the package.
 @param      di         A descriptor for the digest used to encode the package.
 @param      r_size     (In/Out) Result buffer size.
 @param      r          Result buffer.
 @param      c_size     Source (PKCS1 EME Payload) length.
 @param      c          Source buffer to be decoded.
 @param      parameter_data_len Length of tag data (optional)
 @param      parameter_data Pointer to tag data (optional)

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */

CC_NONNULL((1, 2, 3, 4, 6))
int ccrsa_decrypt_oaep(ccrsa_full_ctx_t key,
                   const struct ccdigest_info* di,
                   size_t *r_size, uint8_t *cc_unsafe_indexable r,
                   size_t c_size, const uint8_t *cc_counted_by(c_size) c,
                   size_t parameter_data_len,
                   const uint8_t *cc_counted_by(parameter_data_len) parameter_data);

/*!
 @function   ccrsa_priv_crypt
 @abstract   Perform RSA operation with a private key

 @param      key        A handle an RSA private key.
 @param      out        Output buffer, of size ccrsa_ctx_n(key).
 @param      in         Input buffer, of size ccrsa_ctx_n(key).

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 3))
int ccrsa_priv_crypt(ccrsa_full_ctx_t key, cc_unit *cc_unsafe_indexable out, const cc_unit *cc_unsafe_indexable in);

cc_size ccrsa_n_from_size(size_t size);

size_t ccrsa_sizeof_n_from_size(size_t size);

uint8_t *ccrsa_block_start(size_t size, cc_unit *p, int clear_to_start);

size_t ccrsa_block_size(ccrsa_pub_ctx_t key);

#endif
