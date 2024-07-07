/* Copyright (c) (2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCMODE_SIV_HMAC_INTERNAL_H
#define _CORECRYPTO_CCMODE_SIV_HMAC_INTERNAL_H

#include <corecrypto/ccn.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode_impl.h>

// Maximum size for the key is 512
#define CCSIV_HMAC_MAX_KEY_BYTESIZE   512/8

struct _ccmode_siv_hmac_ctx {
    const struct ccmode_siv_hmac *siv_hmac;
    size_t key_bytesize;
    size_t tag_length;
    cc_unit state;
    cc_unit mac_key[ccn_nof_size(CCSIV_HMAC_MAX_KEY_BYTESIZE/2)]; // hmac key
    cc_unit ctr_key[ccn_nof_size(CCSIV_HMAC_MAX_KEY_BYTESIZE/2)]; // ctr key
    cc_ctx_decl_field(struct cchmac_ctx, cchmac_ctx_size(MAX_DIGEST_BLOCK_SIZE, MAX_DIGEST_STATE_SIZE), hmac_ctx);
};

// Follow marks are used for distinct coding. Each needs to be one byte, and they need to be unique
#define CCSIV_HMAC_AD_MARK 'A'
#define CCSIV_HMAC_NONCE_MARK 'N'
#define CCSIV_HMAC_PLAINTEXT_MARK 'P'
#define _CCMODE_SIV_HMAC_MINIMUM_ACCEPTABLE_COLLISION_RESISTANT_TAG_LENGTH 20

// Change to HMAC
// ccsiv_hmac_ctx is alias for struct _ccmode_siv_hmac_ctx

/*!
 @function   ccmode_siv_hmac_init
 @abstract   Initialize a context for siv_hmac with an associated mode, given key and specifying output tag size.
 
 @param      siv_hmac           Descriptor for the mode
 @param      ctx                Allocated context to be intialized
 @param      rawkey_byte_len    Length of the key:  Supported key sizes are 32, 48, 64 bytes
 @param      rawkey             key for siv_hmac
 @param      tag_length           The length of the output tag requested. Must be at least 20 bytes, and can be as larged as the
 associated digest's output
 
 @discussion In order to  compute HMAC_SIV_Enc_k(a1,...,am, n, x) where ai is the ith piece of associated authenticated data, n is a nonce and x
 is a plaintext, we first initialize the context with this call, and then use it to call ccsiv_hmac_aad for each ai, followed by
 ccsiv_hmac_set_nonce for nonce n, and finally a call to ccsiv_hmac_crypt for the plaintext x. Note the oder of the calls to aad,
 nonce and then crypt is critical. If a second encryption is needed then a call to ccsiv_hmac_reset can be used to reset state,
 and begin again.
 */
int ccmode_siv_hmac_init(const struct ccmode_siv_hmac *siv_hmac,
                         ccsiv_hmac_ctx *ctx,
                         size_t rawkey_byte_len,
                         const uint8_t *rawkey,
                         size_t tag_length);

/*!
 @function   ccmode_siv_hmac_auth_backend
 @abstract   A helper function with adds the string _in_ of length nbytes into the hmac for the provided context ctx. It follows that input with the
             character that is supplied in mark. This function is helper function that is used in length encoding inputs to hmac. It should not be called directly.
 
 @param      ctx                initalized siv_hmac context which the data
 @param      nbytes             Length of the string _in_ to be added to hmac. Do not add 1 for the mark byte!
 @param      in                 string to be added to hmac
 @param      mark               An extra character used in the length encoding after the input in.
  */

void ccmode_siv_hmac_auth_backend(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t mark);

/*!
 @function   ccmode_siv_hmac_auth
 @abstract   Add the next piece of associated authenticated data to the hmac_siv's computation of the the tag. Note this call is optional and no
 associated authenticated data needs to be provided. Multiple pieces of associated authenticated data can be provided by multiple calls to this
 function. Each input is regarded as a seperate piece of associated authenticated data, and the mac is NOT simply computed on the
 concatenation of all of the associated authenticated data inputs. Therefore on decryption the same inputs must be prodivded and in
 the same order.

 @param      ctx                Intialized ctx
 @param      nbytes             Length of the current associated authenticated data being added
 @param      in                 Associated data to be authenticated.
 
 @discussion Adds the associated authenticated data given by in to the computation of the tag in the associated authenticated data.
 */
int ccmode_siv_hmac_auth(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in);

/*!
 @function   ccmode_siv_hmac_nonce
 @abstract   Add the nonce to the hmac_siv's computation of the the tag. Changes the internal state of the context
 so that after the call only a crypt or reset call is permitted.
 @param      ctx                Intialized ctx
 @param      nbytes             Length of the current nonce data being added
 @param      in                 Nonce data to be authenticated.
 
 @discussion The nonce is a special form of associated authenticated data. If provided ( a call to hmac_nonce is optional) it allows
 randomization of the of ciphertext (preventing deterministic encryption). While the length of the nonce is not limimited, the
 amount of entropy that can be provided is limited by the number of bits in the block of the associated block-cipher in mode.
 */
int ccmode_siv_hmac_nonce(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in);

// Authentication of the last vector (the encrypted part)
int ccmode_siv_hmac_auth_finalize(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *V);

/*!
 @function   ccmode_siv_hmac_encrypt
 @abstract   This function encrypts the plaintext given as input in, and provides the ciphertext (which is a concatenation of the tag
 followed by the encrypted plaintext) as output out.
 @param      ctx                Intialized ctx
 @param      nbytes             Length of the current plaintext
 @param      in                 Plaintext
 @param      out                Tag concatenated with ciphertext
 @discussion This function is only called once, and its call precludes calls to ccmode_siv_hmac_decrypt. If one wishes to compute another encryption, one resets the state with
 ccmode_siv_hmac_reset, and then begins the process again. There is no way to stream large plaintext/ciphertext inputs into the
 function.
 */
int ccmode_siv_hmac_encrypt(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *out);

/*!
 @function   ccmode_siv_hmac_decrypt
 @abstract   This function decrypts to a plaintext using the input ciphertext at in (reminder: the ciphertext is the
 tag, followed by encrypted plaintext), and then verifies that the computed tag and provided tag at the front of the ciphertext match.
 Note that in the case that the tag verification fails, no plaintext is returned, nor is any tag returned. Plaintext and tag are zeroed in case of tag mismatch.
 @param      ctx                Intialized ctx
 @param      nbytes             Length of the current plaintext
 @param      in                 Plaintext
 @param      out                Tag concatenated with ciphertext
 @discussion This function is only called once, and its call precludes calls to ccmode_siv_hmac_encrypt. If one wishes to compute another decryption, one resets the state with
 ccmode_siv_hmac_reset, and then begins the process again. There is no way to stream large plaintext/ciphertext inputs into the
 function.
 
 In the case of a decryption, if there is a failure in verifying the computed tag against the provided tag (embedded int he ciphertext), then a decryption/verification
 failure is returned, and any internally computed plaintexts and tags are zeroed out.
 Lastly the contexts internal state is reset, so that a new decryption/encryption can be commenced.
 */
int ccmode_siv_hmac_decrypt(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *out);

/*!
 @function   ccmode_siv_hmac_reset
 @abstract   Resets the state of the ctx, maintaing the key, but preparing  the
 ctx to preform a new Associated Data Authenticated (En)/(De)cryption.
 @param      ctx                Intialized ctx
 */
int ccmode_siv_hmac_reset(ccsiv_hmac_ctx *ctx);

/*!
 @function ccmode_siv_hmac_temp_key_gen
 @abstract Generates the per message ctr key used to encrypt data.
 @param ctx
 A context for the siv_hmac
 @param temp_key
 An allocated array of twice the associated block-cipher's key length
 @param iv
 The IV being used for the ctr encryption in the SIV.
 @discussion We create a key for the CTR mode encryption that is "unique" for each message.
 Let T be all be but the least significant byte of the tag computed from HMAC.
 We compute x0=BC_k(T||0),x1=BC_k(T||1),...,xn=BC_k(T||n), where BC is the block cipher being used in CTR mode in this
 construction. The key actually used for CTR mode encryption is the concatenation of the _first_half_ of each xi.
 The reason we use only the first half of the output of each call to the BC is that BC produces permutations and not
 random functions, so this output is signifincatly close to a random functions output.
 */
int ccmode_siv_hmac_temp_key_gen(ccsiv_hmac_ctx *ctx, uint8_t *temp_key, const uint8_t *iv);

/* Macros for accessing a CCMODE_SIV_HMAC. */
#define _CCMODE_SIV_HMAC_CTX(K) ((struct _ccmode_siv_hmac_ctx *)(K))
#define _CCMODE_SIV_HMAC_HMAC_CTX(K) (_CCMODE_SIV_HMAC_CTX(K)->hmac_ctx)
#define _CCMODE_SIV_HMAC_DIGEST(K) (_CCMODE_SIV_HMAC_CTX(K)->siv_hmac->hmac_digest)
#define _CCMODE_SIV_HMAC_CTR_MODE(K) (_CCMODE_SIV_HMAC_CTX(K)->siv_hmac->ctr)
#define _CCMODE_SIV_HMAC_STATE(K) (_CCMODE_SIV_HMAC_CTX(K)->state)
#define _CCMODE_SIV_HMAC_KEYSIZE(K) (_CCMODE_SIV_HMAC_CTX(K)->key_bytesize)
#define _CCMODE_SIV_HMAC_MAC_KEY(K) ((uint8_t *)_CCMODE_SIV_HMAC_CTX(K)->mac_key)
#define _CCMODE_SIV_HMAC_CTR_KEY(K) ((uint8_t *)_CCMODE_SIV_HMAC_CTX(K)->ctr_key)
#define _CCMODE_SIV_HMAC_TAG_LENGTH(K) (_CCMODE_SIV_HMAC_CTX(K)->tag_length)

/*!
 @function ccmode_factory_siv_hmac_encrypt
 @abstract  Use this function to runtime initialize a ccmode_siv_hmac encrypt object.
 Currently only SHA256 digest and aes ctr mode
 are tested.
 @param siv_hmac A previously allocated siv_hmac array that will be initialized
 @param digest The digest mode that will be used for the HMAC.
 @param ctr  A CTR-Mode primitive that will be used for encryption
 */
void ccmode_factory_siv_hmac_encrypt(struct ccmode_siv_hmac *siv_hmac, const struct ccdigest_info *digest, const struct ccmode_ctr *ctr);

/*!
 @function ccmode_factory_siv_hmac_decrypt
 @abstract  Use this function to runtime initialize a ccmode_siv_hmac decrypt object.
 Currently only SHA256 digest and aes ctr mode
 are tested.
 @param siv_hmac A previously allocated siv_hamc array that will be initialized
 @param digest The digest mode that will be used for the HMAC.
 @param ctr  A CTR-Mode primitive that will be used for encryption
 */
void ccmode_factory_siv_hmac_decrypt(struct ccmode_siv_hmac *siv_hmac, const struct ccdigest_info *digest, const struct ccmode_ctr *ctr);

#endif /* _CORECRYPTO_CCMODE_SIV_HMAC_INTERNAL_H */
