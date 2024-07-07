/* Copyright (c) (2012,2015,2016,2018,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCWRAP_H_
#define _CORECRYPTO_CCWRAP_H_

#include <corecrypto/ccmode.h>

#define CCWRAP_IV 0xA6A6A6A6A6A6A6A6
#define CCWRAP_SEMIBLOCK 8

// chosen somewhat arbitrarily
// corresponds to 65536 bytes of key material and one eight-byte IV
#define CCWRAP_MAXSEMIBLOCKS 8193

/*!
  @function   ccwrap_wrapped_size

  @param      data_size  The size of the unwrapped key

  @result     The size of the key after wrapping
*/
size_t ccwrap_wrapped_size(const size_t data_size);

/*!
  @function   ccwrap_unwrapped_size

  @param      data_size  The size of the wrapped key

  @result     The size of the key after unwrapping

  @discussion If the input is illegal (i.e. it is smaller than the overhead imposed by wrapping), the result will be zero.
*/
size_t ccwrap_unwrapped_size(const size_t data_size);

/*!
  @function   ccwrap_auth_encrypt
  @abstract   Wrap a key.

  @param      ecb_mode   Definition of an ECB implementation
  @param      ctx        An instance of the implementation
  @param      nbytes     Length in bytes of the key
  @param      in         Pointer to the key
  @param      obytes     Return parameter describing the size of the wrapped key
  @param      out        Return parameter pointing to the wrapped key

  @result     0 iff successful.

  @discussion The ECB implementation must describe a 128-bit block cipher, e.g. AES. The @p nbytes argument describing the length of the unwrapped key must be divisible by 8, greater than or equal to 16, and less than or equal to 65536. The @p out buffer should be allocated by the caller with size @p ccwrap_wrapped_size(nbytes). On success, @p *obytes is set to @p ccwrap_wrapped_size(nbytes). The caller needn't verify this invariant.
*/
CC_NONNULL((1, 2, 4, 5, 6))
int ccwrap_auth_encrypt(const struct ccmode_ecb *ecb_mode,
                        ccecb_ctx *ctx,
                        size_t nbytes,
                        const void *in,
                        size_t *obytes,
                        void *out);

/*!
  @function   ccwrap_auth_decrypt
  @abstract   Recover the wrapped key.

  @param      ecb_mode   Definition of an ECB implementation
  @param      ctx        An instance of the implementation
  @param      nbytes     Length in bytes of the wrapped key
  @param      in         Pointer to the wrapped key
  @param      obytes     Return parameter describing the size of the unwrapped key
  @param      out        Return parameter pointing to the unwrapped key

  @result     0 iff successful.

  @discussion The ECB implementation must describe a 128-bit block cipher, e.g. AES. The @p nbytes argument describing the length of the wrapped key must be divisible by 8, greater than or equal to 24, and less than or equal to 65544. The @p out buffer should be allocated by the caller with size @p ccwrap_unwrapped_size(nbytes). On success, @p *obytes is set to @p ccwrap_unwrapped_size(nbytes). The caller needn't verify this invariant.
*/
CC_NONNULL((1, 2, 4, 5, 6))
int ccwrap_auth_decrypt(const struct ccmode_ecb *ecb_mode,
                        ccecb_ctx *ctx,
                        size_t nbytes,
                        const void *in,
                        size_t *obytes,
                        void *out);

/*
    This was originally implemented according to the “AES Key Wrap Specification”
    formalized in RFC 3394.

    The following publications track changes made over time:

   [AES-KW1] National Institute of Standards and Technology, AES Key
         Wrap Specification, 17 November 2001.
         http://csrc.nist.gov/groups/ST/toolkit/documents/kms/
         AES_key_wrap.pdf

   [AES-KW2] Schaad, J. and R. Housley, "Advanced Encryption Standard
             (AES) Key Wrap Algorithm", RFC 3394, September 2002.

    Note: block size is required to be 128 bits.

    This implementation wraps plaintexts between two and (CCWRAP_MAXSEMIBLOCKS-1)
    semiblocks in length to produce ciphertexts between three and
    CCWRAP_MAXSEMIBLOCKS semiblocks in length. All other inputs are rejected.

    While only the original unpadded algorithm is implemented at this time, the
    following documents include specifications for padded versions allowing
    plaintexts of arbitrary length:

        http://tools.ietf.org/html/rfc5649

        NIST SP800-38F

*/

#endif /* _CORECRYPTO_CCWRAP_H_ */
