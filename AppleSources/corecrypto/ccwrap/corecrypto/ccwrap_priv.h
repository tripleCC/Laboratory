/* Copyright (c) (2018,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCWRAP_PRIV_H_
#define _CORECRYPTO_CCWRAP_PRIV_H_

#include <corecrypto/ccwrap.h>

/*!
  @function   ccwrap_auth_encrypt_withiv
  @abstract   Wrap a key.

  @param      ecb_mode   Definition of an ECB implementation
  @param      ctx        An instance of the implementation
  @param      nbytes     Length in bytes of the key
  @param      in         Pointer to the key
  @param      obytes     Return parameter describing the size of the wrapped key
  @param      out        Return parameter pointing to the wrapped key
  @param      iv         The 8-byte IV to use for encryption

  @result     0 iff successful.

  @discussion The ECB implementation must describe a 128-bit block cipher, e.g. AES. The @p nbytes argument describing the length of the unwrapped key must be divisible by 8, greater than or equal to 16, and less than or equal to 65536. The @p out buffer should be allocated by the caller with size @p ccwrap_wrapped_size(nbytes). On success, @p *obytes is set to @p ccwrap_wrapped_size(nbytes). The caller needn't verify this invariant.
*/
CC_NONNULL((1, 2, 4, 5, 6, 7))
int ccwrap_auth_encrypt_withiv(const struct ccmode_ecb *ecb_mode,
                               ccecb_ctx *ctx,
                               size_t nbytes,
                               const void *in,
                               size_t *obytes,
                               void *out,
                               const void *iv);

/*!
  @function   ccwrap_auth_decrypt_withiv
  @abstract   Recover the wrapped key.

  @param      ecb_mode   Definition of an ECB implementation
  @param      ctx        An instance of the implementation
  @param      nbytes     Length in bytes of the wrapped key
  @param      in         Pointer to the wrapped key
  @param      obytes     Return parameter describing the size of the unwrapped key
  @param      out        Return parameter pointing to the unwrapped key
  @param      iv         The 8-byte IV to use for decryption

  @result     0 iff successful.

  @discussion The ECB implementation must describe a 128-bit block cipher, e.g. AES. The @p nbytes argument describing the length of the wrapped key must be divisible by 8, greater than or equal to 24, and less than or equal to 65544. The @p out buffer should be allocated by the caller with size @p ccwrap_unwrapped_size(nbytes). On success, @p *obytes is set to @p ccwrap_unwrapped_size(nbytes). The caller needn't verify this invariant.
*/
CC_NONNULL((1, 2, 4, 5, 6, 7))
int ccwrap_auth_decrypt_withiv(const struct ccmode_ecb *ecb_mode,
                               ccecb_ctx *ctx,
                               size_t nbytes,
                               const void *in,
                               size_t *obytes,
                               void *out,
                               const void *iv);

#endif /* _CORECRYPTO_CCWRAP_PRIV_H_ */
