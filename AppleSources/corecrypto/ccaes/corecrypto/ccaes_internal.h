/* Copyright (c) (2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCAES_INTERNAL_H_
#define _CORECRYPTO_CCAES_INTERNAL_H_

#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_priv.h>

#define CCAES_ROUNDKEY_SIZE 16
#define CCAES_NROUNDS_256 14

/*!
  @function ccaes_unwind_with_ecb
  @abstract "Unwind" an AES encryption key to the equivalent decryption key.

  @param aesecb An AES ECB encryption implementation
  @param key_nbytes Length in bytes of the input AES encryption key
  @param key The input AES encryption key
  @param out The output AES decryption key

  @result @p CCERR_OK iff successful, negative otherwise.
  @discussion Only AES256 (i.e. 32-byte) keys are supported.
*/
int ccaes_unwind_with_ecb(const struct ccmode_ecb *aesecb, size_t key_nbytes, const void *key, void *out);

/// Function to ensure that the key past has a length that corresponds to a correct AES key length in bits or bytes.
/// @param key_nbytes_or_bits Number representing the AES key length in either bits or bytes.
/// @result CCERR_OK if key length corresponds to legitimate length in bits or bytes, and CCERR_PARAMETER otherwise
CC_INLINE int ccaes_key_length_validation(size_t key_nbytes_or_bits)
{
    switch(key_nbytes_or_bits)
    {
        case 16: case 128:
        case 24: case 192:
        case 32: case 256: return CCERR_OK;
        default: return CCERR_PARAMETER;
    }
}

/// Function to ensure that converts a bit length to a byte length
/// @param key_nbytes_or_bits Number representing the AES key length in either bits or bytes.
/// @result Number of bytes necessary to represent key length if it is presented in bits (i.e., the length is greater than 128)
/// @discussion This does not ensure the key length is legitimate. ccaes_key_length_validation should be called first.
CC_INLINE size_t ccaes_key_length_to_nbytes(size_t key_nbytes_or_bits)
{
    if (key_nbytes_or_bits >= 128) {
        return CC_BITLEN_TO_BYTELEN(key_nbytes_or_bits);
    }
    return key_nbytes_or_bits;
}

#endif /* _CORECRYPTO_CCAES_INTERNAL_H_ */
