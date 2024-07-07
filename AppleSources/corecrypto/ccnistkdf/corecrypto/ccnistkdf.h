/* Copyright (c) (2013,2015,2017-2019,2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCNISTKDF_H_
#define _CORECRYPTO_CCNISTKDF_H_

#include <corecrypto/cccmac.h>
#include <corecrypto/ccdigest.h>

/**
 Perform a NIST SP800-108 KDF in Counter Mode with an AES-CMAC PRF.

 @param cbc An AES-CBC mode.
 @param r The bit length of the counter i.
 @param kdk_nbytes Key Derivation Key Length
 @param kdk Key derivation key, a key that is used as an input to a key derivation function
 (along with other input data) to derive keying material.
 @param label_nbytes Label length
 @param label A string that identifies the purpose for the derived keying material,
 which is encoded as a binary string. The encoding method for the Label
 is defined in a larger context, for example, in the protocol that uses a KDF.
 @param context_nbytes Context length
 @param context A binary string containing the information related to the derived keying material.
 It may include identities of parties who are deriving and/or using the derived
 keying material and, optionally, a nonce known by the parties who derive the keys.
 @param dk_nbytes Derived Key Length
 @param dk_len_nbytes The number of bytes used to represent the derived key length. A common value is 4.
 @param dk buffer for the results of the KDF transformation, must be dkLen big
 @return 0 if success, negative values on errors.
 */

int ccnistkdf_ctr_cmac(const struct ccmode_cbc *cbc,
                       uint8_t r, size_t kdk_nbytes, const void *kdk,
                       size_t label_nbytes, const void *label,
                       size_t context_nbytes, const void *context,
                       size_t dk_nbytes, size_t dk_len_nbytes, void *dk);

/**
 Performs the NIST SP800-108 KDF in Counter Mode with AES-CMAC using fixed data.

 @param cbc An AES-CBC mode.
 @param r The bit length of the counter i.
 @param kdk_nbytes Key Derivation Key Length
 @param kdk Key derivation key, a key that is used as an input to a key derivation function
 (along with other input data) to derive keying material.
 @param fixedData_nbytes The fixed data length
 @param fixedData The data fixed within the iteration (excluding i and L)
 @param dk_nbytes Derived Key Length
 @param dk KDF result
 @return 0 on success
 */

int ccnistkdf_ctr_cmac_fixed(const struct ccmode_cbc *cbc,
                             uint8_t r, size_t kdk_nbytes, const void *kdk,
                             size_t fixedData_nbytes, const void *fixedData,
                             size_t dk_nbytes, void *dk);

/*! @function ccnistkdf_ctr_hmac

 @abstract          Perform a NIST SP800-108 KDF in Counter Mode with an HMAC PRF.
                    http://csrc.nist.gov/publications/nistpubs/800-108/sp800-108.pdf
 @discussion        This performs the transformation of password and salt through
                    an HMAC PRF of the callers selection (any Digest, typically SHA-256)
                    returning dkLen bytes containing the entropy.


 @param di          Pseudo-random function to be used
 @param kdkLen      Key Derivation Key Length
 @param kdk         Key derivation key, a key that is used as an input to a key derivation function
                    (along with other input data) to derive keying material.
 @param labelLen  	Label length
 @param label	    A string that identifies the purpose for the derived keying material,
                    which is encoded as a binary string. The encoding method for the Label
                    is defined in a larger context, for example, in the protocol that uses a KDF.
 @param contextLen	Context length
 @param context     A binary string containing the information related to the derived keying material.
                    It may include identities of parties who are deriving and/or using the derived
                    keying material and, optionally, a nonce known by the parties who derive the keys.
 @param dkLen       Derived Key Length
 @param dk          buffer for the results of the KDF transformation, must be dkLen big

 */

int ccnistkdf_ctr_hmac(const struct ccdigest_info *di,
                       size_t kdkLen, const void *kdk,
                       size_t labelLen, const void *label,
                       size_t contextLen, const void *context,
                       size_t dkLen, void *dk);

int ccnistkdf_ctr_hmac_fixed(const struct ccdigest_info *di,
                             size_t kdkLen, const void *kdk,
                             size_t fixedDataLen, const void *fixedData,
                             size_t dkLen, void *dk);

#endif /* _CORECRYPTO_CCNISTKDF_H_ */
