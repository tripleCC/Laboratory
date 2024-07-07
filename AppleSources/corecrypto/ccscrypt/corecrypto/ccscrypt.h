/* Copyright (c) (2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSCRYPT_H_
#define _CORECRYPTO_CCSCRYPT_H_

#include <corecrypto/cc.h>

/*! @function ccscrypt
 @abstract perform scrypt using parameters N, r, and p.
 @discussion |buffer| MUST be allocated space of size at least equal to ccscrypt_storage_size(N, r, p).
  This memory is cleared upon completion of the computation. Otherwise, the result is undefined behavior.

 Considerations: Varying N, r, and p control the amount of memory and CPU resources consumed by the computation.
 See https://www.tarsnap.com/scrypt/scrypt.pdf for details about tuning these parameters.

 @param password_len Length of the password
 @param password     Password to hash
 @param salt_len     Length of per-invocation salt
 @param salt         Per-invocation salt
 @param storage       Temporary storage to be used by the scrypt computation
 @param N            CPU/memory cost parameter
 @param r            Scrypt block size parameter
 @param p            Parallelization parameter
 @param dk_len       Length of the derived key
 @param dk           Output buffer for the derived key, which must be at least |dk_len| bytes long, yet no
                     longer than (2^32 - 1) * 32.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
int
ccscrypt(size_t password_len, const uint8_t *password, size_t salt_len,
         const uint8_t *salt, uint8_t *storage, uint64_t N, uint32_t r,
         uint32_t p, size_t dk_len, uint8_t *dk);

/*! @function ccscrypt_storage_size
 @abstract Compute the amount of temporary memory needed to compute scrypt(N, r, p)
 @discsussion As per https://tools.ietf.org/html/rfc7914#section-2, these parameters
 MUST adhere to the following constraints:

 - N: larger than 1, a power of 2, and less than 2^(128 * r / 8).
 - p: less than or equal to ((2^32-1) * 32) / (128 * r).
 - r: as above.

 @param N            CPU/memory cost parameter
 @param r            Scrypt block size parameter
 @param p            Parallelization parameter

 @return The storage size if the parameters are valid, negative on failure.
 */
int64_t
ccscrypt_storage_size(uint64_t N, uint32_t r, uint32_t p);

#endif /* _CORECRYPTO_CCSCRYPT_H_ */
