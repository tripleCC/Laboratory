/* Copyright (c) (2012,2015,2016,2019-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDRBG_IMPL_H_
#define _CORECRYPTO_CCDRBG_IMPL_H_

#include <corecrypto/cc.h>

/* opaque drbg structure */
struct ccdrbg_state;

struct ccdrbg_info {
    /*! Size of the DRBG state in bytes **/
    size_t size;

    /*! Instantiate the DRBG
     @param drbg       The DRBG state
     @param entropylen Length of entropy
     @param entropy    Entropy bytes
     @param inlen      Length of additional input
     @param in         Additional input bytes
     @return 0 if successful
     */
    int (*CC_SPTR(ccdrbg_info, init))(const struct ccdrbg_info *info, struct ccdrbg_state *drbg,
                size_t entropyLength, const void* entropy,
                size_t nonceLength, const void* nonce,
                size_t psLength, const void* ps);

    /*! Add entropy to the DRBG
     @param drbg       The DRBG state
     @param entropylen Length of entropy
     @param entropy    Entropy bytes
     @param inlen      Length of additional input
     @param in         Additional input bytes
     @return 0 if successful
     */
    int (*CC_SPTR(ccdrbg_info, reseed))(struct ccdrbg_state *drbg,
                  size_t entropylen, const void *entropy,
                  size_t inlen, const void *in);

    /*! Read from the DRBG in a FIPS Testing compliant manor
     @param drbg    The DRBG state to read from
     @param out     [out] Where to store the data
     @param outlen  Length of data desired (octets)
     @param inlen   Length of additional input
     @param in      Additional input bytes
     @return 0 if successfull
     */
    int (*CC_SPTR(ccdrbg_info, generate))(struct ccdrbg_state *drbg,
                    size_t outlen, void *out,
                    size_t inlen, const void *in);

    /*! Terminate a DRBG state
     @param drbg   The DRBG state to terminate
     */
    void (*CC_SPTR(ccdrbg_info, done))(struct ccdrbg_state *drbg);

    /** private parameters */
    const void *custom;

    /*! Whether the DRBG requires a reseed to continue generation
     @param drbg    The DRBG state
     @return true if the DRBG requires reseed; false otherwise
     */
    bool (*CC_SPTR(ccdrbg_info, must_reseed))(const struct ccdrbg_state *drbg);
};



#endif // _CORECRYPTO_CCDRBG_IMPL_H_
