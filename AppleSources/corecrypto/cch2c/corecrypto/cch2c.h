/* Copyright (c) (2020,2022-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCH2C_H_
#define _CORECRYPTO_CCH2C_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccec.h>

struct cch2c_info;

/*!
    @function cch2c
    @abstract Hash input data to an elliptic curve point as in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05

    @discussion The application-supplied domain-separation tag should include (but not be limited to) the name of the hash-to-curve cipher suite. This is available from the @p name field of the @p cch2c_info structure. The length of the user-supplied input data is limited to 255 bytes.

    @param info Parameters for the hash-to-curve method
    @param dst_nbytes Length of the application-supplied domain-separation tag
    @param dst Application-supplied domain-separation tag
    @param data_nbytes Length of the user-supplied input data
    @param data User-supplied input data
    @param pubkey The output elliptic curve point

    @return 0 on success, an error code otherwise.
 */
int cch2c(const struct cch2c_info *info,
          size_t dst_nbytes, const void *dst,
          size_t data_nbytes, const void *data,
          ccec_pub_ctx_t pubkey);

/*!
    @function cch2c_name
    @abstract Return a name for the given set of parameters

    @discussion This name should be incorporated (along with application-specific information) to create a domain-separation tag. The returned string is null-terminated. Not including the terminator, the longest name is 20 bytes long.

    @param info Parameters for the hash-to-curve method
 */
const char *cch2c_name(const struct cch2c_info *info);

extern const struct cch2c_info cch2c_p256_sha256_sswu_ro_info;
extern const struct cch2c_info cch2c_p384_sha512_sswu_ro_info;
extern const struct cch2c_info cch2c_p521_sha512_sswu_ro_info;
extern const struct cch2c_info cch2c_p256_sha256_sae_compat_info;
extern const struct cch2c_info cch2c_p384_sha384_sae_compat_info;

#endif /* _CORECRYPTO_CCH2C_H_ */
