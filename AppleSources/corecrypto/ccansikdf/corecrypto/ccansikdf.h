/* Copyright (c) (2014,2015,2018,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCANSIKDF_H
#define _CORECRYPTO_CCANSIKDF_H

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_priv.h>

CC_PTRCHECK_CAPABLE_HEADER()

/*! @function ccansikdf_x963
 @abstract cciovec version of ccansikdf_x963 which allows multiple shared info inputs in disjoint buffers
 
 @param di Digest information
 @param Z_nbytes Length of the input shared secret value Z in bytes
 @param Z Input shared secret value
 @param sharedinfo_nbytes  Length of the input sharedinfo in bytes
 @param sharedinfo Input shared info
 @param key_nbytes The length of the ouptut key in bytes. Must be less than 2^32 - 1
 @param key The output key material
 
 @return CCERR_OK on success, any other value indicates an error
 */
CC_NONNULL((1, 3, 7))
int ccansikdf_x963(const struct ccdigest_info *di,
                   const size_t Z_nbytes,
                   const unsigned char *cc_counted_by(Z_nbytes) Z,
                   const size_t sharedinfo_nbytes,
                   const void *cc_sized_by(sharedinfo_nbytes) sharedinfo,
                   const size_t key_nbytes,
                   uint8_t *cc_counted_by(key_nbytes) key);

#endif // _CORECRYPTO_CCANSIKDF_H
