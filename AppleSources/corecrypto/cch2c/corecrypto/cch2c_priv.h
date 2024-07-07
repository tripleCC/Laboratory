/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cch2c.h>

#if CC_PRIVATE_CRYPTOKIT
/// Perform the map to curve operation.
/// Returns CCERR_OK on success, error value otherwise.
/// @param info Information about the hash-to-curve ciphersuite
/// @param u The scalar to map on the curve
/// @param q The corresponding point on the curve
CC_NONNULL_ALL
int map_to_curve_sswu(const struct cch2c_info *info,
                      const cc_unit *u,
                      ccec_pub_ctx_t q);
#endif
