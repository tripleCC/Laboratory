/* Copyright (c) (2014-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cczp.h>

#if CC_PRIVATE_CRYPTOKIT

/// Computes the addition of two scalars in a prime-order group (r = x + y mod cczp_prime(zp)).
/// Returns CCERR_OK on success, error value otherwise.
/// @param zp Prime-order group
/// @param r Scalar resulting from the addition
/// @param x Scalar of the addition operation
/// @param y Scalar of the addition operation
CC_NONNULL_ALL
int cczp_add(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/// Computes the substraction of two scalars in a prime-order group (r = x + y mod cczp_prime(zp)).
/// Returns CCERR_OK on success, error value otherwise.
/// @param zp Prime-order group
/// @param r Scalar resulting from the substraction.
/// @param x Scalar of the substraction operation
/// @param y Scalar of the substraction operation
CC_NONNULL_ALL
int cczp_sub(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/// Computes the multiplication of two scalars in a prime-order group (r = x*y mod cczp_prime(zp)).
/// Returns CCERR_OK on success, error value otherwise.
/// @param zp Prime-order group
/// @param r Scalar resulting from the multiplication.
/// @param x Scalar of the multiplication operation
/// @param y Scalar of the multiplication operation
CC_NONNULL_ALL
int cczp_mul(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/// Computes the inverse of a scalar in a prime-order group via constant-time binary XGCD.
/// Returns CCERR_OK on success, error value otherwise.
/// @param zp Prime-order group
/// @param r Scalar resulting from the inversion
/// @param x The scalar to inverse (0 < x < p)
CC_NONNULL_ALL
int cczp_inv(cczp_const_t zp, cc_unit *r, const cc_unit *x);

/// Computes a scalar modulo p in a prime-order group.
/// Returns CCERR_OK on success, error value otherwise.
/// @param zp Prime-order group
/// @param r The resulting scalar mod p
/// @param x The input scalar
CC_NONNULL_ALL
int cczp_mod(cczp_const_t zp, cc_unit *r, const cc_unit *x);

#endif
