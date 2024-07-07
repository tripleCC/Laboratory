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

#ifndef _CORECRYPTO_CCDRBG_DF_INTERNAL_H_
#define _CORECRYPTO_CCDRBG_DF_INTERNAL_H_

#include "cc_internal.h"
#include <corecrypto/ccdrbg_df.h>

// This is the internal part of an interface for derivation functions
// for DRBGs to convert high-entropy inputs into key material. The
// sole part of this interface is a function to derive keys; see
// below.

/*!
  @function ccdrbg_df_derive_keys
  @abstract Derive keys from a set of high-entropy inputs
  @param ctx The derivation function context
  @param inputs_count A count of input vectors
  @param inputs A sequence of input vectors
  @param keys_nbytes The sum length of the keys to derive
  @param keys A buffer to hold the derived keys

  @return 0 if successful; negative otherwise
*/
CC_WARN_RESULT
CC_NONNULL((1, 5))
int ccdrbg_df_derive_keys(const ccdrbg_df_ctx_t *ctx,
                          size_t inputs_count,
                          const cc_iovec_t *inputs,
                          size_t keys_nbytes,
                          void *keys);

/*!
  @function ccdrbg_df_bc_derive_keys
  @abstract Derive keys from a set of high-entropy inputs
  @param ctx The derivation function context
  @param inputs_count A count of input vectors
  @param inputs A sequence of input vectors
  @param keys_nbytes The sum length of the keys to derive
  @param keys A buffer to hold the derived keys

  @return 0 if successful; negative otherwise
*/
CC_WARN_RESULT
CC_NONNULL((1, 5))
int ccdrbg_df_bc_derive_keys(const ccdrbg_df_ctx_t *ctx,
                             size_t inputs_count,
                             const cc_iovec_t *inputs,
                             size_t keys_nbytes,
                             void *keys);

#endif /* _CORECRYPTO_CCDRBG_DF_INTERNAL_H_ */
