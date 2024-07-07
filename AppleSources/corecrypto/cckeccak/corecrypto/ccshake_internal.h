/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSHAKE_INTERNAL_H_
#define _CORECRYPTO_CCSHAKE_INTERNAL_H_

#include <corecrypto/cc.h>
#include "ccxof_internal.h"
#include "cckeccak_internal.h"

#define CCSHAKE256_RATE 136
#define CCSHAKE128_RATE 168

const struct ccxof_info *ccshake128_xi(void);
const struct ccxof_info *ccshake256_xi(void);

#define ccshake128_ctx_decl(_name_) ccxof_ctx_decl(CCKECCAK_STATE_NBYTES, CCSHAKE128_RATE, _name_)
#define ccshake128_ctx_clear(_name_) ccxof_ctx_clear(CCKECCAK_STATE_NBYTES, CCSHAKE128_RATE, _name_)

#define ccshake256_ctx_decl(_name_) ccxof_ctx_decl(CCKECCAK_STATE_NBYTES, CCSHAKE256_RATE, _name_)
#define ccshake256_ctx_clear(_name_) ccxof_ctx_clear(CCKECCAK_STATE_NBYTES, CCSHAKE256_RATE, _name_)

/// @function ccshake128
/// @abstract Perform the `shake128` operation on input bytes `in`
/// @param in_nbytes The byte length of the input buffer `in`
/// @param in The input buffer
/// @param out_nbytes The byte length of the output buffer `out`
/// @param out The output buffer
CC_NONNULL_ALL
void ccshake128(size_t in_nbytes,
                const uint8_t *cc_sized_by(in_nbytes) in,
                size_t out_nbytes,
                uint8_t *cc_sized_by(out_nbytes) out);

/// @function ccshake256
/// @abstract Perform the `shake256` operation on input bytes `in`
/// @param in_nbytes The byte length of the input buffer `in`
/// @param in The input buffer
/// @param out_nbytes The byte length of the output buffer `out`
/// @param out The output buffer
CC_NONNULL_ALL
void ccshake256(size_t in_nbytes,
                const uint8_t *cc_sized_by(in_nbytes) in,
                size_t out_nbytes,
                uint8_t *cc_sized_by(out_nbytes) out);

/// @function ccshake_init
/// @abstract Initializes a `ccxof_state` for SHAKE.
/// @param xi The XOF info.
/// @param state The XOF state.
void ccshake_init(const struct ccxof_info *xi, ccxof_state_t state);

#endif /* _CORECRYPTO_CCSHAKE_INTERNAL_H_ */
