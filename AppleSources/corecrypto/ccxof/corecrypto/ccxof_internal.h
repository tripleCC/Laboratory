/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCXOF_INTERNAL_H_
#define _CORECRYPTO_CCXOF_INTERNAL_H_

#include "cc_internal.h"

struct ccxof_ctx {
    // When absorbing, holds the number of bytes not yet fully absorbed.
    // When squeezing, holds the number of bytes not yet fully squeezed.
    uint32_t nbytes;
    uint32_t squeezing;
    uint8_t b[1];
} CC_ALIGNED(8);

typedef struct ccxof_ctx *ccxof_ctx_t;

struct ccxof_state;
typedef struct ccxof_state *ccxof_state_t;

struct ccxof_info {
    size_t state_nbytes;
    size_t block_nbytes;
    void(* CC_SPTR(ccxof_info, init))(const struct ccxof_info *xi, ccxof_state_t state);
    void(* CC_SPTR(ccxof_info, absorb))(const struct ccxof_info *xi, ccxof_state_t state, size_t nblocks, const uint8_t *in);
    void(* CC_SPTR(ccxof_info, absorb_last))(const struct ccxof_info *xi, ccxof_state_t state, size_t in_nbytes, const uint8_t *in);
    void(* CC_SPTR(ccxof_info, squeeze))(const struct ccxof_info *xi, ccxof_state_t state, size_t out_nbytes, uint8_t *out);
};

#define ccxof_ctx_size(_state_nbytes_, _block_nbytes_) (sizeof(uint64_t) + (_block_nbytes_) + (_state_nbytes_))
#define ccxof_ctx_decl(_state_nbytes_, _block_nbytes_, _name_) cc_ctx_decl(struct ccxof_ctx, ccxof_ctx_size(_state_nbytes_, _block_nbytes_), _name_)
#define ccxof_ctx_clear(_state_nbytes_, _block_nbytes_, _name_) cc_clear(ccxof_ctx_size(_state_nbytes_, _block_nbytes_), _name_)

#define ccxof_nbytes(_xi_, _ctx_) ((_ctx_)->nbytes)
#define ccxof_squeezing(_xi_, _ctx_) ((_ctx_)->squeezing)
#define ccxof_buffer(_xi_, _ctx_) ((_ctx_)->b)
#define ccxof_state(_xi_, _ctx_) ((ccxof_state_t)((_ctx_)->b + (_xi_)->block_nbytes))

void ccxof_init(const struct ccxof_info *xi, ccxof_ctx_t ctx);
void ccxof_absorb(const struct ccxof_info *xi, ccxof_ctx_t ctx, size_t in_nbytes, const uint8_t *in);
void ccxof_squeeze(const struct ccxof_info *xi, ccxof_ctx_t ctx, size_t out_nbytes, uint8_t *out);

#endif /* _CORECRYPTO_CCXOF_INTERNAL_H_ */
