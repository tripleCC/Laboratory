/* Copyright (c) (2020,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSIGMA_PRIV_H_
#define _CORECRYPTO_CCSIGMA_PRIV_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccsigma.h>

#define CCSIGMA_KEX_MAX_SHARED_SECRET_SIZE (32)
#define CCSIGMA_AEAD_MAX_TAG_SIZE (16)

ccsigma_role_t ccsigma_peer_role(struct ccsigma_ctx *ctx);

ccec_pub_ctx_t ccsigma_kex_init_ctx(struct ccsigma_ctx *ctx);

ccec_pub_ctx_t ccsigma_kex_resp_ctx(struct ccsigma_ctx *ctx);

int ccsigma_compute_mac(struct ccsigma_ctx *ctx,
                        size_t key_index,
                        size_t data_size,
                        const void *data,
                        void *tag);

#endif /* _CORECRYPTO_CCSIGMA_PRIV_H_ */
