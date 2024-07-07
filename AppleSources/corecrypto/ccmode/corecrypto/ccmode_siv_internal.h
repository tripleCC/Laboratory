/* Copyright (c) (2015,2017-2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCMODE_SIV_INTERNAL_H_
#define _CORECRYPTO_CCMODE_SIV_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>

#include <corecrypto/cccmac.h>

int ccmode_siv_init(const struct ccmode_siv *siv, ccsiv_ctx *ctx,
                    size_t rawkey_byte_len, const uint8_t *rawkey);

// Authentication of the adata
int ccmode_siv_auth(ccsiv_ctx *ctx,
                    size_t nbytes, const uint8_t *in);

// Authentication of the last vector (the encrypted part)
int ccmode_siv_auth_finalize(ccsiv_ctx *ctx,
                         size_t nbytes, const uint8_t *in, uint8_t* V);

int ccmode_siv_encrypt(ccsiv_ctx *ctx,
                       size_t nbytes, const uint8_t *in, uint8_t *out);

int ccmode_siv_decrypt(ccsiv_ctx *ctx,
                       size_t nbytes, const uint8_t *in, uint8_t *out);

int ccmode_siv_reset(ccsiv_ctx *ctx);

/* Macros for accessing a CCMODE_SIV.
 {
 const struct ccmode_siv *siv;
 uint8_t key[512/8];
 uint8_t d[512/8];
 cc_unit cmac_ctx[cbc->n];
 cc_unit ctr_ctx[ctr->n];
 } */
#define _CCMODE_SIV_CTX(K) ((struct _ccmode_siv_ctx *)(K))
#define _CCMODE_SIV_CBC_MODE(K) (_CCMODE_SIV_CTX(K)->siv->cbc)
#define _CCMODE_SIV_CTR_MODE(K) (_CCMODE_SIV_CTX(K)->siv->ctr)
#define _CCMODE_SIV_STATE(K)    (_CCMODE_SIV_CTX(K)->state)
#define _CCMODE_SIV_KEYSIZE(K)  (_CCMODE_SIV_CTX(K)->key_bytesize)
#define _CCMODE_SIV_K1(K)       ((uint8_t *)_CCMODE_SIV_CTX(K)->k1)
#define _CCMODE_SIV_K2(K)       ((uint8_t *)_CCMODE_SIV_CTX(K)->k2)
#define _CCMODE_SIV_D(K)        ((uint8_t *)_CCMODE_SIV_CTX(K)->block)

// Maximum size for the block is 128
#define CCSIV_MAX_BLOCK_BYTESIZE 128/8

// Maximum size for the key is 512
#define CCSIV_MAX_KEY_BYTESIZE   512/8

struct _ccmode_siv_ctx {
    const struct ccmode_siv *siv;
    size_t  key_bytesize;
    cc_unit state;
    cc_unit k1[ccn_nof_size(CCSIV_MAX_KEY_BYTESIZE/2)]; // cmac key
    cc_unit k2[ccn_nof_size(CCSIV_MAX_KEY_BYTESIZE/2)]; // ctr key
    cc_unit block[ccn_nof_size(CCSIV_MAX_BLOCK_BYTESIZE)];
};

#endif /* _CORECRYPTO_CCMODE_SIV_INTERNAL_H_ */
