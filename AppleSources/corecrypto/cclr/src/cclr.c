/* Copyright (c) (2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cclr_internal.h"
#include "ccaes.h"
#include "ccmode.h"

size_t cclr_block_nbytes(const cclr_ctx_t *lr_ctx)
{
    CC_ENSURE_DIT_ENABLED

    return (lr_ctx->block_nbits + 7) / 8;
}

static int cclr_aes_prf_eval(const cclr_ctx_t *lr_ctx,
                             void *out,
                             const void *in)
{
    const cclr_aes_ctx_t *ctx = (const cclr_aes_ctx_t *)lr_ctx;
    const struct ccmode_ecb *aes_info = ctx->aes_info;
    ccecb_ctx *aes_ctx = ctx->aes_ctx;

    return ccecb_update(aes_info, aes_ctx, 1, in, out);
}

static const cclr_info_t cclr_aes_info = {
    .prf_eval = cclr_aes_prf_eval,
};

static int cclr_init(const cclr_info_t *info,
                     cclr_ctx_t *ctx,
                     size_t block_nbits,
                     size_t nrounds)
{
    int err = CCERR_PARAMETER;
    cc_require(block_nbits > 0, exit);
    cc_require(block_nbits <= CCLR_MAX_BLOCK_NBITS, exit);
    cc_require(block_nbits % 8 == 0, exit);
    cc_require(nrounds >= CCLR_MIN_NROUNDS, exit);
    cc_require(nrounds <= CCLR_MAX_NROUNDS, exit);

    ctx->info = info;
    ctx->block_nbits = block_nbits;
    ctx->nrounds = nrounds;

    err = CCERR_OK;

 exit:
    return err;
}

int cclr_aes_init(cclr_aes_ctx_t *ctx,
                  const struct ccmode_ecb *aes_info,
                  ccecb_ctx *aes_ctx,
                  size_t block_nbits,
                  size_t nrounds)
{
    CC_ENSURE_DIT_ENABLED

    ctx->aes_info = aes_info;
    ctx->aes_ctx = aes_ctx;

    return cclr_init(&cclr_aes_info,
                     &ctx->lr_ctx,
                     block_nbits,
                     nrounds);
}

static void cclr_pack(size_t nbytes,
                      uint8_t *dst,
                      const uint8_t *src,
                      size_t k)
{
    if (k == 0) {
        cc_memcpy(dst, src, nbytes);
        return;
    }

    size_t i;
    for (i = 0; i < nbytes - 1; i += 1) {
        dst[i] = (uint8_t)((src[i] << k) | (src[i + 1] >> (8 - k)));
    }

    dst[i] = (uint8_t)(src[i] << k);
}

static void cclr_unpack(size_t nbytes,
                        uint8_t *dst,
                        const uint8_t *src,
                        size_t k)
{
    if (k == 0) {
        cc_memcpy(dst, src, nbytes);
        return;
    }

    size_t i;
    for (i = nbytes - 1; i > 0; i -= 1) {
        dst[i] = (uint8_t)((src[i] >> k) | (src[i - 1] << (8 - k)));
    }

    dst[i] = (uint8_t)(src[i] >> k);
}

typedef struct cclr_halfblock {
    uint8_t data[CCLR_MAX_HALF_BLOCK_NBYTES];
    size_t nbytes;
    uint8_t mask;
} cclr_halfblock_t;

static int cclr_permute(const cclr_ctx_t *ctx,
                        size_t block_nbytes,
                        void *out,
                        const void *in,
                        const uint8_t *subkeys)
{
    int err = CCERR_PARAMETER;

    cc_require(block_nbytes == cclr_block_nbytes(ctx), exit);

    uint8_t *out_bytes = out;
    const uint8_t *in_bytes = in;

    uint8_t prf_in[CCLR_MAX_PRF_NBYTES] = {
        (uint8_t)ctx->block_nbits,
        (uint8_t)ctx->nrounds,
    };
    uint8_t prf_out[CCLR_MAX_PRF_NBYTES];

    cclr_halfblock_t halfblocks[2] = { 0 };
    cclr_halfblock_t *L = &halfblocks[0];
    cclr_halfblock_t *R = &halfblocks[1];

    size_t L_nbits = ctx->block_nbits / 2;
    L->nbytes = (L_nbits + 7) / 8;
    L->mask = (uint8_t)(0xff << (L_nbits % 8));

    cc_memcpy(L->data, in_bytes, L->nbytes);
    L->data[L->nbytes - 1] &= L->mask;

    size_t R_nbits = (ctx->block_nbits + 1) / 2;
    R->nbytes = (R_nbits + 7) / 8;
    size_t R_offset = L_nbits / 8;
    size_t R_shift = L_nbits % 8;
    size_t R_nbytes_unpacked = ((ctx->block_nbits + 7) / 8) - R_offset;
    cclr_pack(R_nbytes_unpacked, R->data, in_bytes + R_offset, R_shift);

    R->mask = (uint8_t)(0xff << (R_nbits % 8));
    R->data[R->nbytes - 1] &= R->mask;

    size_t halfblock_max_nbytes = R->nbytes;

    for (size_t i = 0; i < ctx->nrounds; i += 1) {
        uint8_t subkey = subkeys[i];

        L = &halfblocks[subkey % 2];
        R = &halfblocks[(subkey + 1) % 2];

        prf_in[2] = subkey;
        cc_memcpy(prf_in + 3, R->data, halfblock_max_nbytes);

        err = ctx->info->prf_eval(ctx, prf_out, prf_in);
        cc_require(err == CCERR_OK, exit);

        cc_xor(L->nbytes, L->data, L->data, prf_out);
        L->data[L->nbytes - 1] &= L->mask;
    }

    L = &halfblocks[0];
    R = &halfblocks[1];

    out_bytes[L->nbytes - 1] = 0;
    cclr_unpack(R_nbytes_unpacked, out_bytes + R_offset, R->data, R_shift);
    cc_memcpy(out_bytes, L->data, L->nbytes - 1);
    out_bytes[L->nbytes - 1] |= L->data[L->nbytes - 1];

 exit:
    if (err != CCERR_OK) {
        cc_clear(block_nbytes, out);
    }
    cc_clear(sizeof(halfblocks), halfblocks);
    cc_clear(sizeof(prf_in), prf_in);
    cc_clear(sizeof(prf_out), prf_out);
    return err;
}

int cclr_encrypt_block(const cclr_ctx_t *ctx,
                       size_t block_nbytes,
                       void *ctext_block,
                       const void *ptext_block)
{
    CC_ENSURE_DIT_ENABLED

    int err = CCERR_PARAMETER;
    cc_require(ctx->nrounds >= CCLR_MIN_NROUNDS, exit);
    cc_require(ctx->nrounds <= CCLR_MAX_NROUNDS, exit);

    uint8_t subkeys[CCLR_MAX_NROUNDS];

    for (uint8_t i = 0; i < ctx->nrounds; i += 1) {
        subkeys[i] = i;
    }

    err = cclr_permute(ctx, block_nbytes, ctext_block, ptext_block, subkeys);

 exit:
    return err;
}

int cclr_decrypt_block(const cclr_ctx_t *ctx,
                       size_t block_nbytes,
                       void *ptext_block,
                       const void *ctext_block)
{
    CC_ENSURE_DIT_ENABLED

    int err = CCERR_PARAMETER;
    cc_require(ctx->nrounds >= CCLR_MIN_NROUNDS, exit);
    cc_require(ctx->nrounds <= CCLR_MAX_NROUNDS, exit);

    uint8_t subkeys[CCLR_MAX_NROUNDS];

    for (uint8_t i = 0; i < ctx->nrounds; i += 1) {
        subkeys[i] = (uint8_t)(ctx->nrounds - i - 1);
    }

    err = cclr_permute(ctx, block_nbytes, ptext_block, ctext_block, subkeys);

 exit:
    return err;
}
