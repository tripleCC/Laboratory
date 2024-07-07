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

#include "ccdrbg_df_internal.h"
#include <corecrypto/ccmode.h>
#include "cc_internal.h"

int
ccdrbg_df_derive_keys(const ccdrbg_df_ctx_t *ctx,
                      size_t inputs_count,
                      const cc_iovec_t *inputs,
                      size_t keys_nbytes,
                      void *keys)
{
    int err = ctx->derive_keys(ctx,
                               inputs_count,
                               inputs,
                               keys_nbytes,
                               keys);
    if (CC_UNLIKELY(err != CCERR_OK)) {
        cc_clear(keys_nbytes, keys);
    }

    return err;
}

CC_WARN_RESULT
CC_NONNULL((1, 2, 3, 4, 5))
static int
update(const struct ccmode_cbc *cbc_info,
       const cccbc_ctx *cbc_ctx,
       cccbc_iv *cbc_iv,
       uint8_t *block,
       size_t *block_nbytes_left,
       size_t data_nbytes,
       const void *data)
{
    int err = CCERR_OK;

    const uint8_t *dp = data;

    size_t block_nbytes_want = CCAES_BLOCK_SIZE - (*block_nbytes_left);

    if (*block_nbytes_left > 0 && data_nbytes >= block_nbytes_want) {
        cc_memcpy(block + (*block_nbytes_left), dp, block_nbytes_want);
        err = cccbc_update(cbc_info, cbc_ctx, cbc_iv, 1, block, block);
        cc_require(err == CCERR_OK, out);
        data_nbytes -= block_nbytes_want;
        dp += block_nbytes_want;
        *block_nbytes_left = 0;
    }

    while (data_nbytes >= CCAES_BLOCK_SIZE) {
        err = cccbc_update(cbc_info, cbc_ctx, cbc_iv, 1, dp, block);
        cc_require(err == CCERR_OK, out);
        data_nbytes -= CCAES_BLOCK_SIZE;
        dp += CCAES_BLOCK_SIZE;
    }

    if (data_nbytes > 0) {
        cc_memcpy(block + (*block_nbytes_left), dp, data_nbytes);
        *block_nbytes_left += data_nbytes;
    }

 out:
    return err;
}

int
ccdrbg_df_bc_derive_keys(const ccdrbg_df_ctx_t *df_ctx,
                         size_t inputs_count,
                         const cc_iovec_t *inputs,
                         size_t keys_nbytes,
                         void *keys)
{
    const ccdrbg_df_bc_ctx_t *ctx = (const ccdrbg_df_bc_ctx_t *)df_ctx;

    cccbc_ctx_decl(ctx->cbc_info->size, cbc_ctx);
    cccbc_iv_decl(ctx->cbc_info->block_size, cbc_iv);

    size_t inputs_total_nbytes = 0;
    for (size_t j = 0; j < inputs_count; j += 1) {
        inputs_total_nbytes += inputs[j].nbytes;
    }

    uint32_t prefix[6] = {
        0,
        0,
        0,
        0,
        CC_H2BE32((uint32_t)inputs_total_nbytes),
        CC_H2BE32((uint32_t)keys_nbytes),
    };

    const uint8_t suffix[CCAES_BLOCK_SIZE] = { 0x80 };
    size_t suffix_nbytes = CCAES_BLOCK_SIZE - ((sizeof(prefix) + inputs_total_nbytes) % CCAES_BLOCK_SIZE);

    uint8_t temp[CCAES_KEY_SIZE_256 + CCAES_BLOCK_SIZE];
    size_t temp_nbytes_need = ctx->key_nbytes + CCAES_BLOCK_SIZE;
    size_t temp_nbytes = 0;

    uint8_t block[CCAES_BLOCK_SIZE];

    uint32_t i = 0;
    int err;

    while (temp_nbytes < temp_nbytes_need) {
        cccbc_iv_clear(ctx->cbc_info->block_size, cbc_iv);

        prefix[0] = CC_H2BE32(i);

        uint8_t *p = temp + temp_nbytes;
        size_t left = 0;

        err = update(ctx->cbc_info,
                     ctx->cbc_ctx,
                     cbc_iv,
                     p,
                     &left,
                     sizeof(prefix),
                     prefix);
        cc_require(err == CCERR_OK, out);

        for (size_t j = 0; j < inputs_count; j += 1) {
            err = update(ctx->cbc_info,
                         ctx->cbc_ctx,
                         cbc_iv,
                         p,
                         &left,
                         inputs[j].nbytes,
                         inputs[j].base);
            cc_require(err == CCERR_OK, out);
        }

        err = update(ctx->cbc_info,
                     ctx->cbc_ctx,
                     cbc_iv,
                     p,
                     &left,
                     suffix_nbytes,
                     suffix);
        cc_require(err == CCERR_OK, out);

        i += 1;
        temp_nbytes += CCAES_BLOCK_SIZE;
    }

    err = cccbc_init(ctx->cbc_info, cbc_ctx, ctx->key_nbytes, temp);
    cc_require(err == CCERR_OK, out);

    void *x = temp + ctx->key_nbytes;

    uint8_t *kp = keys;

    while (keys_nbytes > 0) {
        cccbc_iv_clear(ctx->cbc_info->block_size, cbc_iv);

        uint8_t *p = keys_nbytes >= CCAES_BLOCK_SIZE ? kp : block;
        err = cccbc_update(ctx->cbc_info, cbc_ctx, cbc_iv, 1, x, p);
        cc_require(err == CCERR_OK, out);

        if (keys_nbytes < CCAES_BLOCK_SIZE) {
            cc_memcpy(kp, p, keys_nbytes);
        }

        x = p;
        kp += CC_MIN(keys_nbytes, (size_t)CCAES_BLOCK_SIZE);
        keys_nbytes -= CC_MIN(keys_nbytes, (size_t)CCAES_BLOCK_SIZE);
    }

 out:
    cccbc_ctx_clear(ctx->cbc_info->size, cbc_ctx);
    cccbc_iv_clear(ctx->cbc_info->block_size, cbc_iv);
    return err;
}

int
ccdrbg_df_bc_init(ccdrbg_df_bc_ctx_t *ctx,
                  const struct ccmode_cbc *cbc_info,
                  size_t key_nbytes)
{
    CC_ENSURE_DIT_ENABLED

    const uint8_t key[CCAES_KEY_SIZE_256] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    cc_require_or_return(sizeof(ctx->cbc_ctx) >= cbc_info->size, CCERR_CRYPTO_CONFIG);
    cc_require_or_return(key_nbytes <= CCAES_KEY_SIZE_256, CCERR_CRYPTO_CONFIG);
    cc_require_or_return(cbc_info->block_size == CCAES_BLOCK_SIZE, CCERR_CRYPTO_CONFIG);

    ctx->df_ctx.derive_keys = ccdrbg_df_bc_derive_keys;
    ctx->cbc_info = cbc_info;
    ctx->key_nbytes = key_nbytes;

    return cccbc_init(cbc_info, ctx->cbc_ctx, key_nbytes, key);
}
