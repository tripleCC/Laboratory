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

#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"
#include "cc_debug.h"

#if (CCLR == 0)
entryPoint(cclr_tests, "cclr test")
#else
#include "cclr_internal.h"

static void lr_test_roundtrip(cclr_ctx_t *lr_ctx)
{
    size_t block_nbytes = cclr_block_nbytes(lr_ctx);
    size_t nblocks = 1 << lr_ctx->block_nbits;
    uint32_t *blocks = calloc(nblocks, sizeof(uint32_t));

    for (uint32_t i = 0; i < nblocks; i += 1) {
        blocks[i] = CC_H2LE32(i);

        int err;

        err = cclr_encrypt_block(lr_ctx, block_nbytes, &blocks[i], &blocks[i]);
        is(err, CCERR_OK, "lr_test_roundtrip cclr_encrypt_block; block %u failed", i);

        err = cclr_decrypt_block(lr_ctx, block_nbytes, &blocks[i], &blocks[i]);
        is(err, CCERR_OK, "lr_test_roundtrip cclr_decrypt_block; block %u failed", i);

        is(blocks[i], CC_H2LE32(i), "lr_test_roundtrip %zu bits; block %u incorrect", lr_ctx->block_nbits, i);
    }

    free(blocks);
}

int cclr_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests((3 * (1 << 8)) +
               (3 * (1 << 16)) +
               (3 * (1 << 24)) +
               4);

    cclr_aes_ctx_t lr_ctx;
    const uint8_t key[] = {
        0x59, 0x45, 0x4c, 0x4c, 0x4f, 0x57, 0x20, 0x53,
        0x55, 0x42, 0x4d, 0x41, 0x52, 0x49, 0x4e, 0x45,
    };

    const struct ccmode_ecb *aes_info = ccaes_ecb_encrypt_mode();
    ccecb_ctx_decl(ccecb_context_size(aes_info), aes_ctx);
    int err = ccecb_init(aes_info, aes_ctx, sizeof(key), key);
    is(err, CCERR_OK, "ccecb_init");

    size_t block_nbits_list[] = {
        8, 16, 24,
    };

    for (size_t i = 0; i < CC_ARRAY_LEN(block_nbits_list); i += 1) {
        size_t block_nbits = block_nbits_list[i];

        err = cclr_aes_init(&lr_ctx,
                            aes_info, aes_ctx,
                            block_nbits, 10);
        is(err, CCERR_OK, "cclr_aes_init(%zu bits, 10 rounds)", block_nbits);

        lr_test_roundtrip(&lr_ctx.lr_ctx);
    }


    return 0;
}
#endif // (CCLR != 0)
