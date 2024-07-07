/* Copyright (c) (2014-2016,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccsymmetric_pad.h"

cbc_pad_crypt_f cbc_pad_crypt_funcs[ccpad_cnt][cc_NDirections]={
    {&ccpad_cts1_encrypt, &ccpad_cts1_decrypt},
    {&ccpad_cts2_encrypt, &ccpad_cts2_decrypt},
    {&ccpad_cts3_encrypt, &ccpad_cts3_decrypt},
    {&ccpad_pkcs7_encrypt,&ccpad_pkcs7_decrypt},
    {NULL, NULL},
};

ecb_pad_crypt_f ecb_pad_crypt_funcs[ccpad_cnt][cc_NDirections]={
    {NULL, NULL},
    {NULL, NULL},
    {NULL, NULL},
    {&ccpad_pkcs7_ecb_encrypt,&ccpad_pkcs7_ecb_decrypt},
    {NULL, NULL},
};

size_t
cc_symmetric_crypt_pad(cc_symmetric_context_p ctx,ccpad_select pad, const void *iv, const void *in, void *out, size_t len) {
    size_t result_len=0;

    if (pad>=ccpad_cnt) {
        return 0; // error
    }
    if  (ctx->mode_desc->mode==cc_ModeECB) {
        result_len=ecb_pad_crypt_funcs[pad][ctx->mode_desc->direction](ctx->mode_desc->ciphermode.ecb,
                                                              ctx->ctx.ecb,
                                                              len,in,out);
    }
    else if (ctx->mode_desc->mode==cc_ModeCBC) {
        cccbc_iv_decl(ctx->mode_desc->ciphermode.cbc->block_size, cbciv);
        cccbc_set_iv(ctx->mode_desc->ciphermode.cbc, cbciv, iv);
        result_len=cbc_pad_crypt_funcs[pad][ctx->mode_desc->direction](ctx->mode_desc->ciphermode.cbc,
                                                                         ctx->ctx.cbc,
                                                                         cbciv, len, in, out);
    }
    return result_len;
}


