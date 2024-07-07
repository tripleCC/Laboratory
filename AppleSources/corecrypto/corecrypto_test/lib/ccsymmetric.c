/* Copyright (c) (2012,2014-2016,2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdbool.h>
#include "ccsymmetric.h"
#include "testmore.h"

int cc_get_ciphermode(cc_cipher_select cipher, cc_mode_select mode, cc_direction direction, cc_ciphermode_descriptor desc)
{
    desc->cipher = cipher;
    desc->mode = mode;
    desc->direction = direction;
    desc->ciphermode.data = NULL;
    int op = direction == cc_Encrypt; // save editting flip-flop logic
    switch (cipher) {
    case cc_cipherAES:
        switch (mode) {
        case cc_ModeECB:
            desc->ciphermode.ecb = (op) ? ccaes_ecb_encrypt_mode() : ccaes_ecb_decrypt_mode();
            break;
        case cc_ModeCBC:
            desc->ciphermode.cbc = (op) ? ccaes_cbc_encrypt_mode() : ccaes_cbc_decrypt_mode();
            break;
        case cc_ModeCFB:
            desc->ciphermode.cfb = (op) ? ccaes_cfb_encrypt_mode() : ccaes_cfb_decrypt_mode();
            break;
        case cc_ModeCTR:
            desc->ciphermode.ctr = ccaes_ctr_crypt_mode();
            break;
        case cc_ModeOFB:
            desc->ciphermode.ofb = ccaes_ofb_crypt_mode();
            break;
        case cc_ModeXTS:
            desc->ciphermode.xts = (op) ? ccaes_xts_encrypt_mode() : ccaes_xts_decrypt_mode();
            break;
        case cc_ModeCFB8:
            desc->ciphermode.cfb8 = (op) ? ccaes_cfb8_encrypt_mode() : ccaes_cfb8_decrypt_mode();
            break;
        case cc_ModeGCM:
            desc->ciphermode.gcm = (op) ? ccaes_gcm_encrypt_mode() : ccaes_gcm_decrypt_mode();
            break;
        case cc_ModeCCM:
            desc->ciphermode.ccm = (op) ? ccaes_ccm_encrypt_mode() : ccaes_ccm_decrypt_mode();
            break;
        }
        break;
    case cc_cipherDES:
        switch (mode) {
        case cc_ModeECB:
            desc->ciphermode.ecb = (op) ? ccdes_ecb_encrypt_mode() : ccdes_ecb_decrypt_mode();
            break;
        case cc_ModeCBC:
            desc->ciphermode.cbc = (op) ? ccdes_cbc_encrypt_mode() : ccdes_cbc_decrypt_mode();
            break;
        case cc_ModeCFB:
            desc->ciphermode.cfb = (op) ? ccdes_cfb_encrypt_mode() : ccdes_cfb_decrypt_mode();
            break;
        case cc_ModeCTR:
            desc->ciphermode.ctr = ccdes_ctr_crypt_mode();
            break;
        case cc_ModeOFB:
            desc->ciphermode.ofb = ccdes_ofb_crypt_mode();
            break;
        case cc_ModeCFB8:
            desc->ciphermode.cfb8 = (op) ? ccdes_cfb8_encrypt_mode() : ccdes_cfb8_decrypt_mode();
            break;
        }
        break;
    case cc_cipher3DES:
        switch (mode) {
        case cc_ModeECB:
            desc->ciphermode.ecb = (op) ? ccdes3_ecb_encrypt_mode() : ccdes3_ecb_decrypt_mode();
            break;
        case cc_ModeCBC:
            desc->ciphermode.cbc = (op) ? ccdes3_cbc_encrypt_mode() : ccdes3_cbc_decrypt_mode();
            break;
        case cc_ModeCFB:
            desc->ciphermode.cfb = (op) ? ccdes3_cfb_encrypt_mode() : ccdes3_cfb_decrypt_mode();
            break;
        case cc_ModeCTR:
            desc->ciphermode.ctr = ccdes3_ctr_crypt_mode();
            break;
        case cc_ModeOFB:
            desc->ciphermode.ofb = ccdes3_ofb_crypt_mode();
            break;
        case cc_ModeCFB8:
            desc->ciphermode.cfb8 = (op) ? ccdes3_cfb8_encrypt_mode() : ccdes3_cfb8_decrypt_mode();
            break;
        }
        break;
    case cc_cipherCAST:
        switch (mode) {
        case cc_ModeECB:
            desc->ciphermode.ecb = (op) ? cccast_ecb_encrypt_mode() : cccast_ecb_decrypt_mode();
            break;
        case cc_ModeCBC:
            desc->ciphermode.cbc = (op) ? cccast_cbc_encrypt_mode() : cccast_cbc_decrypt_mode();
            break;
        case cc_ModeCFB:
            desc->ciphermode.cfb = (op) ? cccast_cfb_encrypt_mode() : cccast_cfb_decrypt_mode();
            break;
        case cc_ModeCTR:
            desc->ciphermode.ctr = cccast_ctr_crypt_mode();
            break;
        case cc_ModeOFB:
            desc->ciphermode.ofb = cccast_ofb_crypt_mode();
            break;
        case cc_ModeCFB8:
            desc->ciphermode.cfb8 = (op) ? cccast_cfb8_encrypt_mode() : cccast_cfb8_decrypt_mode();
            break;
        }
        break;
    case cc_cipherRC2:
        switch (mode) {
        case cc_ModeECB:
            desc->ciphermode.ecb = (op) ? ccrc2_ecb_encrypt_mode() : ccrc2_ecb_decrypt_mode();
            break;
        case cc_ModeCBC:
            desc->ciphermode.cbc = (op) ? ccrc2_cbc_encrypt_mode() : ccrc2_cbc_decrypt_mode();
            break;
        case cc_ModeCFB:
            desc->ciphermode.cfb = (op) ? ccrc2_cfb_encrypt_mode() : ccrc2_cfb_decrypt_mode();
            break;
        case cc_ModeCTR:
            desc->ciphermode.ctr = ccrc2_ctr_crypt_mode();
            break;
        case cc_ModeOFB:
            desc->ciphermode.ofb = ccrc2_ofb_crypt_mode();
            break;
        case cc_ModeCFB8:
            desc->ciphermode.cfb8 = (op) ? ccrc2_cfb8_encrypt_mode() : ccrc2_cfb8_decrypt_mode();
            break;
        }
        break;
    case cc_cipherBlowfish:
        switch (mode) {
        case cc_ModeECB:
            desc->ciphermode.ecb = (op) ? ccblowfish_ecb_encrypt_mode() : ccblowfish_ecb_decrypt_mode();
            break;
        case cc_ModeCBC:
            desc->ciphermode.cbc = (op) ? ccblowfish_cbc_encrypt_mode() : ccblowfish_cbc_decrypt_mode();
            break;
        case cc_ModeCFB:
            desc->ciphermode.cfb = (op) ? ccblowfish_cfb_encrypt_mode() : ccblowfish_cfb_decrypt_mode();
            break;
        case cc_ModeCTR:
            desc->ciphermode.ctr = ccblowfish_ctr_crypt_mode();
            break;
        case cc_ModeOFB:
            desc->ciphermode.ofb = ccblowfish_ofb_crypt_mode();
            break;
        case cc_ModeCFB8:
            desc->ciphermode.cfb8 = (op) ? ccblowfish_cfb8_encrypt_mode() : ccblowfish_cfb8_decrypt_mode();
            break;
        }
        break;
    }
    if (desc->ciphermode.data == NULL)
        return CC_FAILURE;
    return CC_SUCCESS;
}

int cc_get_C_ciphermode(cc_cipher_select cipher, cc_mode_select mode, cc_direction direction, cc_ciphermode_descriptor desc)
{
    desc->cipher = cipher;
    desc->mode = mode;
    desc->direction = direction;
    desc->ciphermode.data = NULL;
    return CC_UNIMPLEMENTED;
}

static bool verify_and_ok_duplicate_key(const uint8_t *key, size_t keylen)
{
    if (keylen != 24) {
        return false;
    }
    if (memcmp(key, key+8, 8) == 0 || memcmp(key, key+16, 8) == 0 || memcmp(key+8, key+16, 8) == 0) {
        return true;
    }
    return false;
}

int cc_symmetric_setup(cc_ciphermode_descriptor cm, const void *key, size_t keylen, const void *iv, cc_symmetric_context_p ctx)
{
    int rc;
    switch (cm->mode) {
    case cc_ModeECB:
        rc = cm->ciphermode.ecb->init(cm->ciphermode.ecb, ctx->ctx.ecb, keylen, key);
        break;
    case cc_ModeCBC:
        rc = cm->ciphermode.cbc->init(cm->ciphermode.cbc, ctx->ctx.cbc, keylen, key);
        break;
    case cc_ModeCFB:
        rc = cm->ciphermode.cfb->init(cm->ciphermode.cfb, ctx->ctx.cfb, keylen, key, iv);
        break;
    case cc_ModeCTR:
        rc = cm->ciphermode.ctr->init(cm->ciphermode.ctr, ctx->ctx.ctr, keylen, key, iv);
        break;
    case cc_ModeOFB:
        rc = cm->ciphermode.ofb->init(cm->ciphermode.ofb, ctx->ctx.ofb, keylen, key, iv);
        break;
    case cc_ModeCFB8:
        rc = cm->ciphermode.cfb8->init(cm->ciphermode.cfb8, ctx->ctx.cfb8, keylen, key, iv);
        break;
    default:
        return CC_FAILURE;
    }
    // 3DES was modified to return an error of -1 on a 3DES key setup which repeated any of the sub-keys
    // However, we still want to test these historic test vectors. So if we get a fail on setup we verify that it is
    // for a repeated key in 3DES, and if so, we continue with the test.
    if ((rc == -1) && (cm->cipher == cc_cipher3DES)) {
        rc = verify_and_ok_duplicate_key(key, keylen) ? 0 : rc;
    }

    return (rc == 0) ? CC_SUCCESS : CC_FAILURE;
}

int cc_symmetric_setup_tweaked(cc_ciphermode_descriptor cm,
                               const void *key,
                               size_t keylen,
                               const void *tweak,
                               CC_UNUSED const void *iv,
                               cc_symmetric_context_p ctx)
{
    switch (cm->mode) {
    case cc_ModeXTS:
        if (cm->ciphermode.xts->init(cm->ciphermode.xts, ctx->ctx.xts, keylen, key, tweak) == 0) {
            return CC_SUCCESS;
        }
    }
    return CC_FAILURE;
}

int cc_symmetric_setup_authenticated(cc_ciphermode_descriptor cm,
                                     const void *key,
                                     size_t keylen,
                                     const void *iv,
                                     size_t iv_len,
                                     const void *adata,
                                     size_t adata_len,
                                     const void *adata2,
                                     size_t adata2_len,
                                     size_t data_len,
                                     size_t tag_len,
                                     cc_symmetric_context_p ctx)
{
    int rc;
    switch (cm->mode) {
    case cc_ModeGCM:
        rc = ccgcm_init(cm->ciphermode.gcm, ctx->ctx.gcm, keylen, key);
        if (rc == 0)
            rc = ccgcm_set_iv(cm->ciphermode.gcm, ctx->ctx.gcm, iv_len, iv);
        if (rc == 0)
            rc = ccgcm_aad(cm->ciphermode.gcm, ctx->ctx.gcm, adata_len, adata);
        break;
    case cc_ModeCCM:
        rc = ccccm_init(cm->ciphermode.ccm, ctx->ctx.ccm, keylen, key);
        if (rc == 0)
            rc =
                ccccm_set_iv(cm->ciphermode.ccm, ctx->ctx.ccm, ctx->xtra_ctx.ccm_nonce, iv_len, iv, tag_len, adata_len, data_len);
        if (rc == 0)
            rc = ccccm_cbcmac(cm->ciphermode.ccm, ctx->ctx.ccm, ctx->xtra_ctx.ccm_nonce, adata_len, adata);
        break;
    case cc_ModeSIV:
        rc = ccsiv_init(cm->ciphermode.siv, ctx->ctx.siv, keylen, key);
        if (rc == 0)
            rc = ccsiv_aad(cm->ciphermode.siv, ctx->ctx.siv, adata_len, adata);
        if (rc == 0)
            rc = ccsiv_aad(cm->ciphermode.siv, ctx->ctx.siv, adata2_len, adata2);
        if (rc == 0)
            rc = ccsiv_set_nonce(cm->ciphermode.siv, ctx->ctx.siv, iv_len, iv);
        break;
    case cc_ModeSIV_HMAC:
             rc = ccsiv_hmac_init(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, keylen, key, tag_len);
            if (adata_len == 0){
                is(ccsiv_hmac_aad(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, adata_len, adata), CCMODE_AD_EMPTY, "Empty associated data not reported as error.");
            }
            if (rc == 0 && adata_len != 0)
                rc = ccsiv_hmac_aad(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, adata_len, adata);
            if (rc == 0 && adata2_len != 0)
                rc = ccsiv_hmac_aad(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, adata2_len, adata2);
            
            if (iv_len == 0){
                is(ccsiv_hmac_set_nonce(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, iv_len, iv), CCMODE_NONCE_EMPTY, "Empty nonce data not reported as error.");
            }
            if (rc == 0 && iv_len != 0)
                rc = ccsiv_hmac_set_nonce(cm->ciphermode.siv_hmac, ctx->ctx.siv_hmac, iv_len, iv);
            break;
        
    default:
        return CC_FAILURE;
    }
    return rc;
}

int cc_symmetric_crypt(cc_symmetric_context_p ctx, const void *iv, const void *in, void *out, size_t len)
{
    int rc;
    switch (ctx->mode_desc->mode) {
    case cc_ModeECB:
        rc = ctx->mode_desc->ciphermode.ecb->ecb(ctx->ctx.ecb, len / ctx->mode_desc->ciphermode.ecb->block_size, in, out);
        break;
    case cc_ModeCBC: {
        cccbc_iv_decl(ctx->mode_desc->ciphermode.cbc->block_size, cbciv);
        if ((rc = cccbc_set_iv(ctx->mode_desc->ciphermode.cbc, cbciv, iv))) {
            return rc;
        }
        if ((rc = ctx->mode_desc->ciphermode.cbc->cbc(
                 ctx->ctx.cbc, cbciv, len / ctx->mode_desc->ciphermode.cbc->block_size, in, out))) {
            return rc;
        }
    } break;
    case cc_ModeCFB:
        rc = ctx->mode_desc->ciphermode.cfb->cfb(ctx->ctx.cfb, len / ctx->mode_desc->ciphermode.cfb->block_size, in, out);
        break;
    case cc_ModeCTR:
        rc = ctx->mode_desc->ciphermode.ctr->ctr(ctx->ctx.ctr, len / ctx->mode_desc->ciphermode.ctr->block_size, in, out);
        break;
    case cc_ModeOFB:
        rc = ctx->mode_desc->ciphermode.ofb->ofb(ctx->ctx.ofb, len / ctx->mode_desc->ciphermode.ofb->block_size, in, out);
        break;
    case cc_ModeCFB8:
        rc = ctx->mode_desc->ciphermode.cfb8->cfb8(ctx->ctx.cfb8, len / ctx->mode_desc->ciphermode.cfb8->block_size, in, out);
        break;
    case cc_ModeXTS: {
        ccxts_tweak_decl(ctx->mode_desc->ciphermode.xts->tweak_size, xts_iv);
        if ((rc = ccxts_set_tweak(ctx->mode_desc->ciphermode.xts, ctx->ctx.xts, xts_iv, iv))) {
            return rc;
        }
        if (ctx->mode_desc->ciphermode.xts->xts(
                ctx->ctx.xts, xts_iv, len / ctx->mode_desc->ciphermode.xts->block_size, in, out) == NULL) {
            return -1;
        }
    } break;
    case cc_ModeGCM:
        rc =
            ccgcm_update(ctx->mode_desc->ciphermode.gcm, ctx->ctx.gcm, len / ctx->mode_desc->ciphermode.gcm->block_size, in, out);
        break;
    case cc_ModeCCM:
        rc = ccccm_update(ctx->mode_desc->ciphermode.ccm,
                          ctx->ctx.ccm,
                          ctx->xtra_ctx.ccm_nonce,
                          len / ctx->mode_desc->ciphermode.ccm->block_size,
                          in,
                          out);
        break;
    case cc_ModeSIV:
        rc = ccsiv_crypt(ctx->mode_desc->ciphermode.siv, ctx->ctx.siv, len / ctx->mode_desc->ciphermode.siv->block_size, in, out);
        break;
    case cc_ModeSIV_HMAC:
        rc = ccsiv_hmac_crypt(ctx->mode_desc->ciphermode.siv_hmac, ctx->ctx.siv_hmac, len, in, out);
        break;
    default:
        return CC_FAILURE;
    }
    return rc;
}

void cc_symmetric_final(CC_UNUSED cc_symmetric_context_p ctx)
{
}

int cc_symmetric_authenticated_finalize(cc_symmetric_context_p ctx, char *tag, size_t tag_len)
{
    int rc;
    switch (ctx->mode_desc->mode) {
    case cc_ModeGCM:
        rc = ctx->mode_desc->ciphermode.gcm->finalize(ctx->ctx.gcm, tag_len, tag);
        break;
    case cc_ModeCCM:
        rc = ctx->mode_desc->ciphermode.ccm->finalize(ctx->ctx.ccm, ctx->xtra_ctx.ccm_nonce, tag);
        break;
    default:
        return CC_FAILURE;
    }
    return rc;
}

int cc_symmetric_oneshot(cc_ciphermode_descriptor cm,
                         const void *key,
                         size_t keylen,
                         const void *iv,
                         const void *in,
                         void *out,
                         size_t len)
{
    int rc;
    switch (cm->mode) {
    case cc_ModeECB:
        rc = ccecb_one_shot(cm->ciphermode.ecb, keylen, key, len / cm->ciphermode.ecb->block_size, in, out);
        break;
    case cc_ModeCBC:
        rc = cccbc_one_shot(cm->ciphermode.cbc, keylen, key, iv, len / cm->ciphermode.cbc->block_size, in, out);
        break;
    case cc_ModeCFB:
        rc = cccfb_one_shot(cm->ciphermode.cfb, keylen, key, iv, len / cm->ciphermode.cfb->block_size, in, out);
        break;
    case cc_ModeCTR:
        rc = ccctr_one_shot(cm->ciphermode.ctr, keylen, key, iv, len / cm->ciphermode.ctr->block_size, in, out);
        break;
    case cc_ModeOFB:
        rc = ccofb_one_shot(cm->ciphermode.ofb, keylen, key, iv, len / cm->ciphermode.ofb->block_size, in, out);
        break;
    case cc_ModeCFB8:
        rc = cccfb8_one_shot(cm->ciphermode.cfb8, keylen, key, iv, len / cm->ciphermode.cfb8->block_size, in, out);
        break;
    default:
        return CC_FAILURE;
    }
    return rc;
}

int cc_symmetric_reset(cc_symmetric_context_p ctx)
{
    int rc;
    switch (ctx->mode_desc->mode) {
    case cc_ModeGCM:
        rc = ccgcm_reset(ctx->mode_desc->ciphermode.gcm, ctx->ctx.gcm);
        break;
    case cc_ModeCCM:
        rc = ccccm_reset(ctx->mode_desc->ciphermode.ccm, ctx->ctx.ccm, ctx->xtra_ctx.ccm_nonce);
        break;
    case cc_ModeSIV:
        rc = ccsiv_reset(ctx->mode_desc->ciphermode.siv, ctx->ctx.siv);
        break;
    default:
        rc = CC_FAILURE;
    }
    return rc;
}

size_t cc_symmetric_bloc_size(cc_ciphermode_descriptor cm)
{
    size_t block_size = 0;

    switch (cm->mode) {
    case cc_ModeECB:
        block_size = cm->ciphermode.ecb->block_size;
        break;
    case cc_ModeCBC:
        block_size = cm->ciphermode.cbc->block_size;
        break;
    case cc_ModeCFB:
        block_size = cm->ciphermode.cfb->block_size;
        break;
    case cc_ModeCTR:
        block_size = cm->ciphermode.ctr->block_size;
        break;
    case cc_ModeOFB:
        block_size = cm->ciphermode.ofb->block_size;
        break;
    case cc_ModeCFB8:
        block_size = cm->ciphermode.cfb8->block_size;
        break;
    default:
        return 0;
    }
    return block_size;
}
