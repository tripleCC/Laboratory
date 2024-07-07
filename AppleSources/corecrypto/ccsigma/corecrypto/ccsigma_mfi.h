/* Copyright (c) (2020-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSIGMA_MFI_H_
#define _CORECRYPTO_CCSIGMA_MFI_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccsigma_priv.h>

const struct ccsigma_info *ccsigma_mfi_info(void);

const struct ccsigma_info *ccsigma_mfi_nvm_info(void);

#define CCSIGMA_MFI_KEX_CP_BITSIZE (256)
#define CCSIGMA_MFI_KEX_KEY_SHARE_SIZE (33)
#define CCSIGMA_MFI_SIG_CP_SIZE (32)
#define CCSIGMA_MFI_SIG_CP_BITSIZE (8 * CCSIGMA_MFI_SIG_CP_SIZE)
#define CCSIGMA_MFI_SIGNATURE_SIZE (2 * CCSIGMA_MFI_SIG_CP_SIZE)
#define CCSIGMA_MFI_SESSION_KEYS_BUFFER_SIZE (200)
#define CCSIGMA_MFI_NVM_SESSION_KEYS_BUFFER_SIZE (144)

#define CCSIGMA_MFI_MAC_TAG_SIZE (16)
#define CCSIGMA_MFI_AEAD_TAG_SIZE (16)
#define CCSIGMA_MFI_KDF_MAX_CTX_SIZE (256)

enum {
    CCSIGMA_MFI_ER_KEY,
    CCSIGMA_MFI_ER_IV,
    CCSIGMA_MFI_TR_KEY,
    CCSIGMA_MFI_CR_KEY,
    CCSIGMA_MFI_CR_IV,
    CCSIGMA_MFI_SR_KEY,
    CCSIGMA_MFI_SR_IV,
    CCSIGMA_MFI_EI_KEY,
    CCSIGMA_MFI_EI_IV,
    CCSIGMA_MFI_TI_KEY,
    CCSIGMA_MFI_CI_KEY,
    CCSIGMA_MFI_CI_IV,
    CCSIGMA_MFI_SI_KEY,
    CCSIGMA_MFI_SI_IV,
    CCSIGMA_MFI_SESSION_KEYS_COUNT
};

struct ccsigma_mfi_ctx {
    struct ccsigma_ctx sigma_ctx;
    struct {
        cc_ctx_decl_field(struct ccec_full_ctx, ccec_full_ctx_size(ccn_sizeof(CCSIGMA_MFI_KEX_CP_BITSIZE)), ctx);
        cc_ctx_decl_field(struct ccec_pub_ctx, ccec_pub_ctx_size(ccn_sizeof(CCSIGMA_MFI_KEX_CP_BITSIZE)), peer_ctx);
    } key_exchange;
    struct {
        cc_ctx_decl_field(struct ccec_full_ctx, ccec_full_ctx_size(ccn_sizeof(CCSIGMA_MFI_SIG_CP_BITSIZE)), ctx);
        cc_ctx_decl_field(struct ccec_pub_ctx, ccec_pub_ctx_size(ccn_sizeof(CCSIGMA_MFI_SIG_CP_BITSIZE)), peer_ctx);
    } signature;
    uint8_t session_keys_buffer[CCSIGMA_MFI_SESSION_KEYS_BUFFER_SIZE];
};

#endif /* _CORECRYPTO_CCSIGMA_MFI_H_ */
