/* Copyright (c) (2018,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cccmac.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccspake.h>
#include "ccspake_internal.h"

/*! @function ccspake_mac_hkdf_cmac_compute
 @abstract Generate a CMAC for key confirmation

 @param ctx         SPAKE2+ context
 @param key_nbytes  Length of MAC key
 @param key         MAC key
 @param info_nbytes Length of info
 @param info        Transcript to compute MAC over
 @param t_nbytes    Desired length of the MAC
 @param t           Output buffer for the MAC

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
static int ccspake_mac_hkdf_cmac_compute(ccspake_const_ctx_t ctx,
                                         size_t key_nbytes,
                                         const uint8_t *key,
                                         size_t info_nbytes,
                                         const uint8_t *info,
                                         size_t t_nbytes,
                                         uint8_t *t)
{
    ccspake_const_mac_t mac = ccspake_ctx_mac(ctx);

    if (t_nbytes != mac->tag_nbytes) {
        return CCERR_PARAMETER;
    }

    return cccmac_one_shot_generate(mac->cbc(), key_nbytes, key, info_nbytes, info, t_nbytes, t);
}

static ccspake_mac_decl() ccspake_mac_hkdf_cmac_aes128_sha256_decl = {
    .di = ccsha256_di,
    .cbc = ccaes_cbc_encrypt_mode,
    .confirm_key_nbytes = CCAES_KEY_SIZE_128,
    .tag_nbytes = CCAES_BLOCK_SIZE,
    .derive = ccspake_mac_hkdf_derive,
    .compute = ccspake_mac_hkdf_cmac_compute,
};

ccspake_const_mac_t ccspake_mac_hkdf_cmac_aes128_sha256(void)
{
    return (ccspake_const_mac_t)&ccspake_mac_hkdf_cmac_aes128_sha256_decl;
}
