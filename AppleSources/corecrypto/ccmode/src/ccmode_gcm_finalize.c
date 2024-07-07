/* Copyright (c) (2011,2012,2015,2016,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccmode_internal.h"

int ccmode_gcm_finalize(ccgcm_ctx *key, size_t tag_nbytes, void *tag)
{
    uint8_t *X = CCMODE_GCM_KEY_X(key);
    uint8_t *pad = CCMODE_GCM_KEY_PAD(key);
    uint8_t out_tag[16];
    int rc = 0;
    
    ccmode_gcm_aad_finalize(key);
    if (_CCMODE_GCM_KEY(key)->state != CCMODE_GCM_STATE_TEXT) {
        return CCMODE_INVALID_CALL_SEQUENCE;
    }
    
    if (_CCMODE_GCM_KEY(key)->text_nbytes % CCGCM_BLOCK_NBYTES > 0) {
        ccmode_gcm_mult_h(key, X);
    }
    
    uint64_t aad_nbits = _CCMODE_GCM_KEY(key)->aad_nbytes * 8;
    uint64_t text_nbits = _CCMODE_GCM_KEY(key)->text_nbytes * 8;
    
    // briefly repurposing the pad to hold the length block
    cc_store64_be(aad_nbits, pad);
    cc_store64_be(text_nbits, pad + 8);
    cc_xor(CCGCM_BLOCK_NBYTES, X, X, pad);
    ccmode_gcm_mult_h(key, X);
    
    /* encrypt original counter */
    CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                 CCMODE_GCM_KEY_Y_0(key),
                                 pad);
    
    cc_xor(CCGCM_BLOCK_NBYTES, out_tag, X, pad);
    tag_nbytes = CC_MIN(tag_nbytes, sizeof(out_tag)); //make sure we don't go out of bound
    
    if (_CCMODE_GCM_ECB_MODE(key)->encdec == CCMODE_GCM_DECRYPTOR) {
        rc = cc_cmp_safe(tag_nbytes, out_tag, tag);
        CC_HEAVISIDE_STEP(rc, rc);
        rc = CCMODE_INTEGRITY_FAILURE & (-rc);
    }
    
    //this should be removed for CCMODE_GCM_DECRYPTOR
    //it is here to keep compatibility with the previous usage that
    //returned tag on decryption by mistake
    cc_memcpy(tag, out_tag, tag_nbytes);
    
    _CCMODE_GCM_KEY(key)->state = CCMODE_GCM_STATE_FINAL;

    return rc;
}
