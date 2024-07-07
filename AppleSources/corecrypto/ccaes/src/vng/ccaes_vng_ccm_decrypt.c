/* Copyright (c) (2014-2016,2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_runtime_config.h"
#include "ccaes_vng_ccm.h"

#if  CCMODE_CCM_VNG_SPEEDUP

extern void ccm_decrypt(const void *in, void *out, void *tag, size_t nblocks, void *key, void *ctr, size_t ctr_len) __asm__("_ccm_decrypt");
extern void ccm128_decrypt(const void *in, void *out, void *tag, size_t nblocks, void *key, void *ctr, size_t ctr_len) __asm__("_ccm128_decrypt");
extern void ccm192_decrypt(const void *in, void *out, void *tag, size_t nblocks, void *key, void *ctr, size_t ctr_len) __asm__("_ccm192_decrypt");
extern void ccm256_decrypt(const void *in, void *out, void *tag, size_t nblocks, void *key, void *ctr, size_t ctr_len) __asm__("_ccm256_decrypt");

int ccaes_vng_ccm_decrypt(ccccm_ctx *key, ccccm_nonce *nonce_ctx, size_t nbytes, const uint8_t *in, uint8_t *out) {

    if (_CCMODE_CCM_NONCE(nonce_ctx)->mode == CCMODE_STATE_AAD) {
        if (CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx)) {
            /* transition to new block between auth and enc data */
            CCMODE_CCM_KEY_ECB(key)->ecb(CCMODE_CCM_KEY_ECB_KEY(key), 1,
                                     CCMODE_CCM_KEY_B_I(nonce_ctx),
                                     CCMODE_CCM_KEY_B_I(nonce_ctx));
            CCMODE_CCM_KEY_AUTH_LEN(nonce_ctx) = 0;
        }
        _CCMODE_CCM_NONCE(nonce_ctx)->mode = CCMODE_STATE_TEXT;
    }

    cc_require(_CCMODE_CCM_NONCE(nonce_ctx)->mode == CCMODE_STATE_TEXT,errOut); /* CRYPT_INVALID_ARG */

#if defined __x86_64__
  if ( CC_HAS_AESNI() && CC_HAS_SupplementalSSE3() ) 
#endif
  {

    if (CCMODE_CCM_KEY_PAD_LEN(nonce_ctx) != 0) {
        size_t padl = CCMODE_CCM_KEY_PAD_LEN(nonce_ctx);
        if (padl>nbytes) padl = nbytes;
        ccmode_ccm_crypt(key, nonce_ctx, padl, in, out);
        ccmode_ccm_macdata(key, nonce_ctx, 0, padl, out);
        in += padl;
        out += padl;
        nbytes -= padl;
    }

    if (CCMODE_CCM_KEY_PAD_LEN(nonce_ctx) == 0) {
#if CC_ARM_ARCH_7
      if (nbytes>=16) {
        size_t nblocks = nbytes/16;
                ccm_decrypt(in, out, CCMODE_CCM_KEY_B_I(nonce_ctx), nblocks, CCMODE_CCM_KEY_ECB_KEY(key),
                        CCMODE_CCM_KEY_A_I(nonce_ctx), 
                        CCMODE_CCM_KEY_ECB(key)->block_size - 1 - CCMODE_CCM_KEY_NONCE_LEN(nonce_ctx));
#else
        int *p = (int*) CCMODE_CCM_KEY_ECB_KEY(key);
        if (nbytes>=16) {
              size_t nblocks = nbytes/16;
        switch (p[240/4]) {
            case 10 :
            case 160 :
                ccm128_decrypt(in, out, CCMODE_CCM_KEY_B_I(nonce_ctx), nblocks, CCMODE_CCM_KEY_ECB_KEY(key),
                        CCMODE_CCM_KEY_A_I(nonce_ctx), 
                        CCMODE_CCM_KEY_ECB(key)->block_size - 1 - CCMODE_CCM_KEY_NONCE_LEN(nonce_ctx));
                break;
            case 12 :
            case 192 :
                ccm192_decrypt(in, out, CCMODE_CCM_KEY_B_I(nonce_ctx), nblocks, CCMODE_CCM_KEY_ECB_KEY(key),
                        CCMODE_CCM_KEY_A_I(nonce_ctx), 
                        CCMODE_CCM_KEY_ECB(key)->block_size - 1 - CCMODE_CCM_KEY_NONCE_LEN(nonce_ctx));
                break;
            case 14 :
            case 224 :
                ccm256_decrypt(in, out, CCMODE_CCM_KEY_B_I(nonce_ctx), nblocks, CCMODE_CCM_KEY_ECB_KEY(key),
                        CCMODE_CCM_KEY_A_I(nonce_ctx), 
                        CCMODE_CCM_KEY_ECB(key)->block_size - 1 - CCMODE_CCM_KEY_NONCE_LEN(nonce_ctx));
                break;
        }
#endif

        nbytes &= 15;
        in += nblocks*16;
        out += nblocks*16;
      }
    }
  }

    ccmode_ccm_crypt(key, nonce_ctx, nbytes, in, out);
    ccmode_ccm_macdata(key, nonce_ctx, 0, nbytes, out);
      return 0;
  errOut:
      return CCMODE_INVALID_CALL_SEQUENCE;
  }

#endif  // CCMODE_CCM_VNG_SPEEDUP
