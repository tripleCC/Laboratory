/* Copyright (c) (2010-2012,2014-2019,2021) Apple Inc. All rights reserved.
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
#include "ccaes_vng_gcm.h"

#if CCMODE_GCM_VNG_SPEEDUP

CC_INLINE void aesgcm_encrypt_nblocks(const uint8_t* pt, uint8_t* ct, struct _ccmode_gcm_key *Gctx, unsigned len, unsigned char* Htbl, void *KS)
{
#ifdef  __x86_64__
    if (CC_HAS_AVX1() && !CC_HAS_AVX512_AND_IN_KERNEL())
        gcmEncrypt_avx1(pt, ct, Gctx, len, Htbl, KS);
    else
        gcmEncrypt_SupplementalSSE3(pt, ct, Gctx, len, Htbl, KS);
#else
    gcmEncrypt(pt, ct, Gctx, len, Htbl, KS);
#endif
}

int ccaes_vng_gcm_encrypt(ccgcm_ctx *key, size_t nbytes, const void *in, void *out)
{
    const uint8_t *ptext = in;
    uint8_t *ctext = out;

    uint8_t *X = CCMODE_GCM_KEY_X(key);
    uint8_t *pad = CCMODE_GCM_KEY_PAD(key);

    // X and the pad are always in sync with regards to offsets
    uint32_t Xpad_nbytes = _CCMODE_GCM_KEY(key)->text_nbytes % CCGCM_BLOCK_NBYTES;
    uint32_t Xpad_nbytes_needed = CCGCM_BLOCK_NBYTES - Xpad_nbytes;

    ccmode_gcm_aad_finalize(key);
    cc_require(_CCMODE_GCM_KEY(key)->state == CCMODE_GCM_STATE_TEXT, callseq_out);
    cc_require(UINT64_MAX - _CCMODE_GCM_KEY(key)->text_nbytes >= nbytes, input_out);
    cc_require(_CCMODE_GCM_KEY(key)->text_nbytes + nbytes <= CCGCM_TEXT_MAX_NBYTES, input_out);

    // finish a partial block, if possible
    if (Xpad_nbytes > 0 && nbytes >= Xpad_nbytes_needed) {
        cc_xor(Xpad_nbytes_needed, ctext, ptext, pad + Xpad_nbytes);
        cc_xor(Xpad_nbytes_needed, X + Xpad_nbytes, X + Xpad_nbytes, ctext);
        ccmode_gcm_mult_h(key, X);

        nbytes -= Xpad_nbytes_needed;
        ptext += Xpad_nbytes_needed;
        ctext += Xpad_nbytes_needed;
        _CCMODE_GCM_KEY(key)->text_nbytes += Xpad_nbytes_needed;
        Xpad_nbytes = 0;

        ccmode_gcm_update_pad(key);
    }

    // process full blocks, if any
    if (Xpad_nbytes == 0) {
#ifdef  __x86_64__
        if (CC_HAS_AESNI() && CC_HAS_SupplementalSSE3())
#endif
            if (nbytes >= CCGCM_BLOCK_NBYTES) {
                const unsigned n = (unsigned)(nbytes & (size_t)(-16)); // n will be multiple of 16
                aesgcm_encrypt_nblocks(ptext, ctext, _CCMODE_GCM_KEY(key), n, CCMODE_GCM_VNG_KEY_Htable(key), CCMODE_GCM_KEY_ECB_KEY(key));
                nbytes -= n;
                ptext += n;
                ctext += n;
                _CCMODE_GCM_KEY(key)->text_nbytes += n;
#if !defined(__ARM_NEON__) || defined(__arm64__)
                CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1, CCMODE_GCM_KEY_Y(key), CCMODE_GCM_KEY_PAD(key));
#endif
            }

        while (nbytes >= CCGCM_BLOCK_NBYTES) {
            cc_xor(CCGCM_BLOCK_NBYTES, ctext, ptext, pad);
            cc_xor(CCGCM_BLOCK_NBYTES, X, X, ctext);
            ccmode_gcm_mult_h(key, X);

            nbytes -= CCGCM_BLOCK_NBYTES;
            ptext += CCGCM_BLOCK_NBYTES;
            ctext += CCGCM_BLOCK_NBYTES;
            _CCMODE_GCM_KEY(key)->text_nbytes += CCGCM_BLOCK_NBYTES;

            ccmode_gcm_update_pad(key);
        }
    }

    // process the remainder
    if (nbytes > 0) {
        cc_xor(nbytes, ctext, ptext, pad + Xpad_nbytes);
        cc_xor(nbytes, X + Xpad_nbytes, X + Xpad_nbytes, ctext);

        _CCMODE_GCM_KEY(key)->text_nbytes += nbytes;
    }

    return 0;

 callseq_out:
    return CCMODE_INVALID_CALL_SEQUENCE;

 input_out:
    return CCMODE_INVALID_INPUT;
}

#endif
