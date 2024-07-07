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
#include "ccmode_internal.h"

#include "fipspost_trace.h"

int ccmode_gcm_decrypt(ccgcm_ctx *key, size_t nbytes, const void *in, void *out)
{
    FIPSPOST_TRACE_EVENT;

    const uint8_t *ctext = in;
    uint8_t *ptext = out;

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
        cc_xor(Xpad_nbytes_needed, X + Xpad_nbytes, X + Xpad_nbytes, ctext);
        ccmode_gcm_mult_h(key, X);
        cc_xor(Xpad_nbytes_needed, ptext, ctext, pad + Xpad_nbytes);

        nbytes -= Xpad_nbytes_needed;
        ctext += Xpad_nbytes_needed;
        ptext += Xpad_nbytes_needed;
        _CCMODE_GCM_KEY(key)->text_nbytes += Xpad_nbytes_needed;
        Xpad_nbytes = 0;

        ccmode_gcm_update_pad(key);
    }

    // process full blocks, if any
    if (Xpad_nbytes == 0) {
        while (nbytes >= CCGCM_BLOCK_NBYTES) {
            cc_xor(CCGCM_BLOCK_NBYTES, X, X, ctext);
            ccmode_gcm_mult_h(key, X);
            cc_xor(CCGCM_BLOCK_NBYTES, ptext, ctext, pad);

            nbytes -= CCGCM_BLOCK_NBYTES;
            ctext += CCGCM_BLOCK_NBYTES;
            ptext += CCGCM_BLOCK_NBYTES;
            _CCMODE_GCM_KEY(key)->text_nbytes += CCGCM_BLOCK_NBYTES;

            ccmode_gcm_update_pad(key);
        }
    }

    // process the remainder
    if (nbytes > 0) {
        cc_xor(nbytes, X + Xpad_nbytes, X + Xpad_nbytes, ctext);
        cc_xor(nbytes, ptext, ctext, pad + Xpad_nbytes);

        _CCMODE_GCM_KEY(key)->text_nbytes += nbytes;
    }

    return 0;

 callseq_out:
    return CCMODE_INVALID_CALL_SEQUENCE;

 input_out:
    return CCMODE_INVALID_INPUT;
}
