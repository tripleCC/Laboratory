/* Copyright (c) (2015-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cccmac_internal.h"
#include <corecrypto/ccmode_siv.h>
#include "ccmode_siv_internal.h"
#include "ccmode_internal.h"
#include <corecrypto/cc_priv.h>

/*
 S2V for all vectors but the last S1..Sn-1
 D = AES-CMAC(K, <zero>)
 for i = 1 to n-1 do
 D = dbl(D) xor AES-CMAC(K, Si)
 done
 */
int ccmode_siv_auth(ccsiv_ctx *ctx,
                      size_t nbytes, const uint8_t *in) {

    size_t block_size = _CCMODE_SIV_CBC_MODE(ctx)->block_size;

    // Supports only 128-bit block ciphers.
    if (block_size != 16) {
        return CCMODE_NOT_SUPPORTED;
    }

    // If no data, nothing to do, return without changing state
    if (nbytes == 0) {
        return CCERR_OK;
    }

    uint8_t block[16];

    // Process Si
    // D = dbl(D) xor AES-CMAC(K, Si)
    cccmac_sl_test_xor(_CCMODE_SIV_D(ctx),_CCMODE_SIV_D(ctx));
    cccmac_one_shot_generate(_CCMODE_SIV_CBC_MODE(ctx),
                             _CCMODE_SIV_KEYSIZE(ctx) / 2, _CCMODE_SIV_K1(ctx),
                             nbytes, in,
                             block_size, block);
    cc_xor(block_size, _CCMODE_SIV_D(ctx),_CCMODE_SIV_D(ctx), block);

    // Done
    _CCMODE_SIV_STATE(ctx) = CCMODE_STATE_AAD;
    return CCERR_OK;
}

int ccmode_siv_auth_finalize(ccsiv_ctx *ctx,
                         size_t nbytes, const uint8_t *in, uint8_t* V) {
    int rc=-1;
    size_t block_size=_CCMODE_SIV_CBC_MODE(ctx)->block_size;

    // Supports only 128-bit block ciphers.
    if (block_size != 16) {
        rc = CCMODE_NOT_SUPPORTED;
        goto errOut;
    }

    uint8_t block[2 * 16];
    const struct ccmode_cbc *cbc=_CCMODE_SIV_CBC_MODE(ctx);

    /* Sanity checks */
    if (   (_CCMODE_SIV_STATE(ctx)!=CCMODE_STATE_INIT)
        && (_CCMODE_SIV_STATE(ctx)!=CCMODE_STATE_AAD)) {
        rc=CCMODE_INVALID_CALL_SEQUENCE;
        goto errOut;
    }

    /* Special case, nothing to encrypt or authenticate:
     output is one block size */
    if ((nbytes==0) && _CCMODE_SIV_STATE(ctx)==CCMODE_STATE_INIT) {
        /*
         if n = 0 then
         return V = AES-CMAC(K, <one>)
         fi
         */
        cc_clear(block_size,block);
        block[block_size-1]=0x01;
        cccmac_one_shot_generate(_CCMODE_SIV_CBC_MODE(ctx),
                                 _CCMODE_SIV_KEYSIZE(ctx)/2,_CCMODE_SIV_K1(ctx),
                                 block_size,block,
                                 block_size,V);
        _CCMODE_SIV_STATE(ctx)=CCMODE_STATE_TEXT; // done
        return 0;
    }

    /* Something to encrypt */
    if (nbytes>=block_size) {
        /* if len(Sn) >= 128 then
         T = Sn xorend D */
        cccmac_mode_decl(cbc, cmac);
        cccmac_init(cbc, cmac, _CCMODE_SIV_KEYSIZE(ctx)/2, _CCMODE_SIV_K1(ctx));
        size_t head_nblocks=nbytes/block_size-1;
        size_t tail_nbytes=nbytes-(head_nblocks*block_size);

        // Will process all the entire block except the last
        // 1) Set the last full block and remaining bytes aside
        cc_memcpy(block,&in[(head_nblocks*block_size)],tail_nbytes-block_size);
        cc_xor(block_size,
               &block[tail_nbytes-block_size],
               &in[(head_nblocks*block_size)+tail_nbytes-block_size],
               _CCMODE_SIV_D(ctx));

        // 2) MAC the full blocks
        cccmac_update(cmac, head_nblocks*block_size, in);

        // 3) MAC the tailing bytes
        cccmac_update(cmac, tail_nbytes, block);
        cccmac_final_generate(cmac, block_size,V);
        cccmac_mode_clear(cbc, cmac);
    } else {
        /* else
         T = dbl(D) xor pad(Sn) */
        cccmac_sl_test_xor(_CCMODE_SIV_D(ctx),_CCMODE_SIV_D(ctx));
        cc_memcpy(block,in,nbytes);
        block[nbytes]=0x80;
        for (size_t i=1;i<(block_size-nbytes);i++) {
            block[nbytes+i]=0x00;
        }
        cc_xor(block_size,block,block,_CCMODE_SIV_D(ctx));
        cccmac_one_shot_generate(cbc, _CCMODE_SIV_KEYSIZE(ctx)/2,_CCMODE_SIV_K1(ctx),
                                 block_size,block,block_size,V);
    }
    _CCMODE_SIV_STATE(ctx)=CCMODE_STATE_TEXT; // done with S2V
    return CCERR_OK;
errOut:
    _CCMODE_SIV_STATE(ctx)=CCMODE_STATE_INVALID; // done with S2V
    return rc;
}
