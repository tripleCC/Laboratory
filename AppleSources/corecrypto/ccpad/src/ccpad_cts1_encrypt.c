/* Copyright (c) (2010-2012,2015,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include <corecrypto/ccpad.h>
#include <corecrypto/cc_priv.h>
#include "ccpad_cts_helper.h"

size_t
ccpad_cts1_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key, cccbc_iv *iv,
                   size_t len_bytes, const void *in, void *out)
{
    CC_ENSURE_DIT_ENABLED

    const size_t blocksize = cbc->block_size;
    size_t d;
    size_t nbytes=len_bytes;
    const uint8_t *inp = (const uint8_t *) in;
    uint8_t *outp = (uint8_t *) out;
    uint8_t *pN, *cN, *cN_1;
    uint8_t pad[CCMODE_MAX_BLOCK_SIZE * 2];

    // Full blocks up to padding
    ccpad_cts_crypt(cbc, cbc_key, iv, &nbytes, &inp, &outp);

    // Tail, takes care of padding
    if (nbytes == (blocksize*2)) { /* Complete Block - just encrypt and return */
        cbc->cbc(cbc_key, iv, 2, inp, outp);
        return len_bytes;
    }

    cc_memcpy(pad, inp, nbytes);

    d = nbytes - blocksize;
    pN = pad + blocksize;
    cN = pad + blocksize;
    cN_1 = pad;

    cc_clear(blocksize - d, pN + d);

    /* Encrypt the two blocks */
    cbc->cbc(cbc_key, iv, 2, pad, pad);

    /* Shift the entire last block left by the amount the block was short - into the 2nd to last block */
    cc_memmove(outp, cN_1, d);
    cc_memmove(outp + d, cN, blocksize);
    return len_bytes;
}
