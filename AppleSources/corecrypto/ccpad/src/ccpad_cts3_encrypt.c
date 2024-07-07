/* Copyright (c) (2012,2015,2018,2019,2021) Apple Inc. All rights reserved.
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
ccpad_cts3_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key, cccbc_iv *iv,
                   size_t len_bytes, const void *in, void *out)
{
    CC_ENSURE_DIT_ENABLED

    const size_t blocksize = cbc->block_size;
    uint8_t pad[CCMODE_MAX_BLOCK_SIZE * 2];
    size_t nbytes=len_bytes;
    const uint8_t *inp = (const uint8_t *) in;
    uint8_t *outp = (uint8_t *) out;

    // Full blocks up to padding
    ccpad_cts_crypt(cbc, cbc_key, iv, &nbytes, &inp, &outp);

    // Tail, takes care of padding
    if (nbytes != (blocksize*2)) {
        cc_clear(blocksize*2, pad);
        cc_memcpy(pad, inp, nbytes);
        inp = pad;
    }

    /* Encrypt the two blocks */
    cbc->cbc(cbc_key, iv, 2, inp, pad);
    /* Swap the last two blocks and truncate */
    swapblocks(pad, blocksize);
    cc_memcpy(outp, pad, nbytes);
    return len_bytes;
}
