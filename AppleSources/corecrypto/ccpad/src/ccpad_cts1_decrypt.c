/* Copyright (c) (2012,2014,2015,2018,2019,2021,2022) Apple Inc. All rights reserved.
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
ccpad_cts1_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key, cccbc_iv *iv,
                   size_t len_bytes, const void *in, void *out)
{
    CC_ENSURE_DIT_ENABLED

    const size_t blocksize = cbc->block_size;
    size_t i, d;
    size_t nbytes=len_bytes;
    const uint8_t *inp = (const uint8_t *) in;
    uint8_t *outp = (uint8_t *) out;
    uint8_t z[CCMODE_MAX_BLOCK_SIZE];
    uint8_t cN_1[CCMODE_MAX_BLOCK_SIZE];
    uint8_t cN[CCMODE_MAX_BLOCK_SIZE];

    // Full blocks up to padding
    ccpad_cts_crypt(cbc, cbc_key, iv, &nbytes, &inp, &outp);

    // Tail, takes care of padding
    if (nbytes == (blocksize*2)) {
        /* Complete Block - just decrypt and return */
        cbc->cbc(cbc_key, iv, 2, inp, outp);
        return len_bytes;
    }

    d = nbytes - blocksize;

    cc_memcpy(cN_1, inp, d);
    cc_memcpy(cN, inp+d, blocksize);

    /* step 3 */

    ecb_from_cbc(cbc, cbc_key, cN, z);

    /* step 4 */

    for (i = d; i < blocksize; i += 1) {
        cN_1[i] = z[i];
    }

    /* Encrypt the n-1th block */
    cbc->cbc(cbc_key, iv, 1, cN_1, outp);

    for (i = 0; i < d; i += 1) {
        outp[i+blocksize] = cN_1[i] ^ z[i];
    }

    return len_bytes;
}
