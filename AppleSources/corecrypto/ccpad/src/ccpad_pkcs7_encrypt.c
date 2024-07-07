/* Copyright (c) (2011,2012,2015,2018,2019,2021) Apple Inc. All rights reserved.
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

/* Out must be at least nbytes / block_size + 1 blocks long. */
size_t ccpad_pkcs7_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key,
                         cccbc_iv *iv,
                         size_t nbytes, const void *in, void *out) {
    CC_ENSURE_DIT_ENABLED

    const unsigned char *plain = in;
    unsigned char *cipher = out;
    const size_t block_size = cbc->block_size;
    size_t tail = nbytes & (block_size - 1);
    size_t head = nbytes - tail;

    /* Encrypt all the whole blocks. */
    cbc->cbc(cbc_key, iv, head / block_size, plain, cipher);
    cipher += head;
    plain += head;
    /* Copy the final in bytes (if any) to the out block. */
    cc_memcpy(cipher, plain, tail);
    size_t pad = block_size - tail;
    /* Fill the remainder of the out block with the padding bytes. */
    cc_memset(cipher + tail, (int)pad, pad);
    /* Encrypt the final block in place. */
    cbc->cbc(cbc_key, iv, 1, cipher, cipher);
    return head+block_size;
}
