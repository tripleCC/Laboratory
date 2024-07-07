/* Copyright (c) (2011,2012,2014-2016,2019,2021,2022) Apple Inc. All rights reserved.
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

size_t ccpad_pkcs7_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key,
                           cccbc_iv *iv,
                           size_t nbytes, const void *in, void *out) {
    CC_ENSURE_DIT_ENABLED

    const size_t block_size = cbc->block_size;
    size_t nblocks = nbytes / block_size;
    size_t pad_size = 0;

    // Decryption
    cbc->cbc(cbc_key, iv, nblocks, in, out);
    unsigned char *plain = out;
    
    // Padding parsing and determining real size.
    pad_size = ccpad_pkcs7_decode(block_size,plain+((nblocks-1)*block_size));
    return nbytes - pad_size;
}
