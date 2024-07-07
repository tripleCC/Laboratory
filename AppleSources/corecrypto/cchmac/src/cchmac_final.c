/* Copyright (c) (2010,2011,2015,2017-2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

void cchmac_final(const struct ccdigest_info *di, cchmac_ctx_t hc,
                  unsigned char *mac) {
    CC_ENSURE_DIT_ENABLED


    // Finalize the inner state of the data being HMAC'd, i.e., H((key \oplus ipad) || m)
    ccdigest_final(di, cchmac_digest_ctx(di, hc), cchmac_data(di, hc));

    // Set the HMAC output size based on the digest algorithm
    cchmac_num(di, hc) = (unsigned int)di->output_size; /* typecast: output size will always fit in an unsigned int */
    cchmac_nbits(di, hc) = di->block_size * 8;

    // Copy the pre-computed compress(key \oplus opad) back to digest state,
    // and then run through the digest once more to finish the HMAC
    ccdigest_copy_state(di, cchmac_istate32(di, hc), cchmac_ostate32(di, hc));
    ccdigest_final(di, cchmac_digest_ctx(di, hc), mac);
}
