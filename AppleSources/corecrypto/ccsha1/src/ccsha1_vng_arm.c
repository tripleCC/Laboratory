/* Copyright (c) (2011,2012,2015-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccsha1.h>
#include "ccsha1_internal.h"
#include <corecrypto/ccdigest_priv.h>
#include "ccdigest_internal.h"
#include <corecrypto/cc_config.h>
#include "AccelerateCrypto.h"

#if CC_USE_ASM && CCSHA1_VNG_ARM

static void ccsha1_vng_arm_compress(ccdigest_state_t c, size_t num, const void *p)
{
    AccelerateCrypto_SHA1_compress((uint32_t*) c, num, p);
}

const struct ccdigest_info ccsha1_vng_arm_di = {
    .output_size = CCSHA1_OUTPUT_SIZE,
    .state_size = CCSHA1_STATE_SIZE,
    .block_size = CCSHA1_BLOCK_SIZE,
    .oid_size = ccoid_sha1_len,
    .oid = CC_DIGEST_OID_SHA1,
    .initial_state = ccsha1_initial_state,
    .compress = ccsha1_vng_arm_compress,
    .final = ccdigest_final_64be,
    .impl = CC_IMPL_SHA1_VNG_ARM,
};

#endif
