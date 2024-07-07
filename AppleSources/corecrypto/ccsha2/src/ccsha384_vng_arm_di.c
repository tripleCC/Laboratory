/* Copyright (c) (2016-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>
#include "cc_runtime_config.h"
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccdigest_priv.h>
#include "ccsha2_internal.h"
#include "AccelerateCrypto.h"

#if CC_USE_ASM && CCSHA2_VNG_ARM

static void ccsha384_vng_arm_compress(ccdigest_state_t c, size_t num, const void *p)
{
#if !CC_KERNEL && !CC_IBOOT && defined(__arm64__) && CC_INTERNAL_SDK
    if (CC_HAS_SHA512()) {
        AccelerateCrypto_SHA512_compress_hwassist((uint64_t*) c, num, p);
    }
    else
#endif
    {
        AccelerateCrypto_SHA512_compress((uint64_t*) c, num, p);
    }
}

const struct ccdigest_info ccsha384_vng_arm_di = {
    .output_size = CCSHA384_OUTPUT_SIZE,
    .state_size = CCSHA512_STATE_SIZE,
    .block_size = CCSHA512_BLOCK_SIZE,
    .oid_size = ccoid_sha384_len,
    .oid = CC_DIGEST_OID_SHA384,
    .initial_state = ccsha384_initial_state,
    .compress = ccsha384_vng_arm_compress,
    .final = ccsha512_final,
    .impl = CC_IMPL_SHA384_VNG_ARM,
};

#endif
