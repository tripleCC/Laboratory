/* Copyright (c) (2010,2012,2015,2016,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccsha2.h>
#include "ccdigest_internal.h"
#include "ccsha2_internal.h"

#if CCSHA256_ARMV6M_ASM

const struct ccdigest_info ccsha256_v6m_di = {
    .output_size = CCSHA256_OUTPUT_SIZE,
    .state_size = CCSHA256_STATE_SIZE,
    .block_size = CCSHA256_BLOCK_SIZE,
    .oid_size = ccoid_sha256_len,
    .oid = CC_DIGEST_OID_SHA256,
    .initial_state = ccsha256_initial_state,
    .compress = ccsha256_v6m_compress,
    .final = ccdigest_final_64be,
};

#endif
