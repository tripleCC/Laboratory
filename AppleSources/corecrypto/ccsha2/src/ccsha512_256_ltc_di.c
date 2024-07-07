/* Copyright (c) (2019) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_priv.h>
#include "ccsha2_internal.h"

const struct ccdigest_info ccsha512_256_ltc_di = {
    .output_size = CCSHA512_256_OUTPUT_SIZE,
    .state_size = CCSHA512_256_STATE_SIZE,
    .block_size = CCSHA512_256_BLOCK_SIZE,
    .oid_size = ccoid_sha512_256_len,
    .oid = CC_DIGEST_OID_SHA512_256,
    .initial_state = ccsha512_256_initial_state,
    .compress = ccsha512_ltc_compress,
    .final = ccsha512_final,
};
