/* Copyright (c) (2011,2012,2014-2016,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>

ccec_const_cp_t
ccec_get_cp(size_t keysize)
{
    CC_ENSURE_DIT_ENABLED

    switch(keysize) {
        case 192: return ccec_cp_192();
        case 224: return ccec_cp_224();
        case 256: return ccec_cp_256();
        case 384: return ccec_cp_384();
        case 521: return ccec_cp_521();
        default: return (ccec_const_cp_t)(const struct cczp*) (const cc_unit*)NULL;
    }
}

int
ccec_keysize_is_supported(size_t keysize)
{
    CC_ENSURE_DIT_ENABLED

    switch(keysize) {
        case 192:
        case 224:
        case 256:
        case 384:
        case 521: return 1;
        default: return 0;
    }
}
