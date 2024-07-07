/* Copyright (c) (2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cczp.h>

const cc_unit * cc_indexable cczp_prime(cczp_const_t zp)
{
    return cc_unsafe_forge_bidi_indexable(CCZP_PRIME(zp), ccn_sizeof_n(CCZP_N(zp)));
}
