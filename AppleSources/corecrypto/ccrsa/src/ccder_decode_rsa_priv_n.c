/* Copyright (c) (2012,2015,2018,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccder.h>

cc_size ccder_decode_rsa_priv_n(const uint8_t *der, const uint8_t *der_end)
{
	cc_unit version_0 = 0x00;
    cc_size n;

    der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end);
    if (der == NULL) {
        return 0;
    }

    der = ccder_decode_uint(1, &version_0, der, der_end);
    if (der == NULL) {
        return 0;
    }

    if (version_0 != 0) {
        return 0;
    }

    der = ccder_decode_uint_n(&n, der, der_end);
    if (der == NULL) {
        return 0;
    }

    return n;
}
