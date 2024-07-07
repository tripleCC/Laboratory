/* Copyright (c) (2011,2012,2015,2019,2021,2022) Apple Inc. All rights reserved.
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
#include "ccn_internal.h"
#include <corecrypto/ccz_priv.h>

void ccz_read_uint(ccz *r, size_t data_size, const uint8_t *data)
{
    CC_ENSURE_DIT_ENABLED

    ccz_set_sign(r, 1);
    ccz_set_capacity(r, ccn_nof_size(data_size));
    ccn_read_uint(ccn_nof_size(data_size), r->u, data_size, data);
    ccz_set_n(r, ccn_n(ccn_nof_size(data_size), r->u));
}
