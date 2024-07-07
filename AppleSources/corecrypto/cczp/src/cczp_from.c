/* Copyright (c) (2019,2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

#include "cczp_internal.h"

void cczp_from_default_ws(CC_UNUSED cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    ccn_set(cczp_n(zp), r, x);
}

CC_WORKSPACE_OVERRIDE(cczp_from_ws, cczp_from_default_ws)

void cczp_from_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    CCZP_FUNCS_GET(zp, cczp_from)(ws, zp, r, x);
}
