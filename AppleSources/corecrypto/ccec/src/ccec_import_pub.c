/* Copyright (c) (2010,2011,2014,2015,2019,2021) Apple Inc. All rights reserved.
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
#include "cc_memory.h"
#include "ccec_internal.h"

int ccec_import_pub_ws(cc_ws_t ws, ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key)
{
    return ccec_x963_import_pub_ws(ws, cp, in_len, in, key);
}

int ccec_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    return ccec_x963_import_pub(cp, in_len, in, key);
}
