/* Copyright (c) (2012,2022) Apple Inc. All rights reserved.
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
#include "ccrsa_internal.h"

int ccrsa_import_priv_ws(cc_ws_t ws, ccrsa_full_ctx_t key, size_t inlen, const uint8_t *cc_sized_by(inlen) der)
{
    const uint8_t *local_der = der;
    return (ccder_decode_rsa_priv_ws(ws, key, local_der, local_der + inlen) == NULL);
}
