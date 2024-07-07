/* Copyright (c) (2012,2015,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccder.h>

bool
ccder_blob_encode_len(ccder_blob *to, size_t l)
{
    uint8_t *der = to->der;
    uint8_t *der_end = to->der_end;
    if (l>UINT32_MAX) {
        return NULL; // Not supported
    }
    if        (l <= 0x0000007f) {
        if (der + 1 > der_end) return NULL;
        *--der_end = (uint8_t)(l      );
    } else if (l <= 0x000000ff) {
        if (der + 2 > der_end) return NULL;
        *--der_end = (uint8_t)(l      );
        *--der_end = 0x81;
    } else if (l <= 0x0000ffff) {
        if (der + 3 > der_end) return NULL;
        *--der_end = (uint8_t)(l      );
        *--der_end = (uint8_t)(l >>  8);
        *--der_end = 0x82;
    } else if (l <= 0x00ffffff) {
        if (der + 4 > der_end) return NULL;
        *--der_end = (uint8_t)(l      );
        *--der_end = (uint8_t)(l >>  8);
        *--der_end = (uint8_t)(l >> 16);
        *--der_end = 0x83;
    } else {
        if (der + 5 > der_end) return NULL;
        *--der_end = (uint8_t)(l      );
        *--der_end = (uint8_t)(l >>  8);
        *--der_end = (uint8_t)(l >> 16);
        *--der_end = (uint8_t)(l >> 24);
        *--der_end = 0x84;
    }
    to->der = der;
    to->der_end = der_end;
    return true;
}
