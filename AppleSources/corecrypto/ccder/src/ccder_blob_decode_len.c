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

static bool ccder_blob_decode_len_internal(ccder_read_blob *from, size_t *lenp, bool strict)
{
    const uint8_t *der = from->der;
    const uint8_t *const der_end = from->der_end;
    if (der && der_end && der < der_end) {
        size_t len = *der++;
        if (len < 0x80) {
        } else if (len == 0x81) {
            if (der_end - der < 1)
                goto errOut;
            len = *der++;
            if (strict && (len < 0x80)) {
                goto errOut;
            }
        } else if (len == 0x82) {
            if (der_end - der < 2)
                goto errOut;
            len = (size_t)*(der++) << 8;
            len += *der++;
            if (strict && (len <= 0xff)) {
                goto errOut;
            }
        } else if (len == 0x83) {
            if (der_end - der < 3)
                goto errOut;
            len = (size_t)*(der++) << 16;
            len += (size_t)*(der++) << 8;
            len += *(der++);
            if (strict && (len <= 0xffff)) {
                goto errOut;
            }
        } else if (len == 0x84) {
            if (der_end - der < 4)
                goto errOut;
            len = (size_t)*(der++) << 24;
            len += (size_t)*(der++) << 16;
            len += (size_t)*(der++) << 8;
            len += *(der++);
            if (strict && (len <= 0xffffff)) {
                goto errOut;
            }
        } else {
            goto errOut;
        }
        if ((size_t)(der_end - der) >= len) {
            *lenp = len;
            from->der = der;
            from->der_end = der_end;
            return true;
        }
    }
errOut:
    *lenp = 0;
    return false;
}

bool ccder_blob_decode_len_strict(ccder_read_blob *from, size_t *lenp)
{
    return ccder_blob_decode_len_internal(from, lenp, true);
}


bool ccder_blob_decode_len(ccder_read_blob *from, size_t *lenp)
{
    return ccder_blob_decode_len_internal(from, lenp, false);
}
