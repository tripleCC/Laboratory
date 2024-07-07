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
ccder_blob_decode_tag(ccder_read_blob *from, ccder_tag *tagp)
{
    const uint8_t *der = from->der;
    const uint8_t *const der_end = from->der_end;
    if (der && der < der_end) {
        ccder_tag tag0 = *der++;
        ccder_tag num = tag0 & 0x1f;
        if (num == 0x1f) {
#ifdef CCDER_MULTIBYTE_TAGS
            ccder_tag mask = ((ccder_tag)0x7F << (sizeof(ccder_tag) * 8 - 7));
            uint8_t v;
            num = 0;
            do {
                if (der >= der_end || num & mask) return NULL;
                v = *der++;
                num = (num << 7) | (v & 0x7f);
            } while (v & 0x80);
            /* Check for any of the top 3 reserved bits being set. */
            if (num & (mask << 4)) /* num & CCDER_TAGNUM_MASK */
                return NULL;
#else /* !CCDER_MULTIBYTE_TAGS */
            return NULL;
#endif /* !CCDER_MULTIBYTE_TAGS */
        }
        /* Return tag, top 3 bits are class/method remaining bits are number. */
        *tagp = ((ccder_tag)(tag0 & 0xe0) << ((sizeof(ccder_tag) - 1) * 8)) | num;
        from->der = der;
        from->der_end = der_end;
        return true;
    }
    return false;
}

