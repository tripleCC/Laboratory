/* Copyright (c) (2012,2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccder.h>

size_t
ccder_sizeof_tag(ccder_tag tag) {
#ifdef CCDER_MULTIBYTE_TAGS
    ccder_tag num = (tag & CCDER_TAGNUM_MASK);
    if (num < 0x1f) {
        return 1;
    } else if (num <= 0x7f) {
        /* 7 bit or smaller tag num. */
        return 2;
    } else if (num <= 0x3fff) {
        /* 14 bit or smaller tag num. */
        return 3;
    } else if (num <= 0x1fffff) {
        /* 21 bit or smaller tag num. */
        return 4;
    } else if (num <= 0xfffffff) {
        /* 28 bit or smaller tag num. */
        return 5;
    } else {
        /* 35 bit or smaller tag num. */
        return 6;
    }
#else
    (void)tag;
    return 1;
#endif /* !CCDER_MULTIBYTE_TAGS */
}
