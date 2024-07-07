/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
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

#if CC_EFI

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincompatible-pointer-types-discards-qualifiers"

void *cc_memmove(void *dst, const void *src, size_t len) {
    EfiCopyMem(dst, src, len);
    return dst;
}

void *cc_memcpy(void *dst, const void *src, size_t len) {
    return cc_memmove(dst, src, len);
}

void *cc_memset(void *dst, int val, size_t num) {
    // Note the order of arguments to EfiSetMem
    EfiSetMem(dst, num, val & 0xff);
    return dst;
}

int cc_memcmp(const void *buf1, const void *buf2, size_t len) {
    return (int) EfiCompareMem(buf1, buf2, len);
}

#pragma clang diagnostic pop

#endif // CC_EFI
