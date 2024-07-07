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

#ifndef _CORECRYPTO_CCDER_ENCODE_OCTET_STRING_H_
#define _CORECRYPTO_CCDER_ENCODE_OCTET_STRING_H_

#include <corecrypto/ccder.h>

#ifdef CCDER_ENCODE_OCTET_STRING_SPECIFIER
CCDER_ENCODE_OCTET_STRING_SPECIFIER
#endif
CC_NONNULL((2, 3))
uint8_t *ccder_encode_octet_string(cc_size n, const cc_unit *s,
                                   const uint8_t *der, uint8_t *der_end) {
    return ccder_encode_implicit_octet_string(CCDER_OCTET_STRING, n, s, der, der_end);
}

#endif /* _CORECRYPTO_CCDER_ENCODE_OCTET_STRING_H_ */
