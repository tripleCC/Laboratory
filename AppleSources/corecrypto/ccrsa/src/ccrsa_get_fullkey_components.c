/* Copyright (c) (2011,2012,2015,2016,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrsa_priv.h>

CC_INLINE
int ccCoreZP2pointerAndData(size_t n, const cc_unit *source, uint8_t *dest, size_t *destLen)
{
    size_t len;
    if((len = ccn_write_uint_size(n, source)) > *destLen) {
        return -1;
    }
    *destLen = len;
    ccn_write_uint(n, source, *destLen, dest);
    return 0;
}


int ccrsa_get_fullkey_components(const ccrsa_full_ctx_t key, 
                                 uint8_t *modulus, size_t *modulusLength, 
                                 uint8_t *d, size_t *dLength,
                                 uint8_t *p, size_t *pLength, 
                                 uint8_t *q, size_t *qLength)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccrsa_ctx_n(key);
    if(ccCoreZP2pointerAndData(cczp_n(ccrsa_ctx_private_zp(key)),
                               cczp_prime(ccrsa_ctx_private_zp(key)),
                               p, pLength )) return -1;
    if(ccCoreZP2pointerAndData(cczp_n(ccrsa_ctx_private_zq(key)),
                               cczp_prime(ccrsa_ctx_private_zq(key)),
                               q, qLength )) return -1;
    if(ccCoreZP2pointerAndData(n,
                               ccrsa_ctx_m(key),
                               modulus, modulusLength )) return -1;
    if(ccCoreZP2pointerAndData(n,
                               ccrsa_ctx_d(key),
                               d, dLength )) return -1;

    return 0;
}

