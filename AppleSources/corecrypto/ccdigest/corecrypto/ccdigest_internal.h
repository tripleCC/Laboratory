/* Copyright (c) (2017-2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDIGEST_INTERNAL_H_
#define _CORECRYPTO_CCDIGEST_INTERNAL_H_

#include <corecrypto/ccdigest_priv.h>

void ccdigest_final_64be(const struct ccdigest_info *di, ccdigest_ctx_t,
                         unsigned char *digest);
void ccdigest_final_64le(const struct ccdigest_info *di, ccdigest_ctx_t,
                         unsigned char *digest);

CC_INLINE CC_NONNULL((1))
bool ccdigest_oid_equal(const struct ccdigest_info *di, ccoid_t oid) {
    return ccoid_equal(di->oid, oid);
}

#endif /* _CORECRYPTO_CCDIGEST_INTERNAL_H_ */
