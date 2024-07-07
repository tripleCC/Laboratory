/* Copyright (c) (2011,2012,2015,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrsa.h>

int ccrsa_import_pub(ccrsa_pub_ctx_t key, size_t inlen, const uint8_t *der)
{
    CC_ENSURE_DIT_ENABLED

    const uint8_t *der_out = ccder_decode_rsa_pub_x509(key, der, der+inlen);
    if (der_out == NULL) {
        der_out = ccder_decode_rsa_pub(key, der, der+inlen);
    }
    if (der_out == NULL) {
        return CCERR_PARAMETER;
    }
    return CCERR_OK;
}
