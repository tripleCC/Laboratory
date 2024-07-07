/* Copyright (c) (2015,2016,2019-2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccder.h>
#include "cc_macros.h"
#include "cc_debug.h"

int ccec_der_import_diversified_pub(
    ccec_const_cp_t cp, 
    size_t length, const uint8_t *data,
    int *outflags,
    ccec_pub_ctx_t  diversified_generator,
    ccec_pub_ctx_t  diversified_key
    )
{
    CC_ENSURE_DIT_ENABLED

    int retval=-1;
    const uint8_t *der=data;
    const uint8_t *der_end=der+length;
    size_t der_len;
    const uint8_t *key_ptr=NULL;
    const uint8_t *gen_ptr=NULL;
    size_t key_len = 0;
    size_t gen_len = 0;
    bool compact = true;

    der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end);

    // Parse Generator
    der = ccder_decode_tl(CCDER_OCTET_STRING, &der_len, der, der_end);
    if (der) {
        gen_ptr = der;
        gen_len = der_len;
        der += der_len;
    }

    // Parse Key
    der = ccder_decode_tl(CCDER_OCTET_STRING, &der_len, der, der_end);
    if (der) {
        key_ptr = der;
        key_len = der_len;
        der += der_len;
    }

    cc_require(der==(data+length), errOut);
    cc_require(gen_ptr!=NULL && key_ptr!=NULL, errOut);

    // Import the generator. Try compact and non compact if it fails.
    retval = ccec_compact_import_pub(cp, gen_len, gen_ptr, diversified_generator);
    if (retval != CCERR_OK) {
        compact = false;
        retval = ccec_import_pub(cp, gen_len, gen_ptr, diversified_generator);
        cc_require(retval == CCERR_OK, errOut);
    }

    // Import the key
    if (compact) {
        retval = ccec_compact_import_pub(cp, key_len, key_ptr, diversified_key);
    } else {
        retval = ccec_import_pub(cp, key_len, key_ptr, diversified_key);
    }
    cc_require(retval == CCERR_OK, errOut);

    if (outflags) {
        *outflags = compact ? CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS : 0;
    }

errOut:
    return retval;
 }

