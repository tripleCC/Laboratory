/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
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
#include "ccrsa_internal.h"
#include "cc_macros.h"
#include "cc_debug.h"

int ccrsa_verify_pkcs1v15_allowshortsigs(ccrsa_pub_ctx_t key,
                                         const uint8_t *oid,
                                         size_t digest_len,
                                         const uint8_t *digest,
                                         size_t sig_len,
                                         const uint8_t *sig,
                                         bool *valid)
{
    CC_ENSURE_DIT_ENABLED

    *valid = false;
    cc_fault_canary_t unused_fault_canary;
    int status = ccrsa_verify_pkcs1v15_internal(
        key, oid, digest_len, digest, sig_len, sig, CCRSA_SIG_LEN_VALIDATION_ALLOW_SHORT_SIGS, unused_fault_canary);
    // Backwards compatibility
    if (status == CCERR_VALID_SIGNATURE) {
        *valid = true;
        status = CCERR_OK;
    } else if (status == CCERR_INVALID_SIGNATURE) {
        status = CCERR_OK;
    }

    return status;
}
