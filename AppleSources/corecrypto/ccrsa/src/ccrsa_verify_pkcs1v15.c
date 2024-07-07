/* Copyright (c) (2011,2012,2014-2016,2018-2021) Apple Inc. All rights reserved.
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

int ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t key,
                          const uint8_t *oid,
                          size_t digest_len,
                          const uint8_t *digest,
                          size_t sig_len,
                          const uint8_t *sig,
                          bool *valid)
{
    CC_ENSURE_DIT_ENABLED

    *valid = false;
    int status = ccrsa_verify_pkcs1v15_digest(key, oid, digest_len, digest, sig_len, sig, NULL);

    // Backwards compatibility
    if (status == CCERR_VALID_SIGNATURE) {
        *valid = true;
        status = CCERR_OK;
    } else if (status == CCERR_INVALID_SIGNATURE) {
        status = CCERR_OK;
    }

    return status;
}

int ccrsa_verify_pkcs1v15_digest_ws(cc_ws_t ws,
                                    ccrsa_pub_ctx_t key,
                                    const uint8_t *oid,
                                    size_t digest_len,
                                    const uint8_t *digest,
                                    size_t sig_len,
                                    const uint8_t *sig,
                                    cc_fault_canary_t fault_canary_out)
{
    if (fault_canary_out) {
        CC_FAULT_CANARY_CLEAR(fault_canary_out);
    }

    cc_fault_canary_t fault_canary;
    CC_FAULT_CANARY_CLEAR(fault_canary);

    int res =
        ccrsa_verify_pkcs1v15_internal_ws(ws, key, oid, digest_len, digest, sig_len, sig, CCRSA_SIG_LEN_VALIDATION_STRICT, fault_canary);
    if (fault_canary_out) {
        CC_FAULT_CANARY_MEMCPY(fault_canary_out, fault_canary);
    }
    return res;
}

int ccrsa_verify_pkcs1v15_digest(ccrsa_pub_ctx_t key,
                                 const uint8_t *oid,
                                 size_t digest_len,
                                 const uint8_t *digest,
                                 size_t sig_len,
                                 const uint8_t *sig,
                                 cc_fault_canary_t fault_canary_out)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_VERIFY_PKCS1V15_DIGEST_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_verify_pkcs1v15_digest_ws(ws, key, oid, digest_len, digest, sig_len, sig, fault_canary_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccrsa_verify_pkcs1v15_msg(ccrsa_pub_ctx_t key,
                              const struct ccdigest_info *di,
                              size_t msg_len,
                              const uint8_t *msg,
                              size_t sig_len,
                              const uint8_t *sig,
                              cc_fault_canary_t fault_canary_out)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];
    ccdigest(di, msg_len, msg, digest);

    return ccrsa_verify_pkcs1v15_digest(key, di->oid, di->output_size, digest, sig_len, sig, fault_canary_out);
}
