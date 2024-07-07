/* Copyright (c) (2015,2016,2018-2023) Apple Inc. All rights reserved.
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
#include "cc_fault_canary_internal.h"
#include "cc_macros.h"

static int ccrsa_verify_pss_digest_ws(cc_ws_t ws,
                                      ccrsa_pub_ctx_t key,
                                      const struct ccdigest_info *di,
                                      const struct ccdigest_info *mgfdi,
                                      size_t digestSize,
                                      const uint8_t *digest,
                                      size_t sigSize,
                                      const uint8_t *sig,
                                      size_t saltSize,
                                      cc_fault_canary_t fault_canary_out)
{
    if (fault_canary_out) {
        CC_FAULT_CANARY_CLEAR(fault_canary_out);
    }
    cc_fault_canary_t fault_canary;
    CC_FAULT_CANARY_CLEAR(fault_canary);

    const cc_size modBits = cczp_bitlen(ccrsa_ctx_zm(key));
    const cc_size modBytes = cc_ceiling(modBits, 8);
    const cc_size emBits = modBits - 1; // as defined in §8.1.1
    const cc_size emSize = cc_ceiling(emBits, 8);

    const cc_size n = ccrsa_ctx_n(key);
    const size_t ofs = ccn_sizeof_n(n) - emSize;

    // 1.
    if ((modBytes != sigSize) || (digestSize != di->output_size) || (ofs > sizeof(cc_unit))) {
        return CCRSA_INVALID_INPUT;
    }
    if (modBytes == 0) {
        return CCRSA_KEY_ERROR;
    }

    volatile int rv;

    // 2.
    CC_DECL_BP_WS(ws, bp);
    cc_unit *s = CC_ALLOC_WS(ws, n);
    cc_unit *EM = CC_ALLOC_WS(ws, n);
    CC_CLEAR_BP_WS(ws, bp);

    // 2.a read sig to tmp array and make sure it fits
    rv = CCERR_INTERNAL;
    rv = ccn_read_uint(n, s, sigSize, sig);
    cc_require_action(CC_MULTI_IF_AND(rv == 0), errOut, rv = CCRSA_INVALID_INPUT);

    // 2.b
    rv = CCERR_INTERNAL;
    rv = ccrsa_pub_crypt_ws(ws, key, EM, s);
    cc_require(CC_MULTI_IF_AND(rv == CCERR_OK), errOut);

    // 2.c
    ccn_swap(n, EM);

    // 3
    rv = CCERR_INTERNAL;
    rv = ccrsa_emsa_pss_decode_canary_out_ws(ws, di, mgfdi, saltSize, digestSize, digest, emBits, (uint8_t *)EM + ofs, fault_canary);

    // rv = CCERR_VALID_SIGNATURE, if fault canary is good.
    rv ^= CCRSA_PSS_FAULT_CANARY_XOR;
    CC_FAULT_CANARY_XOR_RV(rv, fault_canary);

    if (fault_canary_out) {
        CC_FAULT_CANARY_MEMCPY(fault_canary_out, fault_canary);
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccrsa_verify_pss_digest(ccrsa_pub_ctx_t key,
                            const struct ccdigest_info *di,
                            const struct ccdigest_info *mgfdi,
                            size_t digestSize,
                            const uint8_t *digest,
                            size_t sigSize,
                            const uint8_t *sig,
                            size_t saltSize,
                            cc_fault_canary_t fault_canary_out)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_VERIFY_PSS_DIGEST_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_verify_pss_digest_ws(ws, key, di, mgfdi, digestSize, digest, sigSize, sig, saltSize, fault_canary_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccrsa_verify_pss_msg_ws(cc_ws_t ws,
                            ccrsa_pub_ctx_t key,
                            const struct ccdigest_info *di,
                            const struct ccdigest_info *mgfdi,
                            size_t msg_nbytes,
                            const uint8_t *msg,
                            size_t sig_nbytes,
                            const uint8_t *sig,
                            size_t salt_nbytes,
                            cc_fault_canary_t fault_canary_out)
{
    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];
    ccdigest(di, msg_nbytes, msg, digest);
    return ccrsa_verify_pss_digest_ws(ws, key, di, mgfdi, di->output_size, digest, sig_nbytes, sig, salt_nbytes, fault_canary_out);
}

int ccrsa_verify_pss_msg(ccrsa_pub_ctx_t key,
                         const struct ccdigest_info *di,
                         const struct ccdigest_info *mgfdi,
                         size_t msg_nbytes,
                         const uint8_t *msg,
                         size_t sig_nbytes,
                         const uint8_t *sig,
                         size_t salt_nbytes,
                         cc_fault_canary_t fault_canary_out)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_VERIFY_PSS_MSG_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_verify_pss_msg_ws(ws, key, di, mgfdi, msg_nbytes, msg, sig_nbytes, sig, salt_nbytes, fault_canary_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
