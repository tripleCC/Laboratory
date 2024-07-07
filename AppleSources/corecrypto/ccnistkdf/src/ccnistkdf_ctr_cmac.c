/* Copyright (c) (2018,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccnistkdf.h>
#include <corecrypto/cc.h>

#include "cc_macros.h"
#include "cc_memory.h"
#include "ccnistkdf_internal.h"

/**
 The inner block of the key derivation, with evaluation of the PRF.

 @param cmac The CMAC context
 @param r The length of the binary representation of the counter i
 @param counter The iteration counter
 @param fixedData_nbytes The length of the fixed data in an iteration
 @param fixedData The fixed data of an iteration
 @param result The result of a PRF evaluation in an iteration
 */
static void
PRF_EVAL (struct cccmac_ctx* cmac, uint8_t r, uint32_t counter, size_t fixedData_nbytes, const void *fixedData, void *result)
{
    cccmac_update_r(cmac, r, counter);
    cccmac_update(cmac, fixedData_nbytes, fixedData);
    cccmac_final_generate(cmac, cmac->cbc->block_size, result);
}

int ccnistkdf_ctr_cmac_fixed(const struct ccmode_cbc *cbc,
                             uint8_t r, size_t kdk_nbytes, const void *kdk,
                             size_t fixedData_nbytes, const void *fixedData,
                             size_t dk_nbytes, void *dk) {
    CC_ENSURE_DIT_ENABLED

    size_t h = cbc->block_size;
    if(dk_nbytes == 0) return CCERR_PARAMETER;
    
    uint8_t lastBlockBuf[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t *result = dk;
    
    size_t completeBlocks = dk_nbytes / h;
    size_t partialBlock_nbytes = dk_nbytes % h;
    size_t evaluatedBlocks = (partialBlock_nbytes > 0) ? (completeBlocks + 1) : completeBlocks;

    if ((r!=8) && (r!=16) && (r!=24) && (r!=32))return CCERR_PARAMETER;
    if (evaluatedBlocks > ((1ULL<<r)-1)) return CCERR_PARAMETER;
    if(kdk_nbytes == 0 || kdk == NULL) return CCERR_PARAMETER;
    if(dk_nbytes == 0 || dk == NULL) return CCERR_PARAMETER;

    cccmac_mode_decl(cbc, cache);
    cccmac_mode_decl(cbc, cmac);

    cccmac_init(cbc, cache, kdk_nbytes, kdk);

    for(uint32_t i = 1; i <= completeBlocks; i++, result += h) {
        cc_memcpy(cmac, cache, sizeof(cache));
        PRF_EVAL(cmac, r, i, fixedData_nbytes, fixedData, result);
    }
    
    if (partialBlock_nbytes > 0) {
        cc_memcpy(cmac, cache, sizeof(cache));
        PRF_EVAL(cmac, r, (uint32_t)evaluatedBlocks, fixedData_nbytes, fixedData, lastBlockBuf);
        cc_memcpy(result, lastBlockBuf, partialBlock_nbytes);
    }

    cc_clear(h, lastBlockBuf);

    cccmac_mode_clear(cbc, cache);
    cccmac_mode_clear(cbc, cmac);

    return CCERR_OK;
}

int ccnistkdf_ctr_cmac(const struct ccmode_cbc *cbc,
                       uint8_t r, size_t kdk_nbytes, const void *kdk,
                       size_t label_nbytes, const void *label,
                       size_t context_nbytes, const void *context,
                       size_t dk_nbytes, size_t dk_len_nbytes, void *dk)
{
    CC_ENSURE_DIT_ENABLED

    size_t fixedData_nbytes = label_nbytes + context_nbytes + 1 + dk_len_nbytes;

    cc_size n = ccn_nof_size(fixedData_nbytes);
    CC_DECL_WORKSPACE_OR_FAIL(ws, n);

    uint8_t *fixedData = (uint8_t *)CC_ALLOC_WS(ws, n);
    int retval = construct_fixed_data(label_nbytes, label, context_nbytes, context, dk_nbytes, dk_len_nbytes, fixedData);
    cc_require(retval == CCERR_OK, errOut);

    retval = ccnistkdf_ctr_cmac_fixed(cbc, r, kdk_nbytes, kdk, fixedData_nbytes, fixedData, dk_nbytes, dk);

errOut:
    CC_FREE_WORKSPACE(ws);
    return retval;
}
