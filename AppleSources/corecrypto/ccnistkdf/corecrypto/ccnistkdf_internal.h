/* Copyright (c) (2013-2015,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCNISTKDF_INTERNAL_H_
#define _CORECRYPTO_CCNISTKDF_INTERNAL_H_

#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/cccmac.h>
#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccnistkdf.h>

/**
 Updates CMAC with r bits of the counter.
 
 @param cmac The CMAC context
 @param r The size of the binary representation of the counter
 @param counter The value of the counter (i)
 */
CC_INLINE void cccmac_update_r(struct cccmac_ctx* cmac, uint8_t r, uint32_t counter) {
    size_t tmp = 0;
    uint8_t r_bytes = r/8;
    uint8_t bytes_offset = 4-r_bytes;
    
    cc_store32_be(counter, (uint8_t *) &tmp);
    tmp = tmp >> bytes_offset*8;
    
    cccmac_update(cmac, r_bytes, &tmp);
}

CC_INLINE void ccdigest_update_uint32_t(const struct ccdigest_info *di, ccdigest_ctx_t ctx, uint32_t n) {
    uint32_t tmp;
    cc_store32_be(n, (uint8_t *) &tmp);
    ccdigest_update(di, ctx, 4, &tmp);
}


#define cchmac_state_cache(_name_) \
    cc_unit _name_[ccn_nof_size(MAX_DIGEST_STATE_SIZE)]

CC_INLINE void cchmac_cache_state(const struct ccdigest_info *di, cchmac_ctx_t hc, cc_unit *cache) {
    ccdigest_copy_state(di, cache, cchmac_istate32(di, hc));
}

CC_INLINE void cchmac_reset_from_cache(const struct ccdigest_info *di,
                                           cchmac_ctx_t hc,
                                           const cc_unit *cache) {
    ccdigest_copy_state(di, cchmac_istate32(di, hc), cache);
    cchmac_nbits(di, hc) = di->block_size * 8;
    cchmac_num(di, hc)=0;
}

#define DEBUG_DUMP 0
#if DEBUG_DUMP

static void cc_internal_print_fixed_data(uint8_t *fixedData, size_t labelLen, size_t contextLen) {
    size_t i;
    uint8_t *p = fixedData;
    
    printf("Fixed Data\nLabel: ");
    for(i = 0; i < labelLen; i++, p++) printf("%02x", *p);
    printf("\nZeroByte: %02x\n", *p);
    p++;
    printf("Context: ");
    for(i = 0; i < contextLen; i++, p++) printf("%02x", *p);
    printf("\nKeyLength: %02x%02x%02x%02x\n", *p, *(p+1), *(p+2), *(p+3));
}

#else

#define cc_internal_print_fixed_data(X,Y,Z) do { } while(0)

#endif

CC_UNUSED
CC_WARN_RESULT
static int construct_fixed_data(size_t label_nbytes, const uint8_t *label,
                                size_t context_nbytes, const uint8_t *context,
                                size_t dk_nbytes, size_t dk_len_nbytes, uint8_t *fixedData)
{
    // fixedData = Label || 0x00 || Context || dkLen*8 (encoded on dkLenSize bits)
    if(dk_nbytes*8 > ((1ULL<<dk_len_nbytes * 8) - 1) || dk_len_nbytes > 4) {
        return CCERR_PARAMETER;
    }
    
    if(label_nbytes > 0 && label != NULL) {
        cc_memcpy(fixedData, label, label_nbytes);
    }
    
    fixedData[label_nbytes] = 0;
    
    if(context_nbytes > 0 && context != NULL) {
        cc_memcpy(fixedData + label_nbytes + 1, context, context_nbytes);
    }
    
    uint32_t be_dk_len = 0;
    cc_store32_be((uint32_t)dk_nbytes*8, (uint8_t *)&be_dk_len);
    be_dk_len = be_dk_len >> (4-dk_len_nbytes)*8;
    
    cc_memcpy(fixedData + label_nbytes + context_nbytes + 1, &be_dk_len, dk_len_nbytes);

    cc_internal_print_fixed_data(fixedData, labelLen, contextLen);
    return CCERR_OK;
}

#endif // _CORECRYPTO_CCNISTKDF_INTERNAL_H_
