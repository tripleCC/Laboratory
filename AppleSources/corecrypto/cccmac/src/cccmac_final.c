/* Copyright (c) (2010,2011,2013-2019,2021) Apple Inc. All rights reserved.
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
#include "cccmac_internal.h"

int cccmac_final_generate(cccmac_ctx_t ctx,
                  size_t mac_nbytes, void *mac) {
    CC_ENSURE_DIT_ENABLED

    int status=-1;
    size_t  final_nbytes = cccmac_block_nbytes(ctx);
    uint8_t *final_buf = cccmac_block(ctx);
    void *subkey = cccmac_k2(ctx);
    uint8_t full_mac[CMAC_BLOCKSIZE];
    const struct ccmode_cbc *cbc=cccmac_cbc(ctx);

    cccmac_cumulated_nbytes(ctx)+=final_nbytes;

    cc_require((final_nbytes <= CMAC_BLOCKSIZE)
               && ((final_nbytes > 0) || cccmac_cumulated_nbytes(ctx)==0),errOut); /* Invalid parameter: data */
    cc_require(mac_nbytes <= CMAC_BLOCKSIZE && mac_nbytes > 0,errOut); /* Invalid mac: data */

    // If Mn* is a complete block, let Mn = K1 ⊕ Mn*;
    if(final_nbytes == CMAC_BLOCKSIZE) {
        subkey = cccmac_k1(ctx);
    }
    // else, let Mn = K2 ⊕ (Mn*||10j), where j = nb-Mlen-1.
    else {
        cc_clear(CMAC_BLOCKSIZE-final_nbytes,final_buf+final_nbytes);
        final_buf[final_nbytes] = 0x80;
    }
    cc_xor(CMAC_BLOCKSIZE, final_buf, final_buf,subkey);
    cccbc_update(cbc,cccmac_mode_sym_ctx(cbc,ctx),cccmac_mode_iv(cbc, ctx),
                 1, final_buf, full_mac);
    cc_memcpy(mac,full_mac,mac_nbytes);
    status = 0;
errOut:
    cccmac_mode_clear(cccmac_cbc(ctx),CCCMAC_HDR(ctx));
    return status;
}

int cccmac_final_verify(cccmac_ctx_t ctx,
                     size_t expected_mac_nbytes, const void *expected_mac) {
    CC_ENSURE_DIT_ENABLED

    int status;
    uint8_t full_mac[CMAC_BLOCKSIZE];
    status=cccmac_final_generate(ctx,CMAC_BLOCKSIZE,full_mac);
    if (status != 0) {
        return status; // Computation error
    }
    if (cc_cmp_safe(expected_mac_nbytes, expected_mac, full_mac) == 0) {
        return 0;      // MAC matches
    }
    return -5;         // MAC mismatches
}
