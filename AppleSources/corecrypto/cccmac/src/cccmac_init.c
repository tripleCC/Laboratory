/* Copyright (c) (2013-2019,2021,2022) Apple Inc. All rights reserved.
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

int cccmac_init(const struct ccmode_cbc *cbc,
                 cccmac_ctx_t ctx,
                 size_t key_nbytes, const void *key_data)
{
    CC_ENSURE_DIT_ENABLED

    int status;
    if (key_nbytes != 16 && key_nbytes != 24 && key_nbytes != 32) {
        return CCERR_PARAMETER; /* Invalid key size */
    }

    cccbc_init(cbc, cccmac_mode_sym_ctx(cbc, ctx), key_nbytes, key_data);
    const uint8_t zeros[CMAC_BLOCKSIZE] = { 0 };
    cccbc_set_iv(cbc, cccmac_mode_iv(cbc, ctx), zeros);
    cccmac_cbc(ctx)=cbc;
    cccmac_block_nbytes(ctx)=0;
    cccmac_cumulated_nbytes(ctx)=0;
    status = cccmac_generate_subkeys(cbc, key_nbytes, key_data,
                           cccmac_k1(ctx), cccmac_k2(ctx));
    return status;
}
