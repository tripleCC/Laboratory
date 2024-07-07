/* Copyright (c) (2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccmode_internal.h"

int ccmode_ctr_setctr(CC_UNUSED const struct ccmode_ctr *mode, ccctr_ctx *ctx, const void *ctr)
{
    CCMODE_CTR_KEY_PAD_OFFSET(ctx) = CCMODE_CTR_KEY_ECB(ctx)->block_size;
    cc_memcpy(CCMODE_CTR_KEY_CTR(ctx), ctr, CCMODE_CTR_KEY_ECB(ctx)->block_size);
    
    return 0;
}
