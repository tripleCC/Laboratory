/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccpolyzp_po2cyc_internal.h"
#include "ccpolyzp_po2cyc_ctx_chain.h"
#include "ccpolyzp_po2cyc_base_convert.h"
#include "ccpolyzp_po2cyc_scalar.h"

CC_PURE size_t sizeof_struct_ccpolyzp_po2cyc(void)
{
    return sizeof(struct ccpolyzp_po2cyc_coeff);
}

CC_PURE size_t sizeof_struct_ccpolyzp_po2cyc_base_convert(void)
{
    return sizeof(struct ccpolyzp_po2cyc_base_convert);
}

CC_PURE size_t sizeof_struct_ccpolyzp_po2cyc_ctx(void)
{
    return sizeof(struct ccpolyzp_po2cyc_ctx);
}

CC_PURE size_t sizeof_struct_ccpolyzp_po2cyc_ctx_chain(void)
{
    return sizeof(struct ccpolyzp_po2cyc_ctx_chain);
}

CC_PURE size_t sizeof_struct_ccrns_mul_modulus(void)
{
    return sizeof(struct ccrns_mul_modulus);
}
