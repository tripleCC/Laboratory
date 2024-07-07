/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec.h>
#include "cc_workspaces.h"

CC_PURE size_t sizeof_struct_ccec_full_ctx(void)
{
    return sizeof(struct ccec_full_ctx);
}

CC_PURE size_t sizeof_struct_ccec_pub_ctx(void)
{
    return sizeof(struct ccec_pub_ctx);
}
