/* Copyright (c) (2020-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/cc.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cch2c_priv.h>

#include "cc_memory.h"
#include "cch2c_internal.h"
#include "cc_macros.h"
#include "cc_workspaces.h"

CC_NONNULL_ALL CC_WARN_RESULT
static int clear_cofactor_nop(CC_UNUSED const struct cch2c_info *info,
                              CC_UNUSED ccec_pub_ctx_t pubkey)
{
    return CCERR_OK;
}

int cch2c_ws(cc_ws_t ws, const struct cch2c_info *info,
             size_t dst_nbytes, const void *dst,
             size_t data_nbytes, const void *data,
             ccec_pub_ctx_t pubkey)
{
    if (dst_nbytes == 0) {
        return CCERR_PARAMETER;
    }

    return cch2c_encode_to_curve_ws(ws, info, dst_nbytes, dst, data_nbytes, data, pubkey);
}

int cch2c(const struct cch2c_info *info,
          size_t dst_nbytes, const void *dst,
          size_t data_nbytes, const void *data,
          ccec_pub_ctx_t pubkey)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = info->curve_params();
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCH2C_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = cch2c_ws(ws, info, dst_nbytes, dst, data_nbytes, data, pubkey);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

const char *cch2c_name(const struct cch2c_info *info)
{
    CC_ENSURE_DIT_ENABLED

    return info->name;
}

const struct cch2c_info cch2c_p256_sha256_sswu_ro_info = {
    .name = "P256-SHA256-SSWU-RO-",
    .l = 48,
    .z = 10,
    .curve_params = ccec_cp_256,
    .digest_info = ccsha256_di,
    .hash_to_base = cch2c_hash_to_base_rfc_ws,
    .map_to_curve = cch2c_map_to_curve_sswu_ws,
    .clear_cofactor = clear_cofactor_nop,
    .encode_to_curve = cch2c_encode_to_curve_ro_ws,
};

const struct cch2c_info cch2c_p384_sha512_sswu_ro_info = {
    .name = "P384-SHA512-SSWU-RO-",
    .l = 72,
    .z = 12,
    .curve_params = ccec_cp_384,
    .digest_info = ccsha512_di,
    .hash_to_base = cch2c_hash_to_base_rfc_ws,
    .map_to_curve = cch2c_map_to_curve_sswu_ws,
    .clear_cofactor = clear_cofactor_nop,
    .encode_to_curve = cch2c_encode_to_curve_ro_ws,
};

const struct cch2c_info cch2c_p521_sha512_sswu_ro_info = {
    .name = "P521-SHA512-SSWU-RO-",
    .l = 96,
    .z = 4,
    .curve_params = ccec_cp_521,
    .digest_info = ccsha512_di,
    .hash_to_base = cch2c_hash_to_base_rfc_ws,
    .map_to_curve = cch2c_map_to_curve_sswu_ws,
    .clear_cofactor = clear_cofactor_nop,
    .encode_to_curve = cch2c_encode_to_curve_ro_ws,
};

const struct cch2c_info cch2c_p256_sha256_sae_compat_info = {
    .l = 48,
    .z = 10,
    .curve_params = ccec_cp_256,
    .digest_info = ccsha256_di,
    .hash_to_base = cch2c_hash_to_base_sae_ws,
    .map_to_curve = cch2c_map_to_curve_sswu_ws,
    .clear_cofactor = clear_cofactor_nop,
    .encode_to_curve = cch2c_encode_to_curve_ro_ws,
};

const struct cch2c_info cch2c_p384_sha384_sae_compat_info = {
    .l = 72,
    .z = 12,
    .curve_params = ccec_cp_384,
    .digest_info = ccsha384_di,
    .hash_to_base = cch2c_hash_to_base_sae_ws,
    .map_to_curve = cch2c_map_to_curve_sswu_ws,
    .clear_cofactor = clear_cofactor_nop,
    .encode_to_curve = cch2c_encode_to_curve_ro_ws,
};
