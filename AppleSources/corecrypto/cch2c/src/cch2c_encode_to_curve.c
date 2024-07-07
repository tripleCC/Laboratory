/* Copyright (c) (2022) Apple Inc. All rights reserved.
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
#include "ccec_internal.h"
#include "cch2c_internal.h"
#include "cc_macros.h"
#include "cc_memory.h"
#include "cc_workspaces.h"

int cch2c_encode_to_curve_ro_ws(cc_ws_t ws,
                                const struct cch2c_info *info,
                                size_t dst_nbytes, const void *dst,
                                size_t data_nbytes, const void *data,
                                ccec_pub_ctx_t q)
{
    int status;

    ccec_const_cp_t cp = info->curve_params();
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *u0 = CC_ALLOC_WS(ws, n);
    cc_unit *u1 = CC_ALLOC_WS(ws, n);
    ccec_pub_ctx_t q0 = CCEC_ALLOC_PUB_WS(ws, n);
    ccec_pub_ctx_t q1 = CCEC_ALLOC_PUB_WS(ws, n);

    ccec_ctx_init(cp, q);

    status = cch2c_hash_to_base_ws(ws, info, dst_nbytes, dst, data_nbytes, data, 0, u0);
    cc_require(status == CCERR_OK, out);

    status = cch2c_hash_to_base_ws(ws, info, dst_nbytes, dst, data_nbytes, data, 1, u1);
    cc_require(status == CCERR_OK, out);

    status = cch2c_map_to_curve_ws(ws, info, u0, q);
    cc_require(status == CCERR_OK, out);

    status = ccec_projectify_ws(ws, cp, ccec_ctx_point(q0), (ccec_const_affine_point_t)ccec_ctx_point(q), NULL);
    cc_require(status == CCERR_OK, out);

    status = cch2c_map_to_curve_ws(ws, info, u1, q);
    cc_require(status == CCERR_OK, out);

    status = ccec_projectify_ws(ws, cp, ccec_ctx_point(q1), (ccec_const_affine_point_t)ccec_ctx_point(q), NULL);
    cc_require(status == CCERR_OK, out);

    ccec_full_add_ws(ws, cp, ccec_ctx_point(q0), ccec_ctx_point(q0), ccec_ctx_point(q1));

    status = ccec_affinify_ws(ws, cp, (ccec_affine_point_t)ccec_ctx_point(q), ccec_ctx_point(q0));
    cc_require(status == CCERR_OK, out);

    status = info->clear_cofactor(info, q);
    cc_require(status == CCERR_OK, out);

out:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

CC_WORKSPACE_OVERRIDE(cch2c_encode_to_curve_ws, cch2c_encode_to_curve_ro_ws)

int cch2c_encode_to_curve_ws(cc_ws_t ws,
                             const struct cch2c_info *info,
                             size_t dst_nbytes, const void *dst,
                             size_t data_nbytes, const void *data,
                             ccec_pub_ctx_t pubkey)
{
    return info->encode_to_curve(ws, info, dst_nbytes, dst, data_nbytes, data, pubkey);
}
