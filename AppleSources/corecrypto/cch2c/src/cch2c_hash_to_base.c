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
#include "cch2c_internal.h"
#include "cc_macros.h"
#include "cc_memory.h"
#include "cc_workspaces.h"
#include "cczp_internal.h"

#include <corecrypto/cchkdf.h>

int cch2c_hash_to_base_sae_ws(cc_ws_t ws,
                              const struct cch2c_info *info,
                              size_t dst_nbytes, const void *dst,
                              size_t data_nbytes, const void *data,
                              uint8_t ctr,
                              cc_unit *u)
{
    int status = CCERR_PARAMETER;
    // The info string has the literals '1' and '2' in it, depending on invocation.
    // ord('1') == 49, hence ctr + 49
    const uint8_t hkdf_info[25] = { 'S', 'A', 'E', ' ', 'H', 'a', 's', 'h', ' ', 't', 'o', ' ', 'E', 'l', 'e', 'm', 'e', 'n', 't', ' ', 'u', ctr + 49, ' ', 'P', ctr + 49 };

    uint8_t buf[CCH2C_MAX_DATA_NBYTES] = { 0 };

    ccec_const_cp_t cp = info->curve_params();
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, 2*n);

    const struct ccdigest_info *di = info->digest_info();

    cc_require(cchkdf_extract(di, dst_nbytes, dst, data_nbytes, data, buf) == CCERR_OK, out);
    cc_require(cchkdf_expand(di, di->output_size, buf, sizeof(hkdf_info), hkdf_info,
                             info->l, buf) == CCERR_OK, out);

    cc_require(ccn_read_uint(2 * n, t, info->l, buf) == CCERR_OK, out);
    cczp_mod_ws(ws, zp, u, t);

    status = CCERR_OK;
out:
    CC_FREE_BP_WS(ws,bp);
    return status;
}

// See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-5.3
int cch2c_hash_to_base_rfc_ws(cc_ws_t ws,
                              const struct cch2c_info *info,
                              size_t dst_nbytes, const void *dst,
                              size_t data_nbytes, const void *data,
                              uint8_t ctr,
                              cc_unit *u)
{
    int status = CCERR_PARAMETER;

    uint8_t hkdf_info[5] = { 'H', '2', 'C', ctr, 1 };
    uint8_t buf[CCH2C_MAX_DATA_NBYTES + 1] = { 0 };

    ccec_const_cp_t cp = info->curve_params();
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, 2 * n);

    const struct ccdigest_info *di = info->digest_info();

    cc_require(data_nbytes <= CCH2C_MAX_DATA_NBYTES, out);

    cc_memcpy(buf, data, data_nbytes);
    cc_require(cchkdf_extract(di, dst_nbytes, dst, data_nbytes + 1, buf, buf) == CCERR_OK, out);

    cc_require(cchkdf_expand(di, di->output_size, buf, sizeof(hkdf_info), hkdf_info,
                             info->l, buf) == CCERR_OK, out);

    cc_require(ccn_read_uint(2 * n, t, info->l, buf) == CCERR_OK, out);
    cczp_mod_ws(ws, zp, u, t);

    status = CCERR_OK;

out:
    CC_FREE_BP_WS(ws, bp);
    return status;
}

CC_WORKSPACE_OVERRIDE(cch2c_hash_to_base_ws, cch2c_hash_to_base_rfc_ws)
CC_WORKSPACE_OVERRIDE(cch2c_hash_to_base_ws, cch2c_hash_to_base_sae_ws)

int cch2c_hash_to_base_ws(cc_ws_t ws,
                          const struct cch2c_info *info,
                          size_t dst_nbytes, const void *dst,
                          size_t data_nbytes, const void *data,
                          uint8_t ctr,
                          cc_unit *u)
{
    return info->hash_to_base(ws, info, dst_nbytes, dst, data_nbytes, data, ctr, u);
}
