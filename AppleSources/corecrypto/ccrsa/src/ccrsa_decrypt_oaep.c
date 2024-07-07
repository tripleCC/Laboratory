/* Copyright (c) (2011-2013,2015,2016,2019,2021,2022) Apple Inc. All rights reserved.
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
#include "cc_macros.h"
#include "ccrsa_internal.h"

int ccrsa_decrypt_oaep_ws(cc_ws_t ws,
                          ccrsa_full_ctx_t key,
                          const struct ccdigest_info* di,
                          size_t *r_size, uint8_t *r,
                          size_t c_size, const uint8_t *c,
                          size_t parameter_data_len,
                          const uint8_t *parameter_data)
{
    struct ccrng_state *rng = ccrng(NULL);
    if (!rng) {
        return CCERR_INTERNAL;
    }

    return ccrsa_decrypt_oaep_blinded_ws(ws, rng, key, di, r_size, r, c_size, c, parameter_data_len, parameter_data);
}

int ccrsa_decrypt_oaep(ccrsa_full_ctx_t key,
                       const struct ccdigest_info* di,
                       size_t *r_size, uint8_t *r,
                       size_t c_size, const uint8_t *c,
                       size_t parameter_data_len,
                       const uint8_t *parameter_data)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_DECRYPT_OAEP_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_decrypt_oaep_ws(ws, key, di, r_size, r, c_size, c, parameter_data_len, parameter_data);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
