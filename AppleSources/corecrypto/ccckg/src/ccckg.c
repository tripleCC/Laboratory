/* Copyright (c) (2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccckg.h>
#include "ccckg_internal.h"

#include "ccansikdf_internal.h"
#include "ccec_internal.h"

size_t ccckg_sizeof_ctx(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    // Need space to store a scalar and a nonce.
    // The owner needs to also store the commitment.
    return sizeof(struct ccckg_ctx) + ccec_ccn_size(cp) + ccn_sizeof(di->output_size * 8) * 2;
}

size_t ccckg_sizeof_commitment(CC_UNUSED ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    return di->output_size;
}

size_t ccckg_sizeof_share(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    // A public EC key plus a nonce.
    return 1 + 2 * ccec_cp_prime_size(cp) + di->output_size;
}

size_t ccckg_sizeof_opening(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    // A scalar plus a nonce.
    return ccec_cp_order_size(cp) + di->output_size;
}

void ccckg_init(ccckg_ctx_t ctx, ccec_const_cp_t cp, const struct ccdigest_info *di, struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    cc_clear(ccckg_sizeof_ctx(cp, di), ctx);

    ccckg_ctx_cp(ctx) = cp;
    ccckg_ctx_di(ctx) = di;
    ccckg_ctx_rng(ctx) = rng;
    ccckg_ctx_state(ctx) = CCCKG_STATE_INIT;
}

int ccckg_derive_sk(ccckg_ctx_t ctx, const cc_unit *x, const uint8_t *r1, const uint8_t *r2, size_t key_len, uint8_t *key)
{
    const struct ccdigest_info *di = ccckg_ctx_di(ctx);
    ccec_const_cp_t cp = ccckg_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);

    uint8_t xbuf[CCCKG_CURVE_MAX_NBYTES];
    ccn_write_uint_padded(n, x, ccec_cp_prime_size(cp), xbuf);
    
    cc_iovec_t shared_data[2] = {
        {
            .base = r1,
            .nbytes = di->output_size,
        },
        {
            .base = r2,
            .nbytes = di->output_size,
        },
    };
    
    return ccansikdf_x963_iovec(di, ccec_cp_prime_size(cp), xbuf, CC_ARRAY_LEN(shared_data), shared_data, key_len, key);
}
