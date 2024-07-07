/* Copyright (c) (2018-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/cchmac.h>
#include "ccsae.h"
#include "ccsae_priv.h"
#include "ccec_internal.h"
#include "ccn_internal.h"
#include "cch2c_internal.h"
#include "ccsae_internal.h"

const uint8_t CCSAE_STATE_INIT = 0b00000001;
const uint8_t CCSAE_STATE_COMMIT_INIT = 0b00000011;
const uint8_t CCSAE_STATE_COMMIT_UPDATE = 0b00000111;
const uint8_t CCSAE_STATE_COMMIT_GENERATED = 0b00001111;
const uint8_t CCSAE_STATE_COMMIT_VERIFIED = 0b00010111;
const uint8_t CCSAE_STATE_COMMIT_BOTH = 0b00011111;
const uint8_t CCSAE_STATE_CONFIRMATION_GENERATED = 0b00111111;
const uint8_t CCSAE_STATE_CONFIRMATION_VERIFIED = 0b01011111;
const uint8_t CCSAE_STATE_CONFIRMATION_BOTH = 0b01111111;

const char *SAE_KCK_PMK_LABEL = "SAE KCK and PMK";
const char *SAE_HUNT_PECK_LABEL = "SAE Hunting and Pecking";

size_t ccsae_sizeof_ctx(ccec_const_cp_t cp)
{
    return sizeof(struct ccsae_ctx) + ccec_ccn_size(cp) * CCSAE_NUM_CTX_CCN;
}

size_t ccsae_sizeof_commitment(ccsae_const_ctx_t ctx)
{
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    return 3 * ccec_cp_prime_size(cp);
}

size_t ccsae_sizeof_confirmation(ccsae_const_ctx_t ctx)
{
    const struct ccdigest_info *di = ccsae_ctx_di(ctx);
    return di->output_size;
}

size_t ccsae_sizeof_pt(const struct cch2c_info *info)
{
    ccec_const_cp_t cp = info->curve_params();
    return ccec_export_pub_size_cp(cp);
}

void ccsae_lexographic_order_key(const uint8_t *A, size_t A_nbytes, const uint8_t *B, size_t B_nbytes, uint8_t *output)
{
    CC_ENSURE_DIT_ENABLED

    size_t min_nbytes = A_nbytes < B_nbytes ? A_nbytes : B_nbytes;
    int res = memcmp(A, B, min_nbytes);

    if (res < 0) {
        cc_memcpy(output, B, B_nbytes);
        cc_memcpy(output + B_nbytes, A, A_nbytes);
    } else if (res > 0) {
        cc_memcpy(output, A, A_nbytes);
        cc_memcpy(output + A_nbytes, B, B_nbytes);
    } else {
        if (min_nbytes == A_nbytes) {
            cc_memcpy(output, B, B_nbytes);
            cc_memcpy(output + B_nbytes, A, A_nbytes);
        } else {
            cc_memcpy(output, A, A_nbytes);
            cc_memcpy(output + A_nbytes, B, B_nbytes);
        }
    }
}

static void
sae_construct_fixed_data(ccec_const_cp_t cp, const char *label, const cc_unit *context, size_t size, uint8_t *fixedData)
{
    cc_size n = ccec_cp_n(cp);
    size_t label_nbytes = strlen(label);
    size_t tn = ccec_cp_prime_size(cp);

    cc_memcpy(fixedData + 2, label, label_nbytes);
    ccn_write_uint_padded(n, context, tn, fixedData + 2 + label_nbytes);
    cc_memset(fixedData + 2 + label_nbytes + tn, size & 0xff, 1);
    cc_memset(fixedData + 2 + label_nbytes + tn + 1, (int)(size >> 8), 1);
}

/*! @function ccsae_ctr_hmac_fixed
 @abstract Computes the modified NIST CTR-HMAC KDF.

 @param di                Digest paramaters
 @param secret            Input buffer used as the HMAC key with size di->output_size
 @param fixedData_nbytes  Length of the fixed data portion of the HMAC
 @param fixedData         Input buffer containing the fixed data
 @param output_nbytes     Size of the output buffer
 @param output            Output buffer

 */
static void ccsae_ctr_hmac_fixed(const struct ccdigest_info *di,
                                 const uint8_t *secret,
                                 uint8_t *fixedData,
                                 size_t fixedData_nbytes,
                                 uint8_t *output,
                                 size_t output_nbytes)
{
    size_t h = di->output_size;
    size_t iterations = cc_ceiling(output_nbytes, h);

    uint8_t result_buf[MAX_DIGEST_OUTPUT_SIZE];

    cchmac_di_decl(di, hc);
    for (size_t i = 1; i <= iterations; i += 1, output += h, output_nbytes -= h) {
        cchmac_init(di, hc, h, secret);
        fixedData[0] = (uint8_t)i;
        fixedData[1] = (uint8_t)(i >> 8);
        cchmac_update(di, hc, fixedData_nbytes, fixedData);
        cchmac_final(di, hc, result_buf);
        cc_memcpy(output, result_buf, CC_MIN_EVAL(output_nbytes, h));
    }

    cchmac_di_clear(di, hc);
    cc_clear(h, result_buf);
}

int ccsae_gen_keys_ws(cc_ws_t ws, ccsae_ctx_t ctx, const uint8_t *keyseed, const cc_unit *context)
{
    const struct ccdigest_info *di = ccsae_ctx_di(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    cc_size tn = ccec_cp_prime_size(cp);
    uint8_t output[MAX_DIGEST_OUTPUT_SIZE + CCSAE_PMK_SIZE]; // Room for KCK & PMK

    const size_t fixedData_nbytes = 2 + SAE_KCK_PMK_LABEL_NBYTES + tn + 2;

    CC_DECL_BP_WS(ws, bp);
    uint8_t *fixedData = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(4 + SAE_KCK_PMK_LABEL_NBYTES) + n);

    sae_construct_fixed_data(cp, ccsae_ctx_kck_pmk_label(ctx), context, (ccsae_sizeof_kck_internal(ctx) + CCSAE_PMK_SIZE) * 8, fixedData);
    ccsae_ctr_hmac_fixed(di, keyseed, fixedData, fixedData_nbytes, output, CCSAE_PMK_SIZE + ccsae_sizeof_kck_internal(ctx));

    cc_memcpy(ccsae_ctx_KCK(ctx), output, ccsae_sizeof_kck_internal(ctx));
    cc_memcpy(ccsae_ctx_PMK(ctx), output + ccsae_sizeof_kck_internal(ctx), CCSAE_PMK_SIZE);

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

void ccsae_gen_password_value_ws(cc_ws_t ws, ccsae_ctx_t ctx, const uint8_t *pwd_seed, cc_unit *output)
{    
    const struct ccdigest_info *di = ccsae_ctx_di(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);
    size_t tnbits = ccec_cp_prime_bitlen(cp);

    const size_t fixedData_nbytes = 2 + SAE_HUNT_PECK_LABEL_NBYTES + tn + 2;

    CC_DECL_BP_WS(ws, bp);
    uint8_t *result_buf = (uint8_t *)CC_ALLOC_WS(ws, n);
    uint8_t *fixedData = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof_size(4 + SAE_HUNT_PECK_LABEL_NBYTES) + n);

    sae_construct_fixed_data(cp, ccsae_ctx_hunt_peck_label(ctx), ccec_cp_p(cp), ccec_cp_prime_bitlen(cp), fixedData);
    ccsae_ctr_hmac_fixed(di, pwd_seed, fixedData, fixedData_nbytes, result_buf, tn);

    (void)ccn_read_uint(n, output, tn, result_buf);
    if (tnbits % 8 != 0) {
        ccn_shift_right(n, output, output, 8 - (tnbits % 8));
    }

    CC_FREE_BP_WS(ws, bp);
}

bool ccsae_y2_from_x_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *y2, const cc_unit *x_in)
{
    cc_size n = ccec_cp_n(cp);
    cczp_const_decl(zp, ccec_cp_zp(cp));
    CC_DECL_BP_WS(ws, bp);

    cc_unit *t = CC_ALLOC_WS(ws, n);
    cc_unit *x = CC_ALLOC_WS(ws, n);
    cc_unit *pm1 = CC_ALLOC_WS(ws, n);
    cc_unit *u = pm1;

    ccn_set(n, x, x_in);
    ccn_sub1(n, pm1, cczp_prime(zp), 1);

    // result1 = 0 if x < p, otherwise 1 or 2
    uint8_t result1 = (uint8_t)(ccn_cmp(ccec_cp_n(cp), x, cczp_prime(ccec_cp_zp(cp))) + 1);

    // Normalize result: result1 = 0 if x < p, 1 otherwise
    result1 = (result1 & 1) | (result1 >> 1);

    // Perform the swap when result1 = 1
    // This is important because:
    //   a. We will hit cc_asserts in the cczp_* functions if x > p
    //   b. cczp_power_fast_ws, called from cczp_is_quadratic_residue_ws, branches if x >= p
    ccn_mux(n, result1, x, pm1, x);

    // We want result to be 1 now
    result1 = result1 ^ 1;

    cczp_to_ws(ws, zp, x, x);
    cczp_sqr_ws(ws, zp, t, x);                 // t = sx^2
    cczp_mul_ws(ws, zp, t, t, x);              // t = sx^3
    cczp_add_ws(ws, zp, u, x, x);              // u = 2sx
    cczp_add_ws(ws, zp, u, u, x);              // u = 3sx
    cczp_sub_ws(ws, zp, t, t, u);              // t = sx^3 - 3sx
    cczp_add_ws(ws, zp, y2, t, ccec_cp_b(cp)); // t = sx^3 - 3sx + b

    int r0 = cczp_is_quadratic_residue_ws(ws, zp, y2); // 1 on success, not 1 otherwise
    uint8_t result2 = (uint8_t)(r0 - 1);               // result2 = 0 on success, not 0 otherwise
    CC_HEAVISIDE_STEP(result2, result2);               // result2 = 0 on success, otherwise 1
    result2 = result2 ^ 1;                             // result2 = 1 on success, otherwise 0
    cc_assert(((r0 == 1) && (result2 == 1)) || ((r0 != 1) && (result2 == 0)));

    CC_FREE_BP_WS(ws, bp);
    return (bool)(result1 & result2);
}
