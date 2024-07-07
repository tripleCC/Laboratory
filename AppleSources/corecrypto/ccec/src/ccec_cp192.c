/* Copyright (c) (2010-2012,2014-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "ccn_internal.h"

#define A(i) ccn64_64_parse(a,i)
#define Anil ccn64_64_null
#define Cnil ccn32_32_null

static void ccn_mod_192_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *a)
{
    cc_assert(cczp_n(zp) == CCN192_N);
    cc_unit s1[CCN192_N] = { ccn192_64(Anil,  A(3),  A(3)) };
    cc_unit s2[CCN192_N] = { ccn192_64(A(4),  A(4),  Anil) };
    cc_unit s3[CCN192_N] = { ccn192_64(A(5),  A(5),  A(5)) };

    cc_unit carry;
    carry =  ccn_add_ws(ws, CCN192_N, r, a, s1);
    carry += ccn_add_ws(ws, CCN192_N, r, r, s2);
    carry += ccn_add_ws(ws, CCN192_N, r, r, s3);

    // Prepare to reduce once more.
    cc_unit t[CCN192_N] = { ccn192_32(Cnil, Cnil, Cnil, carry, Cnil, carry) };

    // Reduce r mod p192.
    carry = ccn_add_ws(ws, CCN192_N, t, r, t);

    // One extra reduction (subtract p).
    cc_unit k = ccn_sub_ws(ws, CCN192_N, r, t, cczp_prime(zp));

    // Keep the extra reduction if carry=1 or k=0.
    ccn_mux(CCN192_N, carry | (k ^ 1), r, r, t);

    /* Sanity for debug */
    cc_assert(ccn_cmp(CCN192_N, r, cczp_prime(zp)) < 0);
}

CC_WORKSPACE_OVERRIDE(cczp_mod_ws, ccn_mod_192_ws)

static const struct ccec_funcs ccec_p192_funcs = {
    .cczp_add = cczp_add_default_ws,
    .cczp_sub = cczp_sub_default_ws,
    .cczp_mul = cczp_mul_default_ws,
    .cczp_sqr = cczp_sqr_default_ws,
    .cczp_mod = ccn_mod_192_ws,
    .cczp_inv = cczp_inv_field_ws,
    .cczp_sqrt = cczp_sqrt_default_ws,
    .cczp_to = cczp_to_default_ws,
    .cczp_from = cczp_from_default_ws,

    CCEC_FUNCS_DEFAULT_DEFINITIONS
};

static const ccec_cp_decl(192) ccec_cp192 =
{
    .hp = {
        .n = CCN192_N,
        .bitlen = 192,
        .funcs = (cczp_funcs_t)&ccec_p192_funcs
    },
    .p = {
        CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .p0inv = 1U,
    .pr2 = {
        CCN192_C(00,00,00,00,00,00,00,01,00,00,00,00,00,00,00,02,00,00,00,00,00,00,00,01)
    },
    .b = {
        CCN192_C(64,21,05,19,e5,9c,80,e7,0f,a7,e9,ab,72,24,30,49,fe,b8,de,ec,c1,46,b9,b1)
    },
    .gx = {
        CCN192_C(18,8d,a8,0e,b0,30,90,f6,7c,bf,20,eb,43,a1,88,00,f4,ff,0a,fd,82,ff,10,12)
    },
    .gy = {
        CCN192_C(07,19,2b,95,ff,c8,da,78,63,10,11,ed,6b,24,cd,d5,73,f9,77,a1,1e,79,48,11)
    },
    .hq = {
        .n = CCN192_N,
        .bitlen = 192,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .q = {
        CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,99,de,f8,36,14,6b,c9,b1,b4,d2,28,31)
    },
    .q0inv = (cc_unit)0x882672070ddbcf2f,
    .qr2 = {
        CCN192_C(28,be,56,77,ea,05,81,a2,46,96,ea,5b,bb,3a,6b,ee,ce,66,ba,cc,de,b3,59,61)
    }
};

ccec_const_cp_t ccec_cp_192(void)
{
    return (ccec_const_cp_t)&ccec_cp192;
}
