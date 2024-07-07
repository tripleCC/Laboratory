/* Copyright (c) (2010,2011,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include "ccec_internal.h"

void ccec_double_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_projective_point_t r, ccec_const_projective_point_t s)
{
    CC_DECL_BP_WS(ws, bp);
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n = ccec_cp_n(cp);

    cc_unit
        *t1=ccec_point_x(r, cp),
        *t2=ccec_point_y(r, cp),
        *t3=ccec_point_z(r, cp);

    cc_unit *t4=CC_ALLOC_WS(ws, n);
    cc_unit *t5=CC_ALLOC_WS(ws, n);

    // 4S + 4M + 14add/sub
    cczp_sqr_ws(ws, zp, t4, ccec_const_point_z(s, cp));      // t4 = z^2
    cczp_sub_ws(ws, zp, t5, ccec_const_point_x(s, cp), t4);  // t5 = x - t4
    cczp_add_ws(ws, zp, t4, ccec_const_point_x(s, cp), t4);  // t4 = x + t4
    cczp_mul_ws(ws, zp, t5, t4, t5);  // t5 = t4 * t5
    cczp_add_ws(ws, zp, t4, t5, t5);  // t4 = 3*t5
    cczp_add_ws(ws, zp, t4, t4, t5);
    cczp_mul_ws(ws, zp, t3, ccec_const_point_z(s, cp), ccec_const_point_y(s, cp));  // t3 = z * y
    cczp_add_ws(ws, zp, t3, t3, t3);  // t3 = 2 * t3
    cczp_sqr_ws(ws, zp, t2, ccec_const_point_y(s, cp));      // t2 = y * t2
    cczp_mul_ws(ws, zp, t5, ccec_const_point_x(s, cp), t2);  // t5 = x * t2
    cczp_add_ws(ws, zp, t5, t5, t5);  // t5 = 4 * t5 
    cczp_add_ws(ws, zp, t5, t5, t5);  // t5 = ((t5 + t5) + (t5 + t5))
    cczp_sqr_ws(ws, zp, t1, t4);      // t1 = t4^2
    cczp_sub_ws(ws, zp, t1, t1, t5);  // t1 = t1 - 2*t5
    cczp_sub_ws(ws, zp, t1, t1, t5);  // could optimize to t6 = t5 + t5 (shift), t1 = t1 - t6 since t3 is not used anymore we could copy it to the output and use t3 as scratch.
    cczp_sqr_ws(ws, zp, t2, t2);      // t2 = t2^2
    cczp_add_ws(ws, zp, t2, t2, t2);  // t2 = 8 * t2
    cczp_add_ws(ws, zp, t2, t2, t2);  // t2 = 4 * t2 = ((t2 + t2) + (t2 + t2))
    cczp_add_ws(ws, zp, t2, t2, t2);  // t2 = (4 * t2) + (4 * t2)
    cczp_sub_ws(ws, zp, t5, t5, t1);  // t5 = t5 - t1
    cczp_mul_ws(ws, zp, t5, t4, t5);  // t5 = t4 * t5
    cczp_sub_ws(ws, zp, t2, t5, t2);  // t2 = t5 - t2
    // Result point is {t1,t2,t3}

    CC_FREE_BP_WS(ws, bp);
}
