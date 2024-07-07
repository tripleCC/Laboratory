/* Copyright (c) (2014-2019,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccn_internal.h"
#include "ccrng_internal.h"
#include "ccec25519_internal.h"

// -121665/121666 (mod p)
const cc_unit kLowerCaseD[] = {
    CCN256_C(52,03,6c,ee,2b,6f,fe,73,8c,c7,40,79,77,79,e8,98,00,70,0a,4d,41,41,d8,ab,75,eb,4d,ca,13,59,78,a3)
};

void cced25519_to_ed25519_point_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   cced25519_point R,
                                   ccec_const_projective_point_t P)
{
    const cc_unit *x = ccec_const_point_x(P, cp);
    const cc_unit *y = ccec_const_point_y(P, cp);
    const cc_unit *z = ccec_const_point_z(P, cp);

    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    // To get (XZ,YZ,XYZ,Z) from (XZ,YZ,Z), compute (XZ*Z,YZ*Z,XZ*YZ,Z^2).

    CC_DECL_BP_WS(ws, bp);
    cczp_mul_ws(ws, zp, &R[2 * n], x, y);
    cczp_mul_ws(ws, zp, &R[0 * n], x, z);
    cczp_mul_ws(ws, zp, &R[1 * n], y, z);
    cczp_sqr_ws(ws, zp, &R[3 * n], z);
    CC_FREE_BP_WS(ws, bp);
}

void cced25519_from_ed25519_point_ws(CC_UNUSED cc_ws_t ws,
                                     ccec_const_cp_t cp,
                                     ccec_projective_point_t R,
                                     cced25519_const_point P)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    // To get (XZ,YZ,Z) from (XZ,YZ,XYZ,Z), simply ignore XYZ.

    ccn_set(n, ccec_point_x(R, cp), &P[0 * n]);
    ccn_set(n, ccec_point_y(R, cp), &P[1 * n]);
    ccn_set(n, ccec_point_z(R, cp), &P[3 * n]);
}

void cced25519_hash_to_scalar_ws(cc_ws_t ws,
                                 ccec_const_cp_t cp,
                                 const struct ccdigest_info *di,
                                 cc_unit *s,
                                 size_t data1_nbytes,
                                 const uint8_t *cc_sized_by(data1_nbytes) data1,
                                 size_t data2_nbytes,
                                 const uint8_t *cc_sized_by(data1_nbytes) data2,
                                 size_t msg_nbytes,
                                 const uint8_t *cc_sized_by(msg_nbytes) msg)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, 2 * n);

    uint8_t h[64];

    // SHA-512(data1 || data2 || M)
    ccdigest_di_decl(di, dc);
    ccdigest_init(di, dc);
    ccdigest_update(di, dc, data1_nbytes, data1);
    ccdigest_update(di, dc, data2_nbytes, data2);
    ccdigest_update(di, dc, msg_nbytes, msg);
    ccdigest_final(di, dc, h);
    ccdigest_di_clear(di, dc);

    // Compute r (mod q).
    ccn_read_le_bytes(2 * n, h, t);
    cczp_modn_ws(ws, zq, s, 2 * n, t);
    cc_clear(sizeof(h), h);

    CC_FREE_BP_WS(ws, bp);
}
