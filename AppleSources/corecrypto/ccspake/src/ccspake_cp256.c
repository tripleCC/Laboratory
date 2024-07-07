/* Copyright (c) (2018,2019,2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccspake.h>
#include "ccspake_internal.h"

/*
 * Points for common groups as defined by RFC 9383, section 4.
 */

static const cc_unit CCSPAKE_P256_M[] = {
    CCN256_C(88,6e,2f,97,ac,e4,6e,55,ba,9d,d7,24,25,79,f2,99,3b,64,e1,6e,f3,dc,ab,95,af,d4,97,33,3d,8f,a1,2f),
    CCN256_C(5f,f3,55,16,3e,43,ce,22,4e,0b,0e,65,ff,02,ac,8e,5c,7b,e0,94,19,c7,85,e0,ca,54,7d,55,a1,2e,2d,20)
};

static const cc_unit CCSPAKE_P256_N[] = {
    CCN256_C(d8,bb,d6,c6,39,c6,29,37,b0,4d,99,7f,38,c3,77,07,19,c6,29,d7,01,4d,49,a2,4b,4f,98,ba,a1,29,2b,49),
    CCN256_C(07,d6,0a,a6,bf,ad,e4,50,08,a6,36,33,7f,51,68,c6,4d,9b,d3,60,34,80,8c,d5,64,49,0b,1e,65,6e,db,e7)
};

static const struct ccspake_cp ccspake_cp256 = {
    .var = CCSPAKE_VARIANT_CCC_V1,
    .cp = ccec_cp_256,
    .m = CCSPAKE_P256_M,
    .n = CCSPAKE_P256_N
};

static const struct ccspake_cp ccspake_cp256_rfc = {
    .var = CCSPAKE_VARIANT_RFC,
    .cp = ccec_cp_256,
    .m = CCSPAKE_P256_M,
    .n = CCSPAKE_P256_N,
};

ccspake_const_cp_t ccspake_cp_256(void)
{
    return &ccspake_cp256;
}

ccspake_const_cp_t ccspake_cp_256_rfc(void)
{
    return &ccspake_cp256_rfc;
}
