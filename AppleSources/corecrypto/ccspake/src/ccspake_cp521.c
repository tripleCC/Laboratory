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

static const cc_unit CCSPAKE_P521_M[] = {
    CCN528_C(00,3f,06,f3,81,31,b2,ba,26,00,79,1e,82,48,8e,8d,20,ab,88,9a,f7,53,a4,18,06,c5,db,18,d3,7d,85,60,8c,fa,e0,6b,82,e4,a7,2c,d7,44,c7,19,19,35,62,a6,53,ea,1f,11,9e,ef,93,56,90,7e,dc,9b,56,97,99,62,d7,aa),
    CCN528_C(01,bd,d1,79,a3,d5,47,61,08,92,e9,b9,6d,ea,1e,ab,10,bd,d7,ac,5a,e0,cf,75,aa,0f,85,3b,fd,18,5c,f7,82,f8,94,30,19,98,b1,1d,18,98,ed,e2,70,1d,ca,37,a2,bb,50,b4,f5,19,c3,d8,9a,7d,05,4b,51,fb,84,91,21,92)
};

static const cc_unit CCSPAKE_P521_N[] = {
    CCN528_C(00,c7,92,4b,9e,c0,17,f3,09,45,62,89,43,36,a5,3c,50,16,7b,a8,c5,96,38,76,88,05,42,bc,66,9e,49,4b,25,32,d7,6c,5b,53,df,b3,49,fd,f6,91,54,b9,e0,04,8c,58,a4,2e,8e,d0,4c,ef,05,2a,3b,c3,49,d9,55,75,cd,25),
    CCN528_C(01,c6,2b,ee,65,0c,92,87,a6,51,bb,75,c7,f3,9a,20,06,87,33,47,b7,69,84,0d,26,1d,17,76,0b,10,7e,29,f0,91,d5,56,a8,2a,2e,4c,de,0c,40,b8,4b,95,b8,78,db,24,89,ef,76,02,06,42,4b,3f,e7,96,8a,a8,e0,b1,f3,34)
};

static const struct ccspake_cp ccspake_cp521 = {
    .var = CCSPAKE_VARIANT_CCC_V1,
    .cp = ccec_cp_521,
    .m = CCSPAKE_P521_M,
    .n = CCSPAKE_P521_N
};

static const struct ccspake_cp ccspake_cp521_rfc = {
    .var = CCSPAKE_VARIANT_RFC,
    .cp = ccec_cp_521,
    .m = CCSPAKE_P521_M,
    .n = CCSPAKE_P521_N,
};

ccspake_const_cp_t ccspake_cp_521(void)
{
    return &ccspake_cp521;
}

ccspake_const_cp_t ccspake_cp_521_rfc(void)
{
    return &ccspake_cp521_rfc;
}
