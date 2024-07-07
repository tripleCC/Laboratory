/* Copyright (c) (2017,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"
#include "ccec_internal.h"
#include "cc_macros.h"
#include "ccrng_zero.h"
#include "cc_memory.h"
#include "cc_workspaces.h"

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_ecdh.h"

// Test ECDH
CC_NONNULL_ALL CC_WARN_RESULT
static int fipspost_post_ecdh_ws(cc_ws_t ws, ccec_const_cp_t cp, uint32_t fips_mode)
{
    int result=CCPOST_GENERIC_FAILURE;
    /*
     [P-256]

     COUNT = 0
     QCAVSx = 700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287
     QCAVSy = db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac
     dIUT = 7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534
     QIUTx = ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230
     QIUTy = 28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141
     ZIUT = 46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b
     */
    const uint8_t QCAVSx[]={
        0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca,
        0x65, 0x64, 0x0d, 0xb9, 0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4,
        0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87
    };
    const uint8_t QCAVSy[]={
        0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba,
        0x5c, 0x51, 0xdc, 0xc5, 0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0,
        0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac
    };
    const uint8_t dIUT[]={
        0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62, 0x14,
        0x63, 0x2e, 0xea, 0xe0, 0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e,
        0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34
    };
    const uint8_t QIUTx[]={
        0xea, 0xd2, 0x18, 0x59, 0x01, 0x19, 0xe8, 0x87, 0x6b, 0x29, 0x14, 0x6f,
        0xf8, 0x9c, 0xa6, 0x17, 0x70, 0xc4, 0xed, 0xbb, 0xf9, 0x7d, 0x38, 0xce,
        0x38, 0x5e, 0xd2, 0x81, 0xd8, 0xa6, 0xb2, 0x30
    };
    const uint8_t QIUTy[]={
        0x28, 0xaf, 0x61, 0x28, 0x1f, 0xd3, 0x5e, 0x2f, 0xa7, 0x00, 0x25, 0x23,
        0xac, 0xc8, 0x5a, 0x42, 0x9c, 0xb0, 0x6e, 0xe6, 0x64, 0x83, 0x25, 0x38,
        0x9f, 0x59, 0xed, 0xfc, 0xe1, 0x40, 0x51, 0x41
    };
    const uint8_t ZIUT[]={
        0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, 0x2e, 0x54, 0xa4, 0x34,
        0xfb, 0xdd, 0x2d, 0x25, 0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68,
        0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b
    };

    uint8_t Z[sizeof(ZIUT)] = { 0 };
    size_t Z_len=sizeof(ZIUT);

    CC_DECL_BP_WS(ws, bp);
    cc_size n = ccec_cp_n(cp);
    size_t nbits = ccec_cp_prime_bitlen(cp);

    ccec_full_ctx_t full_ec_key = CCEC_ALLOC_FULL_WS(ws, n);
    ccec_pub_ctx_t pub_ec_key = CCEC_ALLOC_PUB_WS(ws, n);

    result = ccec_make_priv(nbits, sizeof(QIUTx), QIUTx,
                                   sizeof(QIUTy), QIUTy,
                                   sizeof(dIUT), dIUT, full_ec_key);
    if (result) {
        result = CCPOST_GENERIC_FAILURE;
        failf("result: %d", result);
        goto errOut;
    }

    result = ccec_make_pub(nbits, sizeof(QCAVSx), QCAVSx,
                                  sizeof(QCAVSy), QCAVSy, pub_ec_key);
    if (result) {
        result = CCPOST_GENERIC_FAILURE;
        failf("result: %d", result);
        goto errOut;
    }

    result = ccecdh_compute_shared_secret_ws(ws, full_ec_key, pub_ec_key, &Z_len, Z, &ccrng_zero);
    if (result) {
        result = CCPOST_GENERIC_FAILURE;
        failf("result: %d", result);
        goto errOut;
    }

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode))
    {
        Z[0] ^= 1; // introduce an error
    }

    if (memcmp(Z, ZIUT, sizeof(Z))) {
        result = CCPOST_KAT_FAILURE;
        failf("memcmp");
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

int fipspost_post_ecdh(uint32_t fips_mode)
{
    ccec_const_cp_t cp = ccec_cp_256();
    CC_DECL_WORKSPACE_OR_FAIL(ws, FIPSPOST_POST_ECDH_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = fipspost_post_ecdh_ws(ws, cp, fips_mode);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
