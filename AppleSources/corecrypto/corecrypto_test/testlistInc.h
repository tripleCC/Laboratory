/* Copyright (c) (2012-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>

#define CC 1
#define CCDER 1
#define CCAES_UNWIND 1
#define CCAES_MODES 1
#define CCCHACHATEST 1
#define CCEC25519 1
#define CCEC448 1
#define CCVRF 1
#define CCDES_MODES 1
#define CCCAST_MODES 1
#define CCRC2_MODES 1
#define CCBLOWFISH_MODES 1
#define CCRC4_CIPHER 1
#define CCLR 1
#define CCDH 1
#define CCRSA 1
#define CCEC 1
#define CCDIGEST 1
#define CCHKDF 1
#define CCHMAC 1
#define CCNISTKDF 1
#define CCANSIKDF 1
#define CCPBKDF2 1
#ifdef _MSC_VER
#define CCSCRYPT 0
#define CCHPKE 0
#else
#define CCSCRYPT 1
#define CCHPKE 1
#endif
#if CC_LINUX || defined(_MSC_VER)
#define CC_DYLIB 0
#else
#define CC_DYLIB 1
#endif
#define CCSRP 1
#define CCWRAP 1
#define CCDRBG 1
#define CCENTROPY 1
#define CCRNG 1
#define CCCMAC 1
#define CCPAD 1
#define CCECIES 1
#define CCZP 1
#define CCPOLYZP_PO2CYC 1
#define CCBFV 1
#define CCHE 1
#define CCRABIN_MILLER 1
#define CCH2C 1
#define CCSIGMA 1

ONE_TEST(cc)
ONE_TEST(ccn)
ONE_TEST(ccder)
ONE_TEST(ccentropy)
ONE_TEST(ccrng)
ONE_TEST(ccdrbg)
ONE_TEST(ccpad)
#ifndef _MSC_VER
ONE_TEST(ccansikdf)
ONE_TEST(cchkdf)
ONE_TEST(ccnistkdf)
ONE_TEST(ccnistkdf_cmac)
ONE_TEST(ccscrypt)
ONE_TEST(ccspake)
ONE_TEST(cchpke)
ONE_TEST(cc_dylib)
ONE_TEST(ccsae)
ONE_TEST(ccvrf)
ONE_TEST(ccckg)
ONE_TEST(ccaes_unwind)
#endif
ONE_TEST(ccdigest)
ONE_TEST(cchmac)
ONE_TEST(cccmac)
ONE_TEST(ccpbkdf2)
ONE_TEST(ccaes_modes)
ONE_TEST(ccdes_modes)
ONE_TEST(cccast_modes)
ONE_TEST(ccrc2_modes)
ONE_TEST(ccblowfish_modes)
ONE_TEST(ccrc4_cipher)
ONE_TEST(cclr)
ONE_TEST(cczp)
ONE_TEST(ccpolyzp_po2cyc)
ONE_TEST(ccbfv)
ONE_TEST(cche)
ONE_TEST(ccrsa)
ONE_TEST(ccrsabssa)
ONE_TEST(ccchacha)
ONE_TEST(ccec25519)
ONE_TEST(ccec448)
ONE_TEST(ccec)
ONE_TEST(ccecies)
ONE_TEST(ccec_import_export)
ONE_TEST(ccec_curve_validation)
ONE_TEST(ccdh)
ONE_TEST(ccsrp)
ONE_TEST(ccwrap)
ONE_TEST(ccprime_rabin_miller)
#if CC_DARWIN || CC_USE_L4
    ONE_TEST(ccfips_trace)
#endif
#if !CC_LINUX && !defined(_MSC_VER)
ONE_TEST(cckprng)
#endif
ONE_TEST(cch2c)
ONE_TEST(ccsigma)
ONE_TEST(ccz)
ONE_TEST(cckeccak)
ONE_TEST(ccshake)
ONE_TEST(cckem)
ONE_TEST(cckyber)
