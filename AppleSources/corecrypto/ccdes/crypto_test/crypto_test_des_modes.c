/* Copyright (c) (2012,2015,2017,2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "testmore.h"
#include "testbyteBuffer.h"
#include <corecrypto/ccdes.h>
#include <corecrypto/ccmode.h>
#include "cc_runtime_config.h"
#include <corecrypto/cc_priv.h>

// static int verbose = 1;

#if (CCDES_MODES == 0)
entryPoint(ccdes_modes_tests,"ccdes mode")
#else
#include "crypto_test_modes.h"

static const int kTestTestCount = 276 /* test_mode */ + 5 /* cksum */;

static int test_des_cksum(void)
{
    const uint8_t iv[]={0xAA,0xBB,0xCC,0xDD,0xAA,0xBB,0xCC,0xDD};
    const uint8_t key[]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    const uint8_t out_expected[8]={0xe3,0x48,0x84,0x91,0x88,0xc2,0xa2,0x85};
    uint8_t data[1]={0x00};
    uint8_t out[8];
    uint8_t out2[8];
    uint32_t r,r_expected;
    int rc=1;

    // Valid test
    rc &= is(ccdes_cbc_cksum(data, out, sizeof(data),
       key, sizeof(key), iv), (uint32_t)0x88c2a285, "valid inputs");
    rc &= ok_memcmp(out,out_expected,sizeof(out_expected),"correct output");

    // Negative tests
    r=ccdes_cbc_cksum(data, out, sizeof(data), key, sizeof(key)-1, iv);
    r_expected = cc_load32_be(&out[4]);
    rc &= is(r, (uint32_t)r_expected, "invalid inputs");

    ccdes_cbc_cksum(data, out, sizeof(data), key, sizeof(key)-1, iv);
    ccdes_cbc_cksum(data, out2, sizeof(data), key, sizeof(key)-1, iv);
    rc &=ok(memcmp(out,out_expected,sizeof(out_expected)) ||
            memcmp(out,out_expected,sizeof(out_expected)), "Static output in error case");

    return rc;
}


int ccdes_modes_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
	plan_tests(kTestTestCount);

    ok(test_des_cksum(), "DES cksum");

    ok(test_mode((ciphermode_t) ccdes_ecb_encrypt_mode(), (ciphermode_t) ccdes_ecb_decrypt_mode(), cc_cipherDES, cc_ModeECB) == 1, "Default DES-ECB");
    ok(test_mode((ciphermode_t) ccdes_cbc_encrypt_mode(), (ciphermode_t) ccdes_cbc_decrypt_mode(), cc_cipherDES, cc_ModeCBC) == 1, "Default DES-CBC");
    ok(test_mode((ciphermode_t) ccdes_cfb_encrypt_mode(), (ciphermode_t) ccdes_cfb_decrypt_mode(), cc_cipherDES, cc_ModeCFB) == 1, "Default DES-CFB");
    ok(test_mode((ciphermode_t) ccdes_cfb8_encrypt_mode(), (ciphermode_t) ccdes_cfb8_decrypt_mode(), cc_cipherDES, cc_ModeCFB8) == 1, "Default DES-CFB8");
    ok(test_mode((ciphermode_t) ccdes_ctr_crypt_mode(), (ciphermode_t) ccdes_ctr_crypt_mode(), cc_cipherDES, cc_ModeCTR) == 1, "Default DES-CTR");
    ok(test_mode((ciphermode_t) ccdes_ofb_crypt_mode(), (ciphermode_t) ccdes_ofb_crypt_mode(), cc_cipherDES, cc_ModeOFB) == 1, "Default DES-OFB");    

    ok(test_mode((ciphermode_t) ccdes3_ecb_encrypt_mode(), (ciphermode_t) ccdes3_ecb_decrypt_mode(), cc_cipher3DES, cc_ModeECB) == 1, "Default 3DES-ECB");
    ok(test_mode((ciphermode_t) ccdes3_cbc_encrypt_mode(), (ciphermode_t) ccdes3_cbc_decrypt_mode(), cc_cipher3DES, cc_ModeCBC) == 1, "Default 3DES-CBC");
    ok(test_mode((ciphermode_t) ccdes3_cfb_encrypt_mode(), (ciphermode_t) ccdes3_cfb_decrypt_mode(), cc_cipher3DES, cc_ModeCFB) == 1, "Default 3DES-CFB");
    ok(test_mode((ciphermode_t) ccdes3_cfb8_encrypt_mode(), (ciphermode_t) ccdes3_cfb8_decrypt_mode(), cc_cipher3DES, cc_ModeCFB8) == 1, "Default 3DES-CFB8");
    ok(test_mode((ciphermode_t) ccdes3_ctr_crypt_mode(), (ciphermode_t) ccdes3_ctr_crypt_mode(), cc_cipher3DES, cc_ModeCTR) == 1, "Default 3DES-CTR");
    ok(test_mode((ciphermode_t) ccdes3_ofb_crypt_mode(), (ciphermode_t) ccdes3_ofb_crypt_mode(), cc_cipher3DES, cc_ModeOFB) == 1, "Default 3DES-OFB");
    return 0;
}
#endif

