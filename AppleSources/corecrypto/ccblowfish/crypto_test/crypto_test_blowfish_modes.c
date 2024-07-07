/* Copyright (c) (2012,2015,2019-2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccblowfish.h>
#include <corecrypto/ccmode.h>
#include "cc_runtime_config.h"


// static int verbose = 1;

#if (CCBLOWFISH_MODES == 0)
entryPoint(ccblowfish_modes_tests,"ccblowfish mode")
#else
#include "crypto_test_modes.h"

static const int kTestTestCount = 159;

int ccblowfish_modes_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
	plan_tests(kTestTestCount);
    ok(test_mode((ciphermode_t) ccblowfish_ecb_encrypt_mode(), (ciphermode_t) ccblowfish_ecb_decrypt_mode(), cc_cipherBlowfish, cc_ModeECB) == 1, "Default blowfish-ECB");
    ok(test_mode((ciphermode_t) ccblowfish_cbc_encrypt_mode(), (ciphermode_t) ccblowfish_cbc_decrypt_mode(), cc_cipherBlowfish, cc_ModeCBC) == 1, "Default blowfish-CBC");
    ok(test_mode((ciphermode_t) ccblowfish_cfb_encrypt_mode(), (ciphermode_t) ccblowfish_cfb_decrypt_mode(), cc_cipherBlowfish, cc_ModeCFB) == 1, "Default blowfish-CFB");
    ok(test_mode((ciphermode_t) ccblowfish_cfb8_encrypt_mode(), (ciphermode_t) ccblowfish_cfb8_decrypt_mode(), cc_cipherBlowfish, cc_ModeCFB8) == 1, "Default blowfish-CFB8");
    ok(test_mode((ciphermode_t) ccblowfish_ctr_crypt_mode(), (ciphermode_t) ccblowfish_ctr_crypt_mode(), cc_cipherBlowfish, cc_ModeCTR) == 1, "Default blowfish-CTR");
    ok(test_mode((ciphermode_t) ccblowfish_ofb_crypt_mode(), (ciphermode_t) ccblowfish_ofb_crypt_mode(), cc_cipherBlowfish, cc_ModeOFB) == 1, "Default blowfish-OFB");    
    return 0;
}
#endif

