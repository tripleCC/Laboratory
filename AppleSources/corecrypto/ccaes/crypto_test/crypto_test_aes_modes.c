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

#include "testmore.h"
#include "testbyteBuffer.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include "ccmode_internal.h"
#include "cc_runtime_config.h"
#include "crypto_test_aes_modes.h"
#include "ccaes_vng_gcm.h"

#if (CCAES_MODES == 0)
entryPoint(ccaes_modes_tests,"ccaes mode")
#else
#include "crypto_test_modes.h"

static int kTestTestCount = 118679 /* base */
#if     CCAES_INTEL_ASM
        + 50993;
#else
        + 0;
#endif

#define END_VECTOR   {.keyStr=NULL}

// Our ARMv7/NEON implementation has a key schedule format that's
// incompatible with all others.
#if CC_ARM_ARCH_7 && defined(__ARM_NEON__)
#define WORKAROUND_42544245
#endif

ccsymmetric_test_vector aes_ctr_vectors[] = {
    #include "../test_vectors/aes_ctr_test_vectors.inc"
    END_VECTOR
};

int ccaes_modes_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{

    struct ccmode_ctr ccaes_generic_ctr_crypt_mode;
    ccmode_factory_ctr_crypt(&ccaes_generic_ctr_crypt_mode, &ccaes_ltc_ecb_encrypt_mode);

    static struct ccmode_xts ccaes_generic_ltc_xts_encrypt_mode;
    static struct ccmode_xts ccaes_generic_ltc_xts_decrypt_mode;
    ccmode_factory_xts_encrypt(&ccaes_generic_ltc_xts_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode,  &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_xts_decrypt(&ccaes_generic_ltc_xts_decrypt_mode, &ccaes_ltc_ecb_decrypt_mode,  &ccaes_ltc_ecb_encrypt_mode);

    static struct ccmode_gcm ccaes_generic_ltc_gcm_encrypt_mode;
    static struct ccmode_gcm ccaes_generic_ltc_gcm_decrypt_mode;
    ccmode_factory_gcm_encrypt(&ccaes_generic_ltc_gcm_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_gcm_decrypt(&ccaes_generic_ltc_gcm_decrypt_mode, &ccaes_ltc_ecb_encrypt_mode);

    static struct ccmode_ccm ccaes_generic_ltc_ccm_encrypt_mode;
    static struct ccmode_ccm ccaes_generic_ltc_ccm_decrypt_mode;
    ccmode_factory_ccm_encrypt(&ccaes_generic_ltc_ccm_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_ccm_decrypt(&ccaes_generic_ltc_ccm_decrypt_mode, &ccaes_ltc_ecb_encrypt_mode);

#if CCMODE_GCM_VNG_SPEEDUP && !defined(WORKAROUND_42544245)
    struct ccmode_gcm ccaes_vng_ltc_gcm_encrypt_mode = CCAES_VNG_GCM_ENCRYPT(&ccaes_ltc_ecb_encrypt_mode);
    struct ccmode_gcm ccaes_vng_ltc_gcm_decrypt_mode = CCAES_VNG_GCM_DECRYPT(&ccaes_ltc_ecb_encrypt_mode);
#endif

#if CCAES_INTEL_ASM
    if(CC_HAS_AESNI()) kTestTestCount+=69;
#endif
    plan_tests(kTestTestCount);

    aes_validation_test();

    test_ctr("Default AES-CTR",ccaes_ctr_crypt_mode(), ccaes_ctr_crypt_mode(), aes_ctr_vectors);
    test_ctr("Generic AES-CTR",&ccaes_generic_ctr_crypt_mode, &ccaes_generic_ctr_crypt_mode, aes_ctr_vectors);

    ok(test_hmac_mode((ciphermode_t)ccaes_siv_hmac_sha256_encrypt_mode(), (ciphermode_t)ccaes_siv_hmac_sha256_decrypt_mode(), cc_cipherAES, cc_ModeSIV_HMAC, cc_digestSHA256) == 1, "Generic AES-SIV-HMAC");
    ok(test_mode((ciphermode_t)ccaes_siv_encrypt_mode(), (ciphermode_t)ccaes_siv_decrypt_mode(), cc_cipherAES, cc_ModeSIV) == 1, "Generic AES-SIV");
    ok(test_mode((ciphermode_t) &ccaes_ltc_ecb_encrypt_mode, (ciphermode_t) &ccaes_ltc_ecb_decrypt_mode, cc_cipherAES, cc_ModeECB) == 1, "Standard LTC AES for ECB");
    ok(test_mode((ciphermode_t) &ccaes_gladman_cbc_encrypt_mode, (ciphermode_t) &ccaes_gladman_cbc_decrypt_mode, cc_cipherAES, cc_ModeCBC) == 1, "Standard LTC AES for CBC");
#if 0 // CCAES_ARM_ASM
    ok(test_mode((ciphermode_t) &ccaes_arm_ecb_encrypt_mode, (ciphermode_t) &ccaes_arm_ecb_decrypt_mode, cc_cipherAES, cc_ModeECB) == 1, "arm VNG AES for ECB");
    ok(test_mode((ciphermode_t) &ccaes_arm_cbc_encrypt_mode, (ciphermode_t) &ccaes_arm_cbc_decrypt_mode, cc_cipherAES, cc_ModeCBC) == 1, "arm VNG AES for CBC");
#endif
#if CCAES_INTEL_ASM
    ok(test_mode((ciphermode_t) &ccaes_intel_ecb_encrypt_opt_mode, (ciphermode_t) &ccaes_intel_ecb_decrypt_opt_mode, cc_cipherAES, cc_ModeECB) == 1, "Intel Non-AES-NI AES-ECB");
    ok(test_mode((ciphermode_t) &ccaes_intel_cbc_encrypt_opt_mode, (ciphermode_t) &ccaes_intel_cbc_decrypt_opt_mode, cc_cipherAES, cc_ModeCBC) == 1, "Intel Non-AES-NI AES-CBC");
    ok(test_mode((ciphermode_t) &ccaes_intel_xts_encrypt_opt_mode, (ciphermode_t) &ccaes_intel_xts_decrypt_opt_mode, cc_cipherAES, cc_ModeXTS) == 1, "Intel Non-AES-NI AES-XTS");
    ok(test_xts(&ccaes_intel_xts_encrypt_opt_mode, &ccaes_intel_xts_decrypt_opt_mode), "Intel Non-AES-NI AES-XTS Extended testing");
    if(CC_HAS_AESNI()) {
        ok(test_mode((ciphermode_t) &ccaes_intel_ecb_encrypt_aesni_mode, (ciphermode_t) &ccaes_intel_ecb_decrypt_aesni_mode, cc_cipherAES, cc_ModeECB) == 1, "Intel AES-NI AES-ECB");
        ok(test_mode((ciphermode_t) &ccaes_intel_cbc_encrypt_aesni_mode, (ciphermode_t) &ccaes_intel_cbc_decrypt_aesni_mode, cc_cipherAES, cc_ModeCBC) == 1, "Intel AES-NI AES-CBC");
        ok(test_mode((ciphermode_t) &ccaes_intel_xts_encrypt_aesni_mode, (ciphermode_t) &ccaes_intel_xts_decrypt_aesni_mode, cc_cipherAES, cc_ModeXTS) == 1, "Intel AES-NI AES-XTS");
        ok(test_xts(&ccaes_intel_xts_encrypt_aesni_mode, &ccaes_intel_xts_decrypt_aesni_mode), "Intel AES-NI AES-XTS Extended testing");
    }
#endif
    ok(test_mode((ciphermode_t) ccaes_ecb_encrypt_mode(), (ciphermode_t) ccaes_ecb_decrypt_mode(), cc_cipherAES, cc_ModeECB) == 1, "Default AES-ECB");
    ok(test_mode((ciphermode_t) ccaes_cbc_encrypt_mode(), (ciphermode_t) ccaes_cbc_decrypt_mode(), cc_cipherAES, cc_ModeCBC) == 1, "Default AES-CBC");
    ok(test_mode((ciphermode_t) ccaes_cfb_encrypt_mode(), (ciphermode_t) ccaes_cfb_decrypt_mode(), cc_cipherAES, cc_ModeCFB) == 1, "Default AES-CFB");
    ok(test_mode((ciphermode_t) ccaes_cfb8_encrypt_mode(), (ciphermode_t) ccaes_cfb8_decrypt_mode(), cc_cipherAES, cc_ModeCFB8) == 1, "Default AES-CFB8");
    ok(test_mode((ciphermode_t) ccaes_ofb_crypt_mode(), (ciphermode_t) ccaes_ofb_crypt_mode(), cc_cipherAES, cc_ModeOFB) == 1, "Default AES-OFB");
    ok(test_mode((ciphermode_t) (const struct ccmode_xts *) &ccaes_generic_ltc_xts_encrypt_mode,
                 (ciphermode_t) (const struct ccmode_xts *) &ccaes_generic_ltc_xts_decrypt_mode, cc_cipherAES, cc_ModeXTS) == 1, "Generic AES-XTS");
    ok(test_mode((ciphermode_t) ccaes_xts_encrypt_mode(), (ciphermode_t) ccaes_xts_decrypt_mode(), cc_cipherAES, cc_ModeXTS) == 1, "Default AES-XTS");
    ok(test_mode((ciphermode_t) ccaes_gcm_encrypt_mode(), (ciphermode_t) ccaes_gcm_decrypt_mode(), cc_cipherAES, cc_ModeGCM) == 1, "Default AES-GCM");
    ok(test_mode((ciphermode_t) (const struct ccmode_gcm *) &ccaes_generic_ltc_gcm_encrypt_mode,
                  (ciphermode_t) (const struct ccmode_gcm *) &ccaes_generic_ltc_gcm_decrypt_mode, cc_cipherAES, cc_ModeGCM) == 1, "Generic AES-GCM");
    ok(test_mode((ciphermode_t) ccaes_ccm_encrypt_mode(), (ciphermode_t) ccaes_ccm_decrypt_mode(), cc_cipherAES, cc_ModeCCM) == 1, "Default AES-CCM");
    ok(test_mode((ciphermode_t) (const struct ccmode_ccm *) &ccaes_generic_ltc_ccm_encrypt_mode,
                 (ciphermode_t) (const struct ccmode_ccm *) &ccaes_generic_ltc_ccm_decrypt_mode, cc_cipherAES, cc_ModeCCM) == 1, "Generic AES-CCM");
    ok(test_gcm(ccaes_gcm_encrypt_mode(), ccaes_gcm_decrypt_mode()), "Default AES-GCM Extended testing");
    ok(test_gcm(&ccaes_generic_ltc_gcm_encrypt_mode,&ccaes_generic_ltc_gcm_decrypt_mode), "Generic AES-GCM Extended testing");
    ok(test_ccm(ccaes_ccm_encrypt_mode(), ccaes_ccm_decrypt_mode()), "Default AES-CCM Extended testing");
    ok(test_ccm(&ccaes_generic_ltc_ccm_encrypt_mode, &ccaes_generic_ltc_ccm_decrypt_mode), "Generic AES-CCM Extended testing");
    ok(test_xts(ccaes_xts_encrypt_mode(), ccaes_xts_decrypt_mode()), "Default AES-XTS Extended testing");
    ok(test_xts(&ccaes_generic_ltc_xts_encrypt_mode, &ccaes_generic_ltc_xts_decrypt_mode), "Generic AES-XTS Extended testing");
#if CCMODE_GCM_VNG_SPEEDUP && !defined(WORKAROUND_42544245)
    ok(test_mode((ciphermode_t) (const struct ccmode_gcm *) &ccaes_vng_ltc_gcm_encrypt_mode,
                  (ciphermode_t) (const struct ccmode_gcm *) &ccaes_vng_ltc_gcm_decrypt_mode, cc_cipherAES, cc_ModeGCM) == 1, "VNG/LTC AES-GCM");
    ok(test_gcm(&ccaes_vng_ltc_gcm_encrypt_mode, &ccaes_vng_ltc_gcm_decrypt_mode), "VNG/LTC AES-GCM Extended testing");
#endif
    return 0;
}
#endif
