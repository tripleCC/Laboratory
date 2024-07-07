/* Copyright (c) (2020-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdarg.h>
#include "cc_config.h"

#include "fipspost_indicator.h"
#include "fipspost_post_indicator.h"
#include "fipspost_priv.h"

#include "ccdrbg.h"
#include "ccaes.h"
#include "ccsha1.h"

int fipspost_post_indicator(CC_UNUSED uint32_t fips_mode)
{
    int success = 1;
    
    /// FIPS
    success &= fips_allowed0(fipspost_post_integrity);
    
    /// AES
    for (size_t key_byte_length = 16; key_byte_length <= 32; key_byte_length += 8) {
        success &= fips_allowed_mode(ccaes_ecb_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_ecb_decrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_cbc_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_cbc_decrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_ccm_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_ccm_decrypt_mode, key_byte_length);
#if !(CC_KERNEL)
        success &= fips_allowed_mode(ccaes_cfb8_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_cfb8_decrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_cfb_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_cfb_decrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_ofb_crypt_mode, key_byte_length);
#endif // !(CC_KERNEL)
        success &= fips_allowed_mode(ccaes_ctr_crypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_gcm_encrypt_mode, key_byte_length); /// GMAC
        success &= fips_allowed_mode(ccaes_gcm_decrypt_mode, key_byte_length); /// GMAC
        success &= fips_allowed_mode(ccwrap_auth_encrypt_withiv, key_byte_length);
        success &= fips_allowed_mode(ccwrap_auth_decrypt_withiv, key_byte_length);
        
#if (CC_USE_L4)
        success &= fips_allowed_mode(rfc3394_wrap, key_byte_length);
        success &= fips_allowed_mode(rfc3394_unwrap, key_byte_length);
#endif
        if (key_byte_length != 24) {
#if (CC_USE_L4)
            success &= fips_allowed_mode(ccaes_skg_cbc_encrypt_mode, key_byte_length);
            success &= fips_allowed_mode(ccaes_skg_cbc_decrypt_mode, key_byte_length);
            success &= fips_allowed_mode(ccaes_skg_ecb_encrypt_mode, key_byte_length);
            success &= fips_allowed_mode(ccaes_skg_ecb_decrypt_mode, key_byte_length);
#else
#if !(CC_KERNEL)
            success &= fips_allowed_mode(ccpad_cts1_encrypt, key_byte_length);
            success &= fips_allowed_mode(ccpad_cts1_decrypt, key_byte_length);
            success &= fips_allowed_mode(ccpad_cts2_encrypt, key_byte_length);
            success &= fips_allowed_mode(ccpad_cts2_decrypt, key_byte_length);
#endif // !(CC_KERNEL)
            success &= fips_allowed_mode(ccpad_cts3_encrypt, key_byte_length);
            success &= fips_allowed_mode(ccpad_cts3_decrypt, key_byte_length);
#endif // (CC_USE_L4)
            success &= fips_allowed_mode(ccaes_xts_encrypt_mode, key_byte_length);
            success &= fips_allowed_mode(ccaes_xts_decrypt_mode, key_byte_length);
        }
    }
    
    ///
    /// DRBGs -- CTR_DRBG, HMAC_DRBG, TRNG
    ///
    
    /// DRBG_CTR (SKS)
    
#if (!CC_USE_L4)
    success &= fips_allowed_drbg(ccdrbg_init,     ccdrbg_factory_nistctr, CCAES_KEY_SIZE_128);
    success &= fips_allowed_drbg(ccdrbg_reseed,   ccdrbg_factory_nistctr, CCAES_KEY_SIZE_128);
    success &= fips_allowed_drbg(ccdrbg_generate, ccdrbg_factory_nistctr, CCAES_KEY_SIZE_128);
    success &= fips_allowed_drbg(ccdrbg_done,     ccdrbg_factory_nistctr, CCAES_KEY_SIZE_128);
    
    success &= fips_allowed_drbg(ccdrbg_init,     ccdrbg_factory_nistctr, CCAES_KEY_SIZE_256);
    success &= fips_allowed_drbg(ccdrbg_reseed,   ccdrbg_factory_nistctr, CCAES_KEY_SIZE_256);
    success &= fips_allowed_drbg(ccdrbg_generate, ccdrbg_factory_nistctr, CCAES_KEY_SIZE_256);
    success &= fips_allowed_drbg(ccdrbg_done,     ccdrbg_factory_nistctr, CCAES_KEY_SIZE_256);
#endif // (!CC_USE_L4)
    
    /// DRBG_HMAC
#if (!CC_USE_L4)
#if (!CC_KERNEL) //
    success &= fips_allowed_drbg(ccdrbg_init,     ccdrbg_factory_nisthmac, ccsha1_di);
    success &= fips_allowed_drbg(ccdrbg_reseed,   ccdrbg_factory_nisthmac, ccsha1_di);
    success &= fips_allowed_drbg(ccdrbg_generate, ccdrbg_factory_nisthmac, ccsha1_di);
    success &= fips_allowed_drbg(ccdrbg_done,     ccdrbg_factory_nisthmac, ccsha1_di);
    
    success &= !fips_allowed_drbg(ccdrbg_init,    ccdrbg_factory_nisthmac, ccsha224_di); /* SHA-224 for DRBG  No Longer Allowed */
    success &= !fips_allowed_drbg(ccdrbg_reseed,  ccdrbg_factory_nisthmac, ccsha224_di); /* Negate for Compliance */
    success &= !fips_allowed_drbg(ccdrbg_generate,ccdrbg_factory_nisthmac, ccsha224_di);
    success &= !fips_allowed_drbg(ccdrbg_done,    ccdrbg_factory_nisthmac, ccsha224_di);
    
    success &= fips_allowed_drbg(ccdrbg_init,     ccdrbg_factory_nisthmac, ccsha256_di);
    success &= fips_allowed_drbg(ccdrbg_reseed,   ccdrbg_factory_nisthmac, ccsha256_di);
    success &= fips_allowed_drbg(ccdrbg_generate, ccdrbg_factory_nisthmac, ccsha256_di);
    success &= fips_allowed_drbg(ccdrbg_done,     ccdrbg_factory_nisthmac, ccsha256_di);
#endif  // (!CC_KERNEL)
    success &= !fips_allowed_drbg(ccdrbg_init,    ccdrbg_factory_nisthmac, ccsha384_di);
    success &= !fips_allowed_drbg(ccdrbg_reseed,  ccdrbg_factory_nisthmac, ccsha384_di); /* SHA-384 for DRBG No Longer Allowed */
    success &= !fips_allowed_drbg(ccdrbg_generate,ccdrbg_factory_nisthmac, ccsha384_di); /* Negate for Compliance */
    success &= !fips_allowed_drbg(ccdrbg_done,    ccdrbg_factory_nisthmac, ccsha384_di);
    
    success &= fips_allowed_drbg(ccdrbg_init,     ccdrbg_factory_nisthmac, ccsha512_di);
    success &= fips_allowed_drbg(ccdrbg_reseed,   ccdrbg_factory_nisthmac, ccsha512_di);
    success &= fips_allowed_drbg(ccdrbg_generate, ccdrbg_factory_nisthmac, ccsha512_di);
    success &= fips_allowed_drbg(ccdrbg_done,     ccdrbg_factory_nisthmac, ccsha512_di);
#endif // !(CC_USE_L4)
    
    
    /// DRBG_TRNG (HW)
#if (CC_USE_L4)
    success &= fips_allowed_drbg(ccdrbg_init,     ccdrbg_factory_trng, CCAES_KEY_SIZE_256);
    success &= fips_allowed_drbg(ccdrbg_reseed,   ccdrbg_factory_trng, CCAES_KEY_SIZE_256);
    success &= fips_allowed_drbg(ccdrbg_generate, ccdrbg_factory_trng, CCAES_KEY_SIZE_256);
    success &= fips_allowed_drbg(ccdrbg_done,     ccdrbg_factory_trng, CCAES_KEY_SIZE_256);

    /// TRNG -- SHA2-256 (Conditioning Function)

    success &= fips_allowed_drbg(trng, ccdrbg_factory_trng, ccsha256_trng_di);
#endif
    
    
    
    
    /// ECC
    success &= fips_allowed1(ccec_generate_key_fips, ccec_cp_224);
    success &= fips_allowed1(ccec_generate_key_fips, ccec_cp_256);
    success &= fips_allowed1(ccec_generate_key_fips, ccec_cp_384);
    success &= fips_allowed1(ccec_generate_key_fips, ccec_cp_521);
    success &= fips_allowed1(ccec_make_priv, ccec_cp_224);
    success &= fips_allowed1(ccec_make_priv, ccec_cp_256);
    success &= fips_allowed1(ccec_make_priv, ccec_cp_384);
    success &= fips_allowed1(ccec_make_priv, ccec_cp_521);
    success &= fips_allowed1(ccec_make_pub, ccec_cp_224);
    success &= fips_allowed1(ccec_make_pub, ccec_cp_256);
    success &= fips_allowed1(ccec_make_pub, ccec_cp_384);
    success &= fips_allowed1(ccec_make_pub, ccec_cp_521);
    
    /// ECDSA
    success &= fips_allowed1(ccec_sign_msg, ccec_cp_224);
    success &= fips_allowed1(ccec_sign_msg, ccec_cp_256);
    success &= fips_allowed1(ccec_sign_msg, ccec_cp_384);
    success &= fips_allowed1(ccec_sign_msg, ccec_cp_521);
    success &= fips_allowed1(ccec_verify_msg, ccec_cp_192); // Verify P-192 Only
    success &= fips_allowed1(ccec_verify_msg, ccec_cp_224);
    success &= fips_allowed1(ccec_verify_msg, ccec_cp_256);
    success &= fips_allowed1(ccec_verify_msg, ccec_cp_384);
    success &= fips_allowed1(ccec_verify_msg, ccec_cp_521);
    
    success &= fips_allowed1(ccec_validate_pub, ccec_cp_192);
    success &= fips_allowed1(ccec_validate_pub, ccec_cp_224);
    success &= fips_allowed1(ccec_validate_pub, ccec_cp_256);
    success &= fips_allowed1(ccec_validate_pub, ccec_cp_384);
    success &= fips_allowed1(ccec_validate_pub, ccec_cp_521);
    /// HMAC
    success &= fips_allowed1(cchmac, ccsha1_di);
    success &= fips_allowed1(cchmac, ccsha224_di);
    success &= fips_allowed1(cchmac, ccsha256_di);
    success &= fips_allowed1(cchmac, ccsha384_di);
    success &= fips_allowed1(cchmac, ccsha512_di);
    success &= fips_allowed1(cchmac, ccsha512_256_di);
    success &= fips_allowed1(cchmac, ccsha3_224_di);
    success &= fips_allowed1(cchmac, ccsha3_256_di);
    success &= fips_allowed1(cchmac, ccsha3_384_di);
    success &= fips_allowed1(cchmac, ccsha3_512_di);
    
    /// DH
#if !(CC_KERNEL || CC_USE_L4)
    success &= fips_allowed0(ccdh_gp_rfc3526group14);
    success &= fips_allowed0(ccdh_gp_rfc3526group15);
    success &= fips_allowed0(ccdh_gp_rfc3526group16);
    success &= fips_allowed0(ccdh_gp_rfc3526group17);
    success &= fips_allowed0(ccdh_gp_rfc3526group18);
    
    success &= fips_allowed1(ccdh_generate_key, 2048);
    success &= fips_allowed1(ccdh_generate_key, 3072);
    success &= fips_allowed1(ccdh_generate_key, 4096);
    success &= fips_allowed1(ccdh_generate_key, 6144);
    success &= fips_allowed1(ccdh_generate_key, 8192);
    
    success &= fips_allowed1(ccdh_import_pub, 2048);
    success &= fips_allowed1(ccdh_import_pub, 3072);
    success &= fips_allowed1(ccdh_import_pub, 4096);
    success &= fips_allowed1(ccdh_import_pub, 6144);
    success &= fips_allowed1(ccdh_import_pub, 8192);
    
    success &= fips_allowed1(ccdh_import_priv, 2048);
    success &= fips_allowed1(ccdh_import_priv, 3072);
    success &= fips_allowed1(ccdh_import_priv, 4096);
    success &= fips_allowed1(ccdh_import_priv, 6144);
    success &= fips_allowed1(ccdh_import_priv, 8192);
    
    success &= fips_allowed1(ccdh_compute_shared_secret, 2048);
    success &= fips_allowed1(ccdh_compute_shared_secret, 3072);
    success &= fips_allowed1(ccdh_compute_shared_secret, 4096);
    success &= fips_allowed1(ccdh_compute_shared_secret, 6144);
    success &= fips_allowed1(ccdh_compute_shared_secret, 8192);
#endif
    /// ECDH
#if !(CC_KERNEL)
    success &= fips_allowed1(ccecdh_compute_shared_secret, ccec_cp_224);
    success &= fips_allowed1(ccecdh_compute_shared_secret, ccec_cp_256);
    success &= fips_allowed1(ccecdh_compute_shared_secret, ccec_cp_384);
    success &= fips_allowed1(ccecdh_compute_shared_secret, ccec_cp_521);
    success &= fips_allowed1(ccecdh_generate_key, ccec_cp_224);
    success &= fips_allowed1(ccecdh_generate_key, ccec_cp_256);
    success &= fips_allowed1(ccecdh_generate_key, ccec_cp_384);
    success &= fips_allowed1(ccecdh_generate_key, ccec_cp_521);
#endif // !(CC_KERNEL)
    
    /// KDF
#if !(CC_USE_L4 || CC_KERNEL)
    success &= fips_allowed1(ccnistkdf_ctr_cmac, 16);
    success &= fips_allowed1(ccnistkdf_ctr_cmac, 24);
    success &= fips_allowed1(ccnistkdf_ctr_cmac, 32);
    success &= fips_allowed1(ccnistkdf_ctr_cmac_fixed, 16);
    success &= fips_allowed1(ccnistkdf_ctr_cmac_fixed, 24);
    success &= fips_allowed1(ccnistkdf_ctr_cmac_fixed, 32);

#endif // !(CC_USE_L4 || CC_KERNEL)
#if (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha1_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha224_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha256_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha384_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha512_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha512_256_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha3_224_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha3_256_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha3_384_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha3_512_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha1_di); // KDF_HMAC
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha224_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha256_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha384_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha512_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha512_256_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha3_224_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha3_256_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha3_384_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha3_512_di);
#endif // (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
    {
        size_t pswd_len = 6;    /// Only Approved if password >= 6
        success &= fips_allowed2(ccpbkdf2_hmac, ccsha1_di, pswd_len);
        success &= fips_allowed2(ccpbkdf2_hmac, ccsha224_di, pswd_len);
        success &= fips_allowed2(ccpbkdf2_hmac, ccsha256_di, pswd_len);
        success &= fips_allowed2(ccpbkdf2_hmac, ccsha384_di, pswd_len);
        success &= fips_allowed2(ccpbkdf2_hmac, ccsha512_di, pswd_len);
        success &= fips_allowed2(ccpbkdf2_hmac, ccsha512_256_di, pswd_len);
        /// PBKDF2-SHA3:  Not Yet Approved -- Need ACVP Support / Certs first
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha3_224_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha3_256_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha3_384_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha3_512_di, pswd_len);
    }
    success &= fips_allowed1(cchkdf, ccsha1_di);
    success &= fips_allowed1(cchkdf, ccsha224_di);
    success &= fips_allowed1(cchkdf, ccsha256_di);
    success &= fips_allowed1(cchkdf, ccsha384_di);
    success &= fips_allowed1(cchkdf, ccsha512_di);
    success &= fips_allowed1(cchkdf, ccsha512_256_di);
    success &= fips_allowed1(cchkdf, ccsha3_224_di);
    success &= fips_allowed1(cchkdf, ccsha3_256_di);
    success &= fips_allowed1(cchkdf, ccsha3_384_di);
    success &= fips_allowed1(cchkdf, ccsha3_512_di);
    
    /// Digest
#if !(CC_USE_L4)
    success &= !fips_allowed0(ccmd5_di);
#endif // !(CC_USE_L4)
    success &= fips_allowed0(ccsha1_di);
    success &= fips_allowed0(ccsha224_di);
    success &= fips_allowed0(ccsha256_di);
    success &= fips_allowed0(ccsha384_di);
    success &= fips_allowed0(ccsha512_di);
    success &= fips_allowed0(ccsha512_256_di);
    success &= fips_allowed0(ccsha3_224_di);
    success &= fips_allowed0(ccsha3_256_di);
    success &= fips_allowed0(ccsha3_384_di);
    success &= fips_allowed0(ccsha3_512_di);
    success &= fips_allowed0(ccshake128_xi);
    success &= fips_allowed0(ccshake256_xi);
    /// NDRNG -- Not Yet Approved - considered an NDRNG
    success &= !fips_allowed0(ccrng_uniform);
    
    /// RSA
    success &= fips_allowed1(ccrsa_verify_pss_msg, 1024);
    success &= fips_allowed1(ccrsa_verify_pss_msg, 2048);
    success &= fips_allowed1(ccrsa_verify_pss_msg, 3072);
    success &= fips_allowed1(ccrsa_verify_pss_msg, 4096);
    
    success &= fips_allowed1(ccrsa_verify_pkcs1v15_msg, 1024);
    success &= fips_allowed1(ccrsa_verify_pkcs1v15_msg, 2048);
    success &= fips_allowed1(ccrsa_verify_pkcs1v15_msg, 3072);
    success &= fips_allowed1(ccrsa_verify_pkcs1v15_msg, 4096);
    
    success &= fips_allowed1(ccrsa_generate_fips186_key, 2048);
    success &= fips_allowed1(ccrsa_generate_fips186_key, 3072);
    success &= fips_allowed1(ccrsa_generate_fips186_key, 4096);
    
#if !(CC_BRIDGE && CC_KERNEL)
#if !(CC_USE_L4) /// ccrsa_sign_pss is not in L4.
    success &= fips_allowed1(ccrsa_sign_pss_msg, 2048);
    success &= fips_allowed1(ccrsa_sign_pss_msg, 3072);
    success &= fips_allowed1(ccrsa_sign_pss_msg, 4096);
#endif // !(CC_USE_L4)
    success &= fips_allowed1(ccrsa_sign_pkcs1v15_msg, 2048);
    success &= fips_allowed1(ccrsa_sign_pkcs1v15_msg, 3072);
    success &= fips_allowed1(ccrsa_sign_pkcs1v15_msg, 4096);
#endif // !(CC_BRIDGE && CC_KERNEL)

    /// 'ccrsa_encrypt_oaep' Not yet FIPS Approved Needs FIPSPOST -- Until then Negate this test
#if (!(CC_USE_L4 || CC_KERNEL) || (CC_KERNEL && __x86_64__))
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 2048);
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 3072);
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 4096);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 2048);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 3072);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 4096);
#endif // (!(CC_USE_L4 || CC_KERNEL) || (CC_KERNEL && __x86_64__))
    
    /// TDES
#if (CC_KERNEL) // Decrypt remains for legacy ONLY support - 128/192 Only
    success &= fips_allowed_mode(ccdes3_ecb_decrypt_mode, 16);
    success &= fips_allowed_mode(ccdes3_ecb_decrypt_mode, 24);
#endif // (CC_KERNEL)
    
    ///
    /// Not appproved algorithms.
    ///
    /// ansikdf.
    success &= !fips_allowed1(ccansikdf_x963, ccsha1_di);
    success &= !fips_allowed1(ccansikdf_x963, ccsha224_di);
    success &= !fips_allowed1(ccansikdf_x963, ccsha256_di);
    success &= !fips_allowed1(ccansikdf_x963, ccsha384_di);
    success &= !fips_allowed1(ccansikdf_x963, ccsha512_di);
    
    /// Blowfish.
    success &= !fips_allowed_mode(ccblowfish_ecb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_ecb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cbc_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cbc_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cfb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cfb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cfb8_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cfb8_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_ctr_crypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_ofb_crypt_mode, 16);
    
    /// Cast.
    success &= !fips_allowed_mode(cccast_ecb_decrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_ecb_encrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cbc_decrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cbc_encrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cfb_decrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cfb_encrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cfb8_decrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cfb8_encrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_ctr_crypt_mode, 16);
    success &= !fips_allowed_mode(cccast_ofb_crypt_mode, 16);
    
    /// DES - Removed (sunset 2023) ---  TDES
    success &= !fips_allowed_mode(ccdes3_ecb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cbc_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cbc_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cfb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cfb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cfb8_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cfb8_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_ctr_crypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_ofb_crypt_mode, 16);
    /// DH / ECDH
    success &= !fips_allowed1(ccdh_compute_shared_secret, ccsrp_gp_rfc5054_2048);
#if !(CC_KERNEL || CC_USE_L4)
    success &= !fips_allowed0(ccdh_gp_apple768);
    success &= !fips_allowed0(ccdh_gp_rfc2409group02);
    success &= !fips_allowed0(ccdh_gp_rfc2409group05);
    success &= !fips_allowed0(ccdh_gp_rfc5114_MODP_1024_160);
    success &= !fips_allowed0(ccdh_gp_rfc5114_MODP_2048_224);
    success &= !fips_allowed0(ccdh_gp_rfc5114_MODP_2048_256);
#endif
    /// ECC  -- Not Approved if not using the full *_msg API
    success &= !fips_allowed1(ccec_sign, ccec_cp_224);
    success &= !fips_allowed1(ccec_sign, ccec_cp_256);
    success &= !fips_allowed1(ccec_sign, ccec_cp_384);
    success &= !fips_allowed1(ccec_sign, ccec_cp_521);
    success &= !fips_allowed1(ccec_verify, ccec_cp_192);
    success &= !fips_allowed1(ccec_verify, ccec_cp_224);
    success &= !fips_allowed1(ccec_verify, ccec_cp_256);
    success &= !fips_allowed1(ccec_verify, ccec_cp_384);
    success &= !fips_allowed1(ccec_verify, ccec_cp_521);
    
    success &= !fips_allowed1(ccec_verify_strict, ccec_cp_256);
    success &= !fips_allowed1(ccec_verify_strict, ccec_cp_384);
    success &= !fips_allowed1(ccec_verify_strict, ccec_cp_521);
    
#if !(CC_KERNEL || CC_USE_L4)
    success &= !fips_allowed1(ccec_rfc6637_kdf, ccec_cp_256);
    success &= !fips_allowed1(ccec_rfc6637_kdf, ccec_cp_384);
    success &= !fips_allowed1(ccec_rfc6637_kdf, ccec_cp_521);
    success &= !fips_allowed1(ccec_rfc6637_wrap_key, ccec_cp_256);
    success &= !fips_allowed1(ccec_rfc6637_wrap_key, ccec_cp_384);
    success &= !fips_allowed1(ccec_rfc6637_wrap_key, ccec_cp_521);
    success &= !fips_allowed1(ccec_rfc6637_unwrap_key, ccec_cp_256);
    success &= !fips_allowed1(ccec_rfc6637_unwrap_key, ccec_cp_384);
    success &= !fips_allowed1(ccec_rfc6637_unwrap_key, ccec_cp_521);
#endif
    
    /// ECIES
    success &= !fips_allowed0(ccecies_encrypt_gcm);
    success &= !fips_allowed0(ccecies_decrypt_gcm);
    /// ED25519
    success &= !fips_allowed0(cced25519_make_key_pair);
    success &= !fips_allowed0(cced25519_sign);
    success &= !fips_allowed0(cced25519_verify);
    /// H2C
#if !(CC_USE_L4 || CC_KERNEL)
    success &= !fips_allowed1(cch2c, ccec_cp_256);
    success &= !fips_allowed1(cch2c, ccec_cp_384);
    success &= !fips_allowed1(cch2c, ccec_cp_521);
#endif
    /// HPKE
#if !(CC_USE_L4 || CC_KERNEL)
    success &= !fips_allowed0(cchpke);
    success &= !fips_allowed0(cchpke_kem_x25519_generate_key_pair);
    success &= !fips_allowed0(cchpke_kem_x25519_public_key);
    success &= !fips_allowed0(cchpke_kem_generate_key_pair);
    success &= !fips_allowed0(cchpke_initiator_encrypt);
    success &= !fips_allowed0(cchpke_responder_decrypt);
    success &= !fips_allowed0(cchpke_export_secret);
#endif
    /// KDF
    success &= !fips_allowed0(cchkdf);
    
    {
        size_t pswd_len = 5;    /* password length MUST BE >= 6 */
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha1_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha224_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha256_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha384_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha512_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha512_256_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha3_224_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha3_256_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha3_384_di, pswd_len);
        success &= !fips_allowed2(ccpbkdf2_hmac, ccsha3_512_di, pswd_len);
    }
    /// MD2/4
    success &= !fips_allowed0(ccmd2_di);
    success &= !fips_allowed0(ccmd4_di);
    /// OMAC
    success &= !fips_allowed0(ccomac_update);
    /// RC2/4
    success &= !fips_allowed_mode(ccrc2_ecb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_ecb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cbc_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cbc_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cfb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cfb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cfb8_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cfb8_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_ctr_crypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_ofb_crypt_mode, 16);
    success &= !fips_allowed0(ccrc4);
    /// RIPEMD
    success &= !fips_allowed0(ccrmd160_di);
    /// RSA
    success &= !fips_allowed1(ccrsa_verify_pss_digest, 1024);
    success &= !fips_allowed1(ccrsa_verify_pss_digest, 2048);
    success &= !fips_allowed1(ccrsa_verify_pss_digest, 3072);
    success &= !fips_allowed1(ccrsa_verify_pss_digest, 4096);
    
    success &= !fips_allowed1(ccrsa_verify_pkcs1v15_digest, 1024);
    success &= !fips_allowed1(ccrsa_verify_pkcs1v15_digest, 2048);
    success &= !fips_allowed1(ccrsa_verify_pkcs1v15_digest, 3072);
    success &= !fips_allowed1(ccrsa_verify_pkcs1v15_digest, 4096);
    
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 1024);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 1024);
#if !(!(CC_USE_L4 || CC_KERNEL) || (CC_KERNEL && __x86_64__))
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 2048);
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 3072);
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 4096);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 2048);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 3072);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 4096);
#endif // !(!(CC_USE_L4 || CC_KERNEL) || (CC_KERNEL && __x86_64__))
    
#if !(CC_BRIDGE && CC_KERNEL)
#if !(CC_USE_L4) /// ccrsa_sign_pss is not in L4.
    success &= !fips_allowed1(ccrsa_sign_pss, 2048);
    success &= !fips_allowed1(ccrsa_sign_pss, 3072);
    success &= !fips_allowed1(ccrsa_sign_pss, 4096);
#endif // !(CC_USE_L4)
    success &= !fips_allowed1(ccrsa_sign_pkcs1v15, 2048);
    success &= !fips_allowed1(ccrsa_sign_pkcs1v15, 3072);
    success &= !fips_allowed1(ccrsa_sign_pkcs1v15, 4096);
#endif // !(CC_BRIDGE && CC_KERNEL)
    
    /// SAE
#if !(CC_USE_L4 || CC_KERNEL)
    success &= !fips_allowed0(ccsae_init);
    success &= !fips_allowed0(ccsae_init_p256_sha256);
    success &= !fips_allowed0(ccsae_ctr_hmac_fixed);
    success &= !fips_allowed0(ccsae_get_keys);
#endif
    /// SCRYPT
#if !(CC_USE_L4)
    success &= !fips_allowed0(ccscrypt);
#endif
    /// SIGMA
#if !(CC_USE_L4 || CC_KERNEL)
    success &= !fips_allowed0(ccsigma_init);
    success &= !fips_allowed0(ccsigma_sign);
    success &= !fips_allowed0(ccsigma_verify);
    success &= !fips_allowed0(ccsigma_seal);
#endif
    /// SPAKE
#if !(CC_KERNEL)
    success &= !fips_allowed0(ccspake_kex_generate);
    success &= !fips_allowed0(ccspake_mac_hkdf_cmac_aes128_sha256);
    success &= !fips_allowed0(ccspake_mac_hkdf_hmac_compute);
    success &= !fips_allowed0(ccspake_cp_256);
    success &= !fips_allowed0(ccspake_cp_384);
    success &= !fips_allowed0(ccspake_cp_521);
    success &= !fips_allowed0(ccspake_mac_hkdf_hmac_sha256);
    success &= !fips_allowed0(ccspake_mac_hkdf_hmac_sha512);
    success &= !fips_allowed0(ccspake_kex_process);
    success &= !fips_allowed0(ccspake_kex_generate);
    success &= !fips_allowed0(ccspake_mac_hkdf_derive);
#endif
    /// These tests must fail.
    success &= !fips_allowed0(NULL);
    success &= !fips_allowed1(NULL, 42);
    success &= !fips_allowed_mode(ccaes_ecb_encrypt_mode, 12);
    success &= !fips_allowed_mode(ccdes3_ecb_encrypt_mode, 42);
    success &= !fips_allowed_mode(ccdes_ecb_encrypt_mode, 12);
    
    return !success;
}
