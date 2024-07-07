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

#include "cc_internal.h"
#include "fipspost_indicator.h"

#define STR_EQ(_str_, _expected_) (                    \
(_str_) != NULL && strcmp(_str_, #_expected_) == 0 \
)

int fips_allowed_mode_(const char *mode, size_t key_byte_length)
{
    if (STR_EQ(mode, ccaes_ctr_crypt_mode) 	 ||
        STR_EQ(mode, ccaes_ecb_encrypt_mode) ||
        STR_EQ(mode, ccaes_ecb_decrypt_mode) ||
        STR_EQ(mode, ccaes_cbc_encrypt_mode) ||
        STR_EQ(mode, ccaes_cbc_decrypt_mode) ||
        STR_EQ(mode, ccaes_ccm_encrypt_mode) ||
        STR_EQ(mode, ccaes_ccm_decrypt_mode) ||
        STR_EQ(mode, ccaes_cfb_encrypt_mode) ||
        STR_EQ(mode, ccaes_cfb_decrypt_mode) ||
        STR_EQ(mode, ccaes_cfb8_encrypt_mode) ||
        STR_EQ(mode, ccaes_cfb8_decrypt_mode) ||
        STR_EQ(mode, ccaes_ofb_crypt_mode) ||
        STR_EQ(mode, ccwrap_auth_encrypt_withiv) ||
        STR_EQ(mode, ccwrap_auth_decrypt_withiv) ||
#if (CC_USE_L4)
        STR_EQ(mode, rfc3394_wrap)           ||
        STR_EQ(mode, rfc3394_unwrap)         ||
#endif
        STR_EQ(mode, ccaes_gcm_encrypt_mode) ||
        STR_EQ(mode, ccaes_gcm_decrypt_mode)) {
        return  key_byte_length == 16 ||
                key_byte_length == 24 ||
                key_byte_length == 32;
    }
    
    if (STR_EQ(mode, ccaes_xts_encrypt_mode) ||
        STR_EQ(mode, ccaes_xts_decrypt_mode)) {
        return  key_byte_length == 16 ||
                key_byte_length == 32;
    }
    
#if (CC_KERNEL)
    if (STR_EQ(mode, ccdes3_ecb_decrypt_mode)) { /* Allow for Legacy Support */
        return  key_byte_length == 16 ||		 /* 128/192 bits ONLY        */
                key_byte_length == 24;
    }
#endif // (CC_KERNEL)

    
#if (CC_USE_L4)
    if (STR_EQ(mode, ccaes_skg_cbc_encrypt_mode) ||
        STR_EQ(mode, ccaes_skg_cbc_decrypt_mode) ||
        STR_EQ(mode, ccaes_skg_ecb_encrypt_mode) ||
        STR_EQ(mode, ccaes_skg_ecb_decrypt_mode)) {
        return  key_byte_length == 16 ||
                key_byte_length == 32;
    }
#else
    if (
#if !(CC_KERNEL)
        STR_EQ(mode, ccpad_cts1_encrypt) ||
        STR_EQ(mode, ccpad_cts1_decrypt) ||
        STR_EQ(mode, ccpad_cts2_encrypt) ||
        STR_EQ(mode, ccpad_cts2_decrypt) ||
#endif // !(CC_KERNEL)
        STR_EQ(mode, ccpad_cts3_encrypt) ||
        STR_EQ(mode, ccpad_cts3_decrypt)) {
        return  key_byte_length == 16 ||
                key_byte_length == 24 ||
                key_byte_length == 32;
        }
#endif // (CC_USE_L4)
    
    return 0;
}

int fips_allowed(const char *function, const char *arg1)
{
    int success = 0;
    
    if (arg1 == NULL) {
        /// FIPS Module Integrity
        success |= STR_EQ(function, fipspost_post_integrity);
        
        /// Digest
        success |= STR_EQ(function, ccsha1_di);
        success |= STR_EQ(function, ccsha224_di);
        success |= STR_EQ(function, ccsha256_di);
        success |= STR_EQ(function, ccsha384_di);
        success |= STR_EQ(function, ccsha512_di);
        success |= STR_EQ(function, ccsha512_256_di);
        success |= STR_EQ(function, ccsha3_224_di);
        success |= STR_EQ(function, ccsha3_256_di);
        success |= STR_EQ(function, ccsha3_384_di);
        success |= STR_EQ(function, ccsha3_512_di);
        success |= STR_EQ(function, ccshake128_xi);
        success |= STR_EQ(function, ccshake256_xi);
        /// DH / ECDH
#if !(CC_KERNEL || CC_USE_L4 || defined(__arm__)) || (CC_ARM_ARCH_7)
        success |= STR_EQ(function, ccdh_gp_rfc3526group14);
        success |= STR_EQ(function, ccdh_gp_rfc3526group15);
        success |= STR_EQ(function, ccdh_gp_rfc3526group16);
        success |= STR_EQ(function, ccdh_gp_rfc3526group17);
        success |= STR_EQ(function, ccdh_gp_rfc3526group18);
#endif
    }
    
    if (arg1 != NULL) {
        /// ECC
        if (STR_EQ(function, ccec_generate_key_fips) ||
            STR_EQ(function, ccec_sign_msg)          ||
            STR_EQ(function, ccec_make_priv)         ||
            STR_EQ(function, ccec_make_pub)) {
            success =   STR_EQ(arg1, ccec_cp_224) ||
                        STR_EQ(arg1, ccec_cp_256) ||
                        STR_EQ(arg1, ccec_cp_384) ||
                        STR_EQ(arg1, ccec_cp_521);
        }
        if (STR_EQ(function, ccec_verify_msg)  ||
            STR_EQ(function, ccec_validate_pub)) {
            success =   STR_EQ(arg1, ccec_cp_192) ||   /* P-192: Verify only */
                        STR_EQ(arg1, ccec_cp_224) ||
                        STR_EQ(arg1, ccec_cp_256) ||
                        STR_EQ(arg1, ccec_cp_384) ||
                        STR_EQ(arg1, ccec_cp_521);
        }
        
        /// HMAC
        if (STR_EQ(function, cchmac)) {
            success =   STR_EQ(arg1, ccsha1_di)     ||
                        STR_EQ(arg1, ccsha224_di)   ||
                        STR_EQ(arg1, ccsha256_di)   ||
                        STR_EQ(arg1, ccsha384_di)   ||
                        STR_EQ(arg1, ccsha512_di)   ||
                        STR_EQ(arg1, ccsha512_256_di) ||
                        STR_EQ(arg1, ccsha3_224_di) ||
                        STR_EQ(arg1, ccsha3_256_di) ||
                        STR_EQ(arg1, ccsha3_384_di) ||
                        STR_EQ(arg1, ccsha3_512_di);
        }
        
        /// DH / ECDH
#if !(CC_KERNEL)
        if (STR_EQ(function, ccecdh_compute_shared_secret) ||
            STR_EQ(function, ccecdh_generate_key)) {
            success =   STR_EQ(arg1, ccec_cp_224) ||
                        STR_EQ(arg1, ccec_cp_256) ||
                        STR_EQ(arg1, ccec_cp_384) ||
                        STR_EQ(arg1, ccec_cp_521);
        }
#endif // !(CC_KERNEL)
#if !(CC_KERNEL || CC_USE_L4)
        if (STR_EQ(function, ccdh_generate_key) ||
            STR_EQ(function, ccdh_import_pub)  ||
            STR_EQ(function, ccdh_import_priv) ||
            STR_EQ(function, ccdh_compute_shared_secret)) {
            success =   STR_EQ(arg1, 2048) ||
                        STR_EQ(arg1, 3072) ||
                        STR_EQ(arg1, 4096) ||
                        STR_EQ(arg1, 6144) ||
                        STR_EQ(arg1, 8192);
        }
#endif // !(CC_KERNEL || CC_USE_L4)
        
        
        /// KDF
#if (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
        if (STR_EQ(function, ccnistkdf_ctr_hmac) ||
            STR_EQ(function, ccnistkdf_ctr_hmac_fixed)) {
            success =   STR_EQ(arg1, ccsha1_di) ||
                        STR_EQ(arg1, ccsha224_di) ||
                        STR_EQ(arg1, ccsha256_di) ||
                        STR_EQ(arg1, ccsha384_di) ||
                        STR_EQ(arg1, ccsha512_di) ||
                        STR_EQ(arg1, ccsha512_256_di) ||
                        STR_EQ(arg1, ccsha3_224_di) ||
                        STR_EQ(arg1, ccsha3_256_di) ||
                        STR_EQ(arg1, ccsha3_384_di) ||
                        STR_EQ(arg1, ccsha3_512_di);
        }
#endif // (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
        if (STR_EQ(function, cchkdf)) {
            success =   STR_EQ(arg1, ccsha1_di) ||
                        STR_EQ(arg1, ccsha224_di) ||
                        STR_EQ(arg1, ccsha256_di) ||
                        STR_EQ(arg1, ccsha384_di) ||
                        STR_EQ(arg1, ccsha512_di) ||
                        STR_EQ(arg1, ccsha512_256_di) ||
                        STR_EQ(arg1, ccsha3_224_di) ||
                        STR_EQ(arg1, ccsha3_256_di) ||
                        STR_EQ(arg1, ccsha3_384_di) ||
                        STR_EQ(arg1, ccsha3_512_di);
        }
        if (STR_EQ(function, ccpbkdf2_hmac)) {
            success =   STR_EQ(arg1, ccsha1_di) ||
                        STR_EQ(arg1, ccsha224_di) ||
                        STR_EQ(arg1, ccsha256_di) ||
                        STR_EQ(arg1, ccsha384_di) ||
                        STR_EQ(arg1, ccsha512_di) ||
                        STR_EQ(arg1, ccsha512_256_di);
        }
        
#if !(CC_USE_L4 || CC_KERNEL)
        if (STR_EQ(function, ccnistkdf_ctr_cmac) ||
            STR_EQ(function, ccnistkdf_ctr_cmac_fixed)) {
            unsigned long key_byte_length = strtoul(arg1, NULL, 10);
            return  key_byte_length == 16 ||
                    key_byte_length == 24 ||
                    key_byte_length == 32;
        }
#endif // !(CC_USE_L4 || CC_KERNEL)

        /// RSA
        if (STR_EQ(function, ccrsa_generate_fips186_key)
#if !(CC_BRIDGE && CC_KERNEL)
#if !(CC_USE_L4) /// ccrsa_sign_pss is not in L4.
            || STR_EQ(function, ccrsa_sign_pss_msg)
#endif // !(CC_USE_L4)
            || STR_EQ(function, ccrsa_sign_pkcs1v15_msg)
#endif // !(CC_BRIDGE && CC_KERNEL)
            ) {
            unsigned long key_bit_length = strtoul(arg1, NULL, 10);
            success =   key_bit_length >= 2048;
        }
        if (STR_EQ(function, ccrsa_verify_pss_msg) ||
            STR_EQ(function, ccrsa_verify_pkcs1v15_msg)) {
            unsigned long key_bit_length = strtoul(arg1, NULL, 10);
            success =   key_bit_length == 1024 ||
                        key_bit_length >= 2048;
        }
    }
    
    return success;
}

int fips_allowed_drbg_(const char *function, const char *arg1, const char *arg2)
{
    int success = 0;
    
    if ((arg1 == NULL) || (arg2 ==NULL)) {
        return 0;
    }
    
    ///
    /// DRBGs -- CTR_DRBG, HMAC_DRBG, TRNG (HW CTR_DRBG)
    ///
    if (STR_EQ(function, ccdrbg_init)       ||
        STR_EQ(function, ccdrbg_reseed)     ||
        STR_EQ(function, ccdrbg_generate)   ||
        STR_EQ(function, ccdrbg_done)) {
        
        /// DRBG_HMAC (SKS)
        if (STR_EQ(arg1, ccdrbg_factory_nisthmac)) {
            success =
#if (!CC_KERNEL)
                        STR_EQ(arg2, ccsha1_di)   ||
                        STR_EQ(arg2, ccsha256_di) ||
#endif  // (!CC_KERNEL)
                        STR_EQ(arg2, ccsha512_di);
        }
#if !(CC_USE_L4)
        /// DRBG_CTR (SKS)
        if (STR_EQ(arg1, ccdrbg_factory_nistctr)) {
            success =   STR_EQ(arg2, CCAES_KEY_SIZE_128)   ||
                        STR_EQ(arg2, CCAES_KEY_SIZE_256);
        }
#endif // !(CC_USE_L4)
        
        /// DRBG_TRNG (HW CTR_DRBG)
#if (CC_USE_L4)
        if (STR_EQ(arg1, ccdrbg_factory_trng)) {
            success = STR_EQ(arg2, CCAES_KEY_SIZE_256);
        }
#endif
    }

#if (CC_USE_L4)
    if (STR_EQ(function, trng)) {
        if (STR_EQ(arg1, ccdrbg_factory_trng)) {
            success = STR_EQ(arg2, ccsha256_trng_di);
        }
    }
#endif
    
    return success;
}
