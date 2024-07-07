/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccaes.h>
#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_aes_ccm.h"
#include <corecrypto/cc_priv.h>

// Test the AES CCM mode
int fipspost_post_aes_ccm(uint32_t fips_mode)
{
    // Decryption data (test vector 1 from NIST CCM document SP-800-38C document by Dworkin)
    const uint8_t key_buffer_dec[] =  {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    const size_t key_buffer_dec_length = CC_ARRAY_LEN(key_buffer_dec);
    
    const uint8_t dec_nonce_buffer[]= {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    const size_t dec_nonce_buffer_length = CC_ARRAY_LEN(dec_nonce_buffer);
    
    const uint8_t dec_aData[]= {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    const size_t dec_aData_len  = CC_ARRAY_LEN(dec_aData);
    
    const uint8_t dec_data_in[] = {0x71, 0x62, 0x01, 0x5b};
    const size_t dec_data_in_length = CC_ARRAY_LEN(dec_data_in);
    
    const uint8_t dec_plaintext[] = {0x20, 0x21, 0x22, 0x23};
    
    uint8_t dec_dataOut[sizeof(dec_plaintext)];
    uint8_t dec_tag[4];
    const size_t dec_tag_length = sizeof(dec_tag);

    unsigned char* result_tag_dec_ptr;
    result_tag_dec_ptr = POST_FIPS_RESULT_STR("\x4d\xac\x25\x5d");
    size_t result_tag_dec_length = 4;
    
    int rc = CCERR_OK;
    
    // Test decryption and authentication first
    memset(dec_tag, 0, dec_tag_length);
    const struct ccmode_ccm* mode_dec_ptr = ccaes_ccm_decrypt_mode();
    if (ccccm_one_shot(mode_dec_ptr, key_buffer_dec_length, key_buffer_dec,
                       dec_nonce_buffer_length, dec_nonce_buffer,
                       dec_data_in_length, dec_data_in, dec_dataOut,
                       dec_aData_len, dec_aData,
                       dec_tag_length, dec_tag)) {
        failf("ccccm_one_shot AEAD decrypt authentication");
        return CCPOST_LIBRARY_ERROR;
    }
    
    // Validate authentication and encryption
    if (cc_cmp_safe(result_tag_dec_length, dec_tag, result_tag_dec_ptr)) {
        failf("ccccm_one_shot AEAD decrypt authentication");
        rc |= CCPOST_KAT_FAILURE;
    }
    if (cc_cmp_safe(sizeof(dec_plaintext), dec_dataOut, dec_plaintext)) {
        failf("ccccm_one_shot AEAD decrypt decryption");
        rc |= CCPOST_KAT_FAILURE;
    }
    
    // Validate decryption and verification
    if (ccccm_one_shot_decrypt(mode_dec_ptr, key_buffer_dec_length, key_buffer_dec,
                       dec_nonce_buffer_length, dec_nonce_buffer,
                       dec_data_in_length, dec_data_in, dec_dataOut,
                       dec_aData_len, dec_aData,
                       dec_tag_length, result_tag_dec_ptr)) {
        failf("ccccm_one_shot AEAD decrypt authentication");
        rc |= CCPOST_KAT_FAILURE;
    }
    if (cc_cmp_safe(sizeof(dec_plaintext), dec_dataOut, dec_plaintext)) {
        failf("ccccm_one_shot AEAD decrypt decryption");
        rc |= CCPOST_KAT_FAILURE;
    }
    
    // Encryption Data (test vector 2 from FIPS document)
    const uint8_t enc_key_buffer[]= {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    const size_t enc_key_buffer_length = CC_ARRAY_LEN(enc_key_buffer);
    
    uint8_t enc_nonce_buffer[]= {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const size_t enc_nonce_buffer_length = CC_ARRAY_LEN(enc_nonce_buffer);
    
    const uint8_t enc_aData[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const size_t enc_aData_length = CC_ARRAY_LEN(enc_aData);
    
    const uint8_t enc_ciphertext_in []= {0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62, 0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59, 0x3d};
    const size_t enc_ciphertext_in_length = CC_ARRAY_LEN(enc_ciphertext_in);
    
    uint8_t enc_plaintext[] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
    const size_t enc_plaintext_length = CC_ARRAY_LEN(enc_plaintext);
    
    unsigned char* enc_result_tag_ptr;
    enc_result_tag_ptr = POST_FIPS_RESULT_STR("\x1f\xc6\x4f\xbf\xac\xcd");
    
    // Test encryption and authentication
    uint8_t enc_tag[6];
    memset(enc_tag, 0, sizeof(enc_tag));
    const size_t enc_tag_length = sizeof(enc_tag);

    uint8_t enc_ciphertext_out[sizeof(enc_ciphertext_in)];
    
    const struct ccmode_ccm* mode_enc_ptr = ccaes_ccm_encrypt_mode();
    if (ccccm_one_shot(mode_enc_ptr, enc_key_buffer_length, enc_key_buffer,
                       enc_nonce_buffer_length, enc_nonce_buffer,
                       enc_plaintext_length, enc_plaintext, enc_ciphertext_out,
                       enc_aData_length, enc_aData,
                       enc_tag_length, enc_tag)) {
        failf("ccccm_one_shot encrypt authentication");
        return CCPOST_LIBRARY_ERROR;
    }
    
    // Validate encryption and authentication
    if (cc_cmp_safe( enc_tag_length, enc_tag, enc_result_tag_ptr)) {
        failf("ccccm_one_shot encrypt authentication");
        rc |=  CCPOST_KAT_FAILURE;
    }
    if (cc_cmp_safe(enc_ciphertext_in_length, enc_ciphertext_out, enc_ciphertext_in)) {
        failf("ccccm_one_shot encrypt encryption");
        rc |=  CCPOST_KAT_FAILURE;
    }
    
    if (ccccm_one_shot_encrypt(mode_enc_ptr, enc_key_buffer_length, enc_key_buffer,
                       enc_nonce_buffer_length, enc_nonce_buffer,
                       enc_plaintext_length, enc_plaintext, enc_ciphertext_out,
                       enc_aData_length, enc_aData,
                       enc_tag_length, enc_tag)) {
        failf("ccccm_one_shot encrypt authentication");
        return CCPOST_LIBRARY_ERROR;
    }
    
    // Validate encryption and authentication
    if (cc_cmp_safe( enc_tag_length, enc_tag, enc_result_tag_ptr)) {
        failf("ccccm_one_shot encrypt authentication");
        rc |=  CCPOST_KAT_FAILURE;
    }
    if (cc_cmp_safe(enc_ciphertext_in_length, enc_ciphertext_out, enc_ciphertext_in)) {
        failf("ccccm_one_shot encrypt encryption");
        rc |=  CCPOST_KAT_FAILURE;
    }
    
    return rc;
}
