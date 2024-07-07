/* Copyright (c) (2012,2014-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdlib.h>
#include "testmore.h"
#include "testbyteBuffer.h"
#include <corecrypto/ccmode.h>
#include "ccsymmetric.h"
#include "crypto_test_modes.h"
#include "crypto_test_modes_vectors.h" // raw data is here
#include "cc_debug.h"

static int verbose = 0;

static void report_cipher_mode(duplex_cryptor cryptor) {
    char *cipherStr, *modeStr, *digestStr;
    
    switch(cryptor->cipher) {
        case cc_cipherAES: cipherStr = "AES-"; break;
        case cc_cipherDES: cipherStr = "DES-"; break;
        case cc_cipher3DES: cipherStr = "3DES-"; break;
        case cc_cipherCAST: cipherStr = "CAST-"; break;
        case cc_cipherRC2: cipherStr = "RC2-"; break;
        case cc_cipherBlowfish: cipherStr = "Blowfish-"; break;
        default: cipherStr = "UnknownCipher-"; break;
    }
    switch(cryptor->mode) {
        case cc_ModeECB:   modeStr = "ECB\n"; break;
        case cc_ModeCBC:   modeStr = "CBC\n"; break;
        case cc_ModeCFB:   modeStr = "CFB\n"; break;
        case cc_ModeCTR:   modeStr = "CTR\n"; break;
        case cc_ModeOFB:   modeStr = "OFB\n"; break;
        case cc_ModeXTS:   modeStr = "XTS\n"; break;
        case cc_ModeCFB8:  modeStr = "CFB8\n"; break;
        case cc_ModeGCM:   modeStr = "GCM\n"; break;
        case cc_ModeCCM:   modeStr = "CCM\n"; break;
        case cc_ModeSIV:   modeStr = "SIV\n"; break;
        case cc_ModeSIV_HMAC: modeStr = "SIV_HMAC\n"; break;
        default: modeStr = "UnknownMode\n"; break;
    }
    switch(cryptor->digest){
        case cc_digestSHA256: digestStr = "SHA256\n"; break;
        default: digestStr = "UnknownDigest --Correct if not an HMAC mode\n"; break;
    }
    diag("%s%s%s", cipherStr, modeStr, digestStr);
}

ccsymmetric_test_vector *vectors[cc_NCiphers][cc_NModes] = {
    { aes_ecb_vectors, aes_cbc_vectors, aes_cfb_vectors, NULL, aes_ofb_vectors, aes_xts_vectors, aes_cfb8_vectors, aes_gcm_vectors, aes_ccm_vectors,aes_siv_vectors, aes_siv_hmac_vectors}, // AES
    { des_ecb_vectors, des_cbc_vectors, des_cfb_vectors, des_ctr_vectors, des_ofb_vectors, NULL, des_cfb8_vectors, NULL, NULL }, // DES
    { des3_ecb_vectors, des3_cbc_vectors, des3_cfb_vectors, des3_ctr_vectors, des3_ofb_vectors, NULL, des3_cfb8_vectors, NULL, NULL }, // 3DES
    { cast_ecb_vectors, cast_cbc_vectors, cast_cfb_vectors, cast_ctr_vectors, cast_ofb_vectors, NULL, cast_cfb8_vectors, NULL, NULL }, // CAST
    { rc2_ecb_vectors, rc2_cbc_vectors, rc2_cfb_vectors, rc2_ctr_vectors, rc2_ofb_vectors, NULL, rc2_cfb8_vectors, NULL, NULL }, // RC2
    { blowfish_ecb_vectors, blowfish_cbc_vectors, blowfish_cfb_vectors, blowfish_ctr_vectors, blowfish_ofb_vectors, NULL, blowfish_cfb8_vectors, NULL, NULL }, // Blowfish
};


static cc_status
ccsymmetric_tests(duplex_cryptor cryptor, ccsymmetric_test_vector test) {
    byteBuffer key = hexStringToBytes(test.keyStr);
    byteBuffer twk = hexStringToBytes(test.twkStr);
    byteBuffer init_iv = hexStringToBytes(test.init_ivStr);
    byteBuffer block_iv = hexStringToBytes(test.block_ivStr);
    byteBuffer adata = hexStringToBytes(test.aDataStr);
    byteBuffer adata2 = hexStringToBytes(test.aData2Str);
    byteBuffer pt = hexStringToBytes(test.ptStr);
    byteBuffer ct = hexStringToBytes(test.ctStr);
    byteBuffer tag = hexStringToBytes(test.tagStr);
    size_t len_in = pt->len;
    size_t len_out = ct->len;
    cc_status status = 1;
    
    cc_ciphermode_descriptor_s encrypt_desc;
    cc_ciphermode_descriptor_s decrypt_desc;
    
    encrypt_desc.cipher = decrypt_desc.cipher = cryptor->cipher;
    encrypt_desc.mode = decrypt_desc.mode = cryptor->mode;
    encrypt_desc.direction = cc_Encrypt;
    decrypt_desc.direction = cc_Decrypt;
    encrypt_desc.ciphermode = cryptor->encrypt_ciphermode;
    decrypt_desc.ciphermode = cryptor->decrypt_ciphermode;
    
    MAKE_GENERIC_MODE_CONTEXT(encrypt_ctx, &encrypt_desc);
    MAKE_GENERIC_MODE_CONTEXT(decrypt_ctx, &decrypt_desc);

    if(verbose) report_cipher_mode(cryptor);

    //--------------------------------------------------------------------------
    // Known answer test
    //--------------------------------------------------------------------------
    switch(cryptor->mode) {
        case cc_ModeECB:
        case cc_ModeCBC:
        case cc_ModeCFB:
        case cc_ModeCTR:
        case cc_ModeOFB:
        case cc_ModeCFB8:
            ok_or_fail((cc_symmetric_setup(&encrypt_desc, key->bytes, key->len, init_iv->bytes, encrypt_ctx) == 0), "cipher-mode is initted");
            ok_or_fail((cc_symmetric_setup(&decrypt_desc, key->bytes, key->len, init_iv->bytes, decrypt_ctx) == 0), "cipher-mode is initted");
            break;
        case cc_ModeXTS:
            ok_or_fail((cc_symmetric_setup_tweaked(&encrypt_desc, key->bytes, key->len, twk->bytes, init_iv->bytes, encrypt_ctx) == 0), "cipher-mode is initted");
            ok_or_fail((cc_symmetric_setup_tweaked(&decrypt_desc, key->bytes, key->len, twk->bytes, init_iv->bytes, decrypt_ctx) == 0), "cipher-mode is initted");
            break;
        
        case cc_ModeSIV_HMAC:
        case cc_ModeCCM:
        case cc_ModeGCM:
        case cc_ModeSIV:
            ok_or_fail((cc_symmetric_setup_authenticated(&encrypt_desc, key->bytes, key->len, init_iv->bytes, init_iv->len,
                                                         adata->bytes, adata->len, adata2->bytes, adata2->len,
                                                         len_in, tag->len, encrypt_ctx) == 0), "cipher-mode is initted");
            ok_or_fail((cc_symmetric_setup_authenticated(&decrypt_desc, key->bytes, key->len, init_iv->bytes, init_iv->len,
                                                         adata->bytes, adata->len, adata2->bytes, adata2->len,
                                                         len_out, tag->len, decrypt_ctx) == 0), "cipher-mode is initted");
            break;
        default:
            break;
    }
    
    uint8_t in[len_in], out[len_out];
    ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) encrypt_ctx, block_iv->bytes, pt->bytes, out, len_in) == 0,
               "cc_symmetric_crypt encrypt");

    if(test.ctStr) {
        ok_memcmp_or_fail(out, ct->bytes, len_out, "ciphertext as expected");
    } else if(verbose) {
        byteBuffer result = bytesToBytes(out, len_out);
        diag("Round Trip Results\n");
        printByteBufferAsCharAssignment(pt, "pt");
        printByteBufferAsCharAssignment(result, "ct");
        free(result);
        return 1;
    }
    
    ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) decrypt_ctx, block_iv->bytes, out, in, len_out) == 0,
               "cc_symmetric_crypt decrypt");
    ok_memcmp_or_fail(in, pt->bytes, len_in, "plaintext as expected");
    
    if ((cryptor->mode == cc_ModeGCM)
        || (cryptor->mode == cc_ModeCCM)){
        size_t len = tag->len;
        char returned_tag[len];
        cc_clear(len, returned_tag);

        ok_or_fail(cc_symmetric_authenticated_finalize((cc_symmetric_context_p) encrypt_ctx, returned_tag, len) == 0,
                   "cc_symmetric_authenticated_finalize encrypt");
        ok_or_fail(cc_symmetric_authenticated_finalize((cc_symmetric_context_p) decrypt_ctx, returned_tag, len) == 0,
                   "cc_symmetric_authenticated_finalize decrypt");

        if(test.tagStr) {
            ok_memcmp_or_fail(returned_tag, tag->bytes, len, "computed and expected tags match");
        } else {
            byteBuffer result = bytesToBytes(returned_tag, len);
            diag("Round Trip Tags\n");
            printByteBufferAsCharAssignment(result, "tagStr");
            free(result);
        }
    }

    //--------------------------------------------------------------------------
    // Usage test
    //--------------------------------------------------------------------------
    switch(cryptor->mode) {
        case cc_ModeECB:
        case cc_ModeCBC:
        case cc_ModeCFB:
        case cc_ModeCTR:
        case cc_ModeOFB:
        case cc_ModeCFB8:
        case cc_ModeGCM:
        case cc_ModeCCM:
            break;
        case cc_ModeSIV:
            memset(in,0,sizeof(in));
            memset(out,0,sizeof(out));

            // Encrypt again => expect failure with SIV
            ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) encrypt_ctx, block_iv->bytes, pt->bytes, out, len_in) != 0,
                       "Negative test: cc_symmetric_crypt encrypt");
            ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) decrypt_ctx, block_iv->bytes, out, in, len_out) != 0,
                       "Negative test: cc_symmetric_crypt decrypt");

            // Reset
            ok_or_fail(cc_symmetric_reset((cc_symmetric_context_p) encrypt_ctx) == 0,
                       "cc_symmetric_reset reset");
            ok_or_fail(cc_symmetric_reset((cc_symmetric_context_p) decrypt_ctx) == 0,
                       "cc_symmetric_reset reset");

            // Success after reset
            ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) encrypt_ctx, block_iv->bytes, pt->bytes, out, len_in) == 0,
                       "After reset cc_symmetric_crypt encrypt");
            ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) decrypt_ctx, block_iv->bytes, out, in, len_out) == 0,
                       "After reset cc_symmetric_crypt decrypt");

            if (adata->len==0 && adata2->len==0 && init_iv->len==0) {
                ok_memcmp_or_fail(out, ct->bytes, len_out, "ciphertext as expected");
                ok_memcmp_or_fail(in, pt->bytes, len_in, "plaintext as expected");
            }
            break;
        default:
            break;
    }


    //--------------------------------------------------------------------------
    free(key);
    free(twk);
    free(init_iv);
    free(block_iv);
    free(adata);
    free(adata2);
    free(pt);
    free(tag);
    free(ct);
    return status;
}

static int
run_symmetric_vectors(duplex_cryptor cryptor) {
    ccsymmetric_test_vector *run_vector = vectors[cryptor->cipher][cryptor->mode];
    for(int i=0; run_vector[i].keyStr != NULL; i++) {
        ccsymmetric_test_vector test = run_vector[i];
        ok_or_fail(ccsymmetric_tests(cryptor, test), "Test Vector %d",i);
    }
    return 1;
}

int test_mode(ciphermode_t encrypt_ciphermode, ciphermode_t decrypt_ciphermode, cc_cipher_select cipher, cc_mode_select mode) {
    duplex_cryptor_s cryptor;
   
    cryptor.cipher = cipher;
    cryptor.mode = mode;
    cryptor.encrypt_ciphermode = encrypt_ciphermode;
    cryptor.decrypt_ciphermode = decrypt_ciphermode;
    cryptor.digest = cc_NDigest;
    ok_or_fail(run_symmetric_vectors(&cryptor), "Cipher-Mode Test");

    // Switch to allow testing for properties that are specific to a given node
    switch(mode) {
        case cc_ModeSIV:
            test_aes_siv_corner_cases(&cryptor);
            break;
        default:
            break;
    }

    return 1;
}

int test_hmac_mode(ciphermode_t encrypt_ciphermode, ciphermode_t decrypt_ciphermode, cc_cipher_select cipher, cc_mode_select mode, cc_digest_select digest) {
    duplex_cryptor_s cryptor;
    cryptor.cipher = cipher;
    cryptor.mode = mode;
    cryptor.digest = digest;
    cryptor.encrypt_ciphermode = encrypt_ciphermode;
    cryptor.decrypt_ciphermode = decrypt_ciphermode;
    ok_or_fail (test_siv_hmac_corner_cases(&cryptor), "siv_hmac corner case tests");
    ok_or_fail(run_symmetric_vectors(&cryptor), "Cipher-Mode Test");
    return 1;
}

int test_siv_hmac_corner_cases(duplex_cryptor cryptor)
{
    cc_ciphermode_descriptor_s encrypt_desc;
    cc_ciphermode_descriptor_s decrypt_desc;
    encrypt_desc.cipher = decrypt_desc.cipher = cryptor->cipher;
    encrypt_desc.mode = decrypt_desc.mode = cryptor->mode;
    encrypt_desc.direction = cc_Encrypt;
    encrypt_desc.ciphermode = cryptor->encrypt_ciphermode;

    MAKE_GENERIC_MODE_CONTEXT(encrypt_ctx, &encrypt_desc);
    ccmode_siv_hmac_state_tests(&encrypt_desc, encrypt_ctx);
    return 1;
}

int test_aes_siv_corner_cases(duplex_cryptor cryptor)
{
        cc_ciphermode_descriptor_s encrypt_desc;
        cc_ciphermode_descriptor_s decrypt_desc;
        encrypt_desc.cipher = decrypt_desc.cipher = cryptor->cipher;
        encrypt_desc.mode = decrypt_desc.mode = cryptor->mode;
        encrypt_desc.direction = cc_Encrypt;
        decrypt_desc.direction = cc_Decrypt;
        encrypt_desc.ciphermode = cryptor->encrypt_ciphermode;
        decrypt_desc.ciphermode = cryptor->decrypt_ciphermode;

        MAKE_GENERIC_MODE_CONTEXT(encrypt_ctx, &encrypt_desc);
        MAKE_GENERIC_MODE_CONTEXT(decrypt_ctx, &decrypt_desc);
        ccmode_aes_siv_encrypt_decrypt_in_place_tests(&encrypt_desc, encrypt_ctx, &decrypt_desc, decrypt_ctx);
        return 1;
}

