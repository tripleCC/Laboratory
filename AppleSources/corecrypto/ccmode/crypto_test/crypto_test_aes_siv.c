/* Copyright (c) (2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

//  Created by Apple Inc. on 5/22/19.
//

#include "crypto_test_modes.h"
#include <corecrypto/ccmode.h>
#include "testmore.h"
#include "ccmode_siv_internal.h"
#include "ccmode_siv.h"
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_impl.h>
#include <corecrypto/ccaes.h>

int ccmode_aes_siv_encrypt_decrypt_in_place_tests(cc_ciphermode_descriptor cm,
                                                  CC_UNUSED cc_symmetric_context_p ctx,
                                                  cc_ciphermode_descriptor dcm,
                                                  CC_UNUSED cc_symmetric_context_p dctx)
{   
    size_t block_size = CCAES_BLOCK_SIZE;
    uint8_t key[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    size_t key_len = sizeof(key);
    is(key_len, 32, "Key Length is supposed to be 32 bytes long");
    uint8_t *adata = (uint8_t *)"This is the first piece of authenticated data";
    size_t adata_len CC_UNUSED = strlen((char *)adata);
    uint8_t *iv = (uint8_t *)"This is the IV/nonce";
    size_t iv_len CC_UNUSED = strlen((char *)iv);
    uint8_t *plaintext = (uint8_t *)"This is a sample plaintext";
    size_t plaintext_n = strlen((char *)plaintext);
    uint8_t extended_plaintext_buffer[2*plaintext_n + 2 * block_size];
  
    memcpy(extended_plaintext_buffer, plaintext, plaintext_n);

    // Test to ensure that ccsive_one_shot performs decryption "in-place". That is ciphertext
    // and plaintext can occupy same place in memory. Necessary requirement for some security properties
    ccsiv_one_shot(cm->ciphermode.siv,
                   32,
                   key,
                   (unsigned int)iv_len,
                   iv,
                   (unsigned int)adata_len,
                   adata,
                   plaintext_n,
                   plaintext,
                   extended_plaintext_buffer);
    ccsiv_one_shot(dcm->ciphermode.siv,
                   32,
                   key,
                   (unsigned int)iv_len,
                   iv,
                   (unsigned int)adata_len,
                   adata,
                   plaintext_n + block_size,
                   extended_plaintext_buffer,
                   extended_plaintext_buffer);
    ok_memcmp(extended_plaintext_buffer,
              plaintext,
              plaintext_n,
              "Failed ccsive_one_shot decrypt in place: Implementation should allow in and out to point to same buffer");

    is(ccsiv_one_shot(cm->ciphermode.siv,
                      32,
                      key,
                      (unsigned int)iv_len,
                      iv,
                      (unsigned int)adata_len,
                      adata,
                      plaintext_n,
                      plaintext,
                      plaintext),
       CCMODE_BUFFER_OUT_IN_OVERLAP,
       "in call to ccsiv_one_shot in encrypt mode, cannot hav in - block_length < out < in + length(plaintext)");
    is(ccsiv_one_shot(cm->ciphermode.siv,
                      32,
                      key,
                      (unsigned int)iv_len,
                      iv,
                      (unsigned int)adata_len,
                      adata,
                      plaintext_n,
                      plaintext,
                      plaintext - block_size + 1 ),
       CCMODE_BUFFER_OUT_IN_OVERLAP,
       "in call to ccsiv_one_shot in encrypt mode, cannot hav in - block_length < out < in + length(plaintext)");
    is(ccsiv_one_shot(cm->ciphermode.siv,
                      32,
                      key,
                      (unsigned int)iv_len,
                      iv,
                      (unsigned int)adata_len,
                      adata,
                      plaintext_n,
                      plaintext,
                      plaintext + plaintext_n - 1),
       CCMODE_BUFFER_OUT_IN_OVERLAP,
       "in call to ccsiv_one_shot in encrypt mode, cannot have out < in + length(plaintext)");

    memcpy(extended_plaintext_buffer, plaintext, plaintext_n);
    is(ccsiv_one_shot(cm->ciphermode.siv,
                      32,
                      key,
                      (unsigned int)iv_len,
                      iv,
                      (unsigned int)adata_len,
                      adata,
                      plaintext_n,
                      extended_plaintext_buffer,
                      extended_plaintext_buffer+plaintext_n),
       CCERR_OK,
       "in call to ccsiv_one_shot in encrypt mode, everything should be fine if out >= in + length(plaintext)");


    memcpy(extended_plaintext_buffer + block_size, plaintext, plaintext_n);
    is(ccsiv_one_shot(cm->ciphermode.siv,
                      32,
                      key,
                      (unsigned int)iv_len,
                      iv,
                      (unsigned int)adata_len,
                      adata,
                      plaintext_n,
                      extended_plaintext_buffer + block_size,
                      extended_plaintext_buffer),
       CCERR_OK,
       "ccsiv_one_shot encrypt won't encrypt in place, but it should encrypt close to in place if out = in - block_len");


    ccsiv_one_shot(dcm->ciphermode.siv,
                   32,
                   key,
                   (unsigned int)iv_len,
                   iv,
                   (unsigned int)adata_len,
                   adata,
                   plaintext_n + block_size,
                   extended_plaintext_buffer,
                   extended_plaintext_buffer);
    ok_memcmp(extended_plaintext_buffer,
              plaintext,
              plaintext_n,
              "Failed ccsive_one_shot decrypt in place: Implementation should allow in and out to point to same buffer");



    return 1;
}
