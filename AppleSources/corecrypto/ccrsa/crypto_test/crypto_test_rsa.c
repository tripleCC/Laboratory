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
#include "testccnBuffer.h"

// static int verbose = 1;

#if (CCRSA == 0)
entryPoint(ccrsa_tests,"ccrsa")
#else
#include "ccrsa_internal.h"
#include <corecrypto/ccrng_test.h>
#include <corecrypto/ccrng_sequence.h>
#include <corecrypto/ccrng_rsafips_test.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include "crypto_test_rsa.h"
#include "crypto_test_rsapss.h"
#include "crypto_test_rsapkcs1v15.h"

#define RSA_KNOWN_KEY_STRESS 10

static int check_sane_key_nbits(ccrsa_full_ctx_t fk, int public) {
    size_t key_nbits;
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);

    if (public) {
        key_nbits = ccrsa_pubkeylength(pubk);
    } else {
        key_nbits = ccrsa_privkeylength(fk);
    }

    return (key_nbits < 512 || key_nbits > 4097);
}

static int crypt_decrypt(ccrsa_full_ctx_t fk)
{
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
    cc_size n = ccrsa_ctx_n(fk);
    cc_unit data[n], cipher[n], decrypted[n];

    ccn_clear(n, data);
    ccn_clear(n, cipher);
    ccn_clear(n, decrypted);

    is(ccn_random_bits(ccrsa_pubkeylength(pubk)-1, data, global_test_rng),0,"Random data");

    CC_DECL_WORKSPACE_TEST(ws);
    is(ccrsa_pub_crypt_ws(ws, pubk, cipher, data),0,"Pub crypt");
    is(ccrsa_priv_crypt_blinded_ws(ws, global_test_rng, fk, decrypted, cipher),0,"Priv crypt");
    CC_FREE_WORKSPACE(ws);

    return !ok_memcmp(decrypted, data, ccn_sizeof_n(n), "Results are what we started with");
}

static int oaep_decrypt_error_test(ccrsa_full_ctx_t fk) {
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
    size_t key_nbits = ccrsa_pubkeylength(pubk);
    size_t key_nbytes = (key_nbits+7)/8;
    cc_size n=ccrsa_ctx_n(pubk);
    cc_unit tmp_u[n];
    ccn_clear(n, tmp_u);
    uint8_t tmp[key_nbytes];
    int status = 0,expected_status;
    uint32_t test_status = 0;
    int test_index=0;
    bool run_test=true;
    struct ccrng_sequence_state rng_seq;

    // Arbitrary choices for the test
    struct ccdigest_info di_big = {
        .output_size = key_nbytes/2+1,
    };
    const struct ccdigest_info *di_test;
    const struct ccdigest_info *di=NULL;
    if (key_nbytes<128) {
        di=ccsha1_di();
    } else
    {
        di=ccsha256_di();
    }

    cc_assert(2*di->output_size+2<key_nbytes);
    size_t M_len=key_nbytes-(2*di->output_size+2); // Message of maximum size
    uint8_t M[M_len];
    uint8_t seed[di->output_size];
    uint8_t seed_mask[di->output_size];
    size_t maskedDB_len=key_nbytes-di->output_size-1;
    memset(seed,0xff,sizeof(seed));
    byteBuffer decryptedData = mallocByteBuffer(M_len);
    char* test_description=NULL;

    // Message is all 0
    memset(M,0,M_len);

    // Seed is all 0xFF
    memset(seed,0xff,sizeof(seed));

    // dbMask = MGF(seed, k - hLen - 1)
    uint8_t dbMask[maskedDB_len];
    ccmgf(di, sizeof(dbMask), dbMask, sizeof(seed), seed);

    // Helpers for operating on the encoded message.
    uint8_t *ptr = ccrsa_block_start(key_nbytes, tmp_u, 0);
    // n might be larger than required by the modulus.
    ptr += ccn_sizeof_n(n - ccn_nof_size(key_nbytes));
    uint8_t *maskedDB = &ptr[1 + di->output_size];

    while(run_test)
    {
        di_test = di;
        key_nbytes = (key_nbits+7)/8;
        M_len = decryptedData->len = sizeof(M);

        // The 2nd and 5th test need zero-bytes in the padding.
        if (test_index == 1 || test_index == 4) {
            M_len -= 7;
        }

        // Encode message, in little endian as an array of cc_unit
        ccrng_sequence_init(&rng_seq, sizeof(seed), seed);
        status=ccrsa_oaep_encode(di, (struct ccrng_state*)&rng_seq, key_nbytes, tmp_u, M_len, M);
        cc_assert(status==0); (void) status; // Analyzer warning in release mode

        switch (test_index)
        {
            case 0:
                test_description="oaep_decrypt: Sanity";
                // Keep the encoded message good for sanity
                expected_status=CCERR_OK; // Pass
                break;
            case 1:
                test_description="oaep_decrypt: Sanity #2";
                // Keep the encoded message good for sanity
                expected_status=CCERR_OK; // Pass
                break;
            case 2:
                test_description="oaep_decrypt: Y not zero";
                // Y is not zero
                ccn_swap(n, tmp_u);
                cc_assert(ptr[0] == 0);
                ptr[0] = 0x01;
                ccn_swap(n, tmp_u);
                if (key_nbits % 8 == 1) {
                    // We need the encoded message to be less than the modulus.
                    // Otherwise, ccrsa_pub_crypt will return an error.
                    // By tampering with the message to set the high byte to one,
                    // we risk violating that constraint iff the high byte of the
                    // modulus is also one (i.e. its bit-length is one mod eight).
                    // We reduce by the modulus to avoid unexpected failures.

                    // If the modular reduction is actually performed (i.e. tmp_u > m),
                    // this results in a free pass for this test case. We do not
                    // expect to receive this pass often enough for regressions
                    // to go unnoticed.

                    (void)ccn_mod(n, tmp_u, n, tmp_u, ccrsa_ctx_m(fk));
                }
                expected_status=CCRSA_PRIVATE_OP_ERROR;
                break;
            case 3:
                test_description="oaep_decrypt: No Separator";
                // No separator 0x01
                ccn_swap(n, tmp_u);
                cc_assert((maskedDB[maskedDB_len - M_len - 1] ^ dbMask[maskedDB_len - M_len - 1]) == 0x01);
                maskedDB[maskedDB_len - M_len - 1] ^= 0x01;
                ccmgf(di, di->output_size, seed_mask, maskedDB_len, maskedDB); // Recompute seed mask
                cc_xor(di->output_size, &ptr[1], seed, seed_mask); // Overwrite maskedSeed
                ccn_swap(n, tmp_u);
                expected_status=CCRSA_PRIVATE_OP_ERROR;
                break;
            case 4:
                test_description="oaep_decrypt: Padding is not zero";
                // Padding is not zero
                ccn_swap(n, tmp_u);
                cc_assert((maskedDB[maskedDB_len - M_len - 1] ^ dbMask[maskedDB_len - M_len - 1]) == 0x01);
                cc_assert((maskedDB[maskedDB_len - M_len - 2] ^ dbMask[maskedDB_len - M_len - 2]) == 0x00);
                maskedDB[maskedDB_len - M_len - 2] ^= 0x02;
                ccmgf(di, di->output_size, seed_mask, maskedDB_len, maskedDB); // Recompute seed mask
                cc_xor(di->output_size, &ptr[1], seed, seed_mask); // Overwrite maskedSeed
                ccn_swap(n, tmp_u);
                expected_status=CCRSA_PRIVATE_OP_ERROR;
                break;
            case 5:
                test_description="oaep_decrypt: lHash does not match";
                // lHash does not match
                ccn_swap(n, tmp_u);
                maskedDB[0] ^= 0x01;
                ccmgf(di, di->output_size, seed_mask, maskedDB_len, maskedDB); // Recompute seed mask
                cc_xor(di->output_size, &ptr[1], seed, seed_mask); // Overwrite maskedSeed
                ccn_swap(n, tmp_u);
                expected_status=CCRSA_PRIVATE_OP_ERROR;
                break;
            case 6:
                test_description="oaep_decrypt: maskedSeed does not match";
                // maskedSeed corrupted
                ccn_swap(n, tmp_u);
                ptr[2] ^= 0x01;
                ccn_swap(n, tmp_u);
                expected_status=CCRSA_PRIVATE_OP_ERROR;
                break;
            case 7:
                test_description="oaep_decrypt: key vs hash length error";
                // Padding test fails
                di_test = &di_big;
                expected_status=CCRSA_INVALID_CONFIG;
                break;
            case 8:
                test_description="oaep_decrypt: output is too small";
                // Output buffer is too small
                decryptedData->len=key_nbytes-2*di->output_size-3;
                expected_status=CCRSA_INVALID_INPUT;
                break;
            case 9:
                test_description="oaep_decrypt: ciphertext is too small";
                // Ciphertext is too small
                key_nbytes -= 1;
                expected_status=CCRSA_INVALID_INPUT;
                break;
            default:
                run_test=false;
                expected_status=1;
                break;
        }

        if (run_test)
        {
            // Encrypt
            is(ccrsa_pub_crypt(pubk, tmp_u, tmp_u),0, "Test %i: ccrsa_pub_crypt",test_index);

            // we need to write leading zeroes if necessary, truncate for test 8
            ccn_write_uint_padded(n, tmp_u, key_nbytes, tmp);

            // Try to decrypt, expected to fail
            CC_DECL_WORKSPACE_TEST(ws);
            ok((status = ccrsa_decrypt_oaep_blinded_ws(ws, global_test_rng, fk, di_test,
                                            &decryptedData->len, decryptedData->bytes,
                                            key_nbytes, tmp,
                                            0, NULL)) == expected_status,
               "Test %i: %s",test_index,test_description);
            CC_FREE_WORKSPACE(ws);

            // Check return value
            if  (status==expected_status)   // Expect failures
            {
                test_status|=(1<<test_index);
            }
            test_index++;
        }

    }
    free(decryptedData);
    if (((1<<test_index)-1)==test_status)
    {
        return 0; // All tests passed
    }
    return -1;
}

static int pkcs1v15_decrypt_error_test(ccrsa_full_ctx_t fk) {
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
    size_t key_nbytes = (ccrsa_pubkeylength(pubk)+7)/8;
    cc_size n=ccrsa_ctx_n(pubk);
    uint8_t tmp[key_nbytes];
    cc_unit tmp_u[n];
    byteBuffer encryptedData = mallocByteBuffer(key_nbytes);
    byteBuffer decryptedData = mallocByteBuffer(key_nbytes);
    int status = 0;
    bool expect_match;
    char* test_description=NULL;

    for (int test_index = 0; test_index < 5; test_index += 1) {
        // Expect format is 00:02:PS:00:Msg
        // PS has to be great or equal to 8 bytes.
        memset(tmp, 0xff, key_nbytes);
        tmp[0] = 0x00;  // Prefix byte 1
        tmp[1] = 0x02;  // Prefix byte 2
        tmp[10] = 0x00; // Prefix separator

        // Fail in most cases
        // In failure, decryption returns random data
        expect_match = false;

        switch(test_index) {
        case 0:
            // GOOD message for sanity, pass
            test_description = "pkcs1v15_decrypt: Sanity";
            expect_match = true;
            break;
        case 1:
            // Prefix byte 1: Not null => must fail
            test_description = "pkcs1v15_decrypt: Padding first byte";
            tmp[0] = 0x01;
            break;
        case 2:
            // Prefix byte 2: Not 0x02 => must fail
            test_description = "pkcs1v15_decrypt: Padding second byte";
            tmp[1] = 0xff;
            break;
        case 3:
            // No separator => must fail
            test_description = "pkcs1v15_decrypt: No separator";
            tmp[10] = 0xff;
            break;
        case 4:
            // Padding length too short => must fail
            test_description = "pkcs1v15_decrypt: Padding length";
            tmp[9] = 0x00;
            break;
        }

        // Convert tmp to unsigned big number representation for encryption
        ccn_zero(n, tmp_u);
        ccn_read_uint(n,tmp_u,key_nbytes,tmp);
        if (ccn_cmp(n,tmp_u,ccrsa_ctx_m(fk))<0) {
            // Encrypt
            is(ccrsa_pub_crypt(pubk, tmp_u, tmp_u),0,"ccrsa_pub_crypt");

            /* we need to write leading zeroes if necessary */
            ok(ccn_write_uint_padded_ct(n, tmp_u, encryptedData->len, encryptedData->bytes)>=0,
               "serializing");

            // Try to decrypt, expected to fail
            decryptedData->len=key_nbytes;
            CC_DECL_WORKSPACE_TEST(ws);
            status = ccrsa_decrypt_eme_pkcs1v15_blinded_ws(ws, global_test_rng, fk,
                                                           &decryptedData->len,
                                                           decryptedData->bytes,
                                                           encryptedData->len,
                                                           encryptedData->bytes);
            is(status, CCERR_OK, "%s return code", test_description);
            CC_FREE_WORKSPACE(ws);

            // Compare the decrypted data to the tail of the tmp buffer.
            bool size_match = decryptedData->len == (key_nbytes - 11);
            int cmp = memcmp(&tmp[11], decryptedData->bytes, decryptedData->len);
            ok((expect_match && size_match && cmp == 0) ||
               (!expect_match && (!size_match || cmp != 0)),
               "%s expect match", test_description);

            ok(decryptedData->len <= (sizeof(tmp) - 11),
               "%s length %z", test_description, decryptedData->len);
        } else {
            // In rare cases, the erroneous message (tmp) can not be encrypted:
            // For example, when tmp is constructed with MSB of 0x01 (eg. "0x0102FFF...") and
            // the key's most significant byte is also 0x01, there is a probability for modulus <= tmp
            // (for example if the input key's second byte is 0x00 or 0x01).
            // In this case tmp is not valid to encrypt for the given key.
            // When that occurs, we skip this test.
            pass("ccrsa_pub_crypt");
            pass(test_description);
        }
    }

    free(encryptedData);
    free(decryptedData);
    return 0;
}

static int pkcs1v15_decode_length_test(ccrsa_full_ctx_t fk, struct ccrng_state *rng)
{
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
    size_t key_nbytes = ccrsa_block_size(pubk);
    cc_size n = ccrsa_ctx_n(pubk);
    cc_unit block[n];

    size_t sizes_seen_count = key_nbytes - 10;
    bool sizes_seen[sizes_seen_count];
    memset(sizes_seen, false, sizes_seen_count);
    bool all_sizes_seen = false;

    int status = CCERR_OK;
    const char *test_description = "pkcs1v15_decode_length_test all sizes seen";

    // Based on estimates for the coupon collector's problem, 2^16
    // iterations should be enough to avoid false negatives even for
    // 8192-bit keys. In the average case, we will break out of this
    // loop in (n * H_n) cases, where n is sizes_seen_count and H_n is
    // the n'th harmonic number. For the same 8192-bit key, that's
    // less than 2^13 iterations.
    for (size_t k = 0; k < (1 << 16); k += 1) {
        size_t block_nbytes = key_nbytes;
        status = ccrng_generate(rng, block_nbytes, block);
        cc_require_action(status == CCERR_OK, out,
                          test_description = "pkcs1v15_decode_length_test rng");

        CC_DECL_WORKSPACE_TEST(ws);
        status = ccrsa_eme_pkcs1v15_decode_safe_ws(ws, fk,
                                                   &block_nbytes, (uint8_t *)block,
                                                   block_nbytes, block);
        CC_FREE_WORKSPACE(ws);

        cc_require_action(status == CCERR_OK, out,
                          test_description = "pkcs1v15_decode_length_test decode");


        cc_require_action(block_nbytes <= (key_nbytes - 11), out,
                          test_description = "pkcs1v15_decode_length_test length");

        sizes_seen[block_nbytes] = true;

        all_sizes_seen = true;
        for (size_t i = 0; i < sizes_seen_count; i += 1) {
            if (!sizes_seen[i]) {
                all_sizes_seen = false;
            }
        }

        if (all_sizes_seen) {
            break;
        }
    }

    is(all_sizes_seen, true, "%s", test_description);

 out:
    is(status, CCERR_OK, "%s", test_description);
    return status;
}

static int pkcs1v15_encrypt_error_test(ccrsa_full_ctx_t fk) {
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
    size_t key_nbytes = (ccrsa_pubkeylength(pubk)+7)/8;
    size_t output_len;
    byteBuffer plaintextData=NULL;
    byteBuffer encryptedData=NULL;
    int status = 0,expected_status;
    uint32_t test_status = 0;
    int test_index=0;
    bool run_test=true;
    char* test_description=NULL;

    while(run_test)
    {
        switch(test_index)
        {
            // Expect format is 00:02:PS:00:Msg
            // PS has to be great or equal to 8 bytes.
            case 0:
                test_description="pkcs1v15_encrypt: sanity";
                // Handcraft GOOD message for sanity
                plaintextData = mallocByteBuffer(key_nbytes-11);
                status = ccrng_generate(global_test_rng, plaintextData->len, plaintextData->bytes);
                is(status,0,"rng error");

                encryptedData = mallocByteBuffer(key_nbytes);

                expected_status=0;
                break;
            case 1:
                test_description="pkcs1v15_encrypt: output buffer too short";
                plaintextData = mallocByteBuffer(key_nbytes-11);
                status = ccrng_generate(global_test_rng, plaintextData->len, plaintextData->bytes);
                is(status,0,"rng error");
                encryptedData = mallocByteBuffer(key_nbytes-1);
                expected_status=CCRSA_INVALID_INPUT;
                break;
            case 2:
                test_description="pkcs1v15_encrypt: message too long";
                plaintextData = mallocByteBuffer(key_nbytes-10);
                status = ccrng_generate(global_test_rng, plaintextData->len, plaintextData->bytes);
                is(status,0,"rng error");
                encryptedData = mallocByteBuffer(key_nbytes);
                expected_status=CCRSA_INVALID_INPUT;
                break;
            default:
                run_test=false;
                expected_status=1;
                break;
        }

        if (run_test)
        {
            // Encrypt the message
            output_len=encryptedData->len;
            ok((status = ccrsa_encrypt_eme_pkcs1v15(pubk,
                                                    global_test_rng,
                                                    &output_len, encryptedData->bytes,
                                                    plaintextData->len, plaintextData->bytes
                                                    )) == expected_status,
               test_description);

            free(encryptedData);encryptedData=NULL;
            free(plaintextData);plaintextData=NULL;
            // Keep record of failures
            if  (status==expected_status)   // Expect failures
            {
                test_status|=(1<<test_index);
            }
            test_index++;
        }

    }
    if (((1<<test_index)-1)==test_status)
    {
        return 0; // All tests passed
    }
    return -1;
}

static int wrap_unwrap(ccrsa_full_ctx_t fk, int padding, struct ccrng_state *rng) {
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
    size_t key_nbytes = ccrsa_privkeylength(fk)/8+64;
    byteBuffer decryptedKey = mallocByteBuffer(key_nbytes);
    byteBuffer encryptedKey = mallocByteBuffer(key_nbytes);
    int status = 1;

    uint8_t keydata[16];
    ok_status(ccrng_generate(global_test_rng, sizeof(keydata), keydata), "Get some random for keydata");

    CC_DECL_WORKSPACE_TEST(ws);

    switch(padding) {
        case PADDING_PKCS1: {
            ok((status = ccrsa_encrypt_eme_pkcs1v15_ws(ws, pubk, rng,
                                        &encryptedKey->len, encryptedKey->bytes,
                                        sizeof(keydata), keydata)) == 0,
                        "Wrap Key Data with RSA Encryption");
            if(status) goto errout;
            ok((status = ccrsa_decrypt_eme_pkcs1v15_blinded_ws(ws, rng, fk,
                                        &decryptedKey->len, decryptedKey->bytes,
                                        encryptedKey->len, encryptedKey->bytes)) == 0,
                        "Unwrap Key Data with RSA Encryption");
            if(status) goto errout;
        } break;
        case PADDING_OAEP: {
            ok((status = ccrsa_encrypt_oaep_ws(ws, pubk, ccsha1_di(), rng,
                                               &encryptedKey->len, encryptedKey->bytes,
                                               sizeof(keydata), keydata, 0, NULL)) == 0,
               "Wrap Key Data with RSA Encryption");
            if(status) goto errout;
            ok((status = ccrsa_decrypt_oaep_blinded_ws(ws, rng, fk, ccsha1_di(),
                                                    &decryptedKey->len, decryptedKey->bytes,
                                                    encryptedKey->len, encryptedKey->bytes, 0, NULL)) == 0,
               "Unwrap Key Data with RSA Encryption");
            if(status) goto errout;
        } break;
    }
    status=!ok_memcmp(keydata,decryptedKey->bytes,sizeof(keydata),"Round Trip wrap/unwrap");
errout:
    free(encryptedKey);
    free(decryptedKey);
    CC_FREE_WORKSPACE(ws);
    return status;
}

#define MAXKEYSPACE 512

static int sign_verify(ccrsa_full_ctx_t fk, int padding, struct ccrng_state *rng, const struct ccdigest_info *di)
{
    int status = 1;
    bool valid=false;
    byteBuffer signature = mallocByteBuffer(MAXKEYSPACE*2);
    
    uint8_t random_msg[di->output_size];
    uint8_t hash[di->output_size];
    ok_status(ccrng_generate(global_test_rng, sizeof(random_msg), random_msg), "Get some random for msg");
    ccdigest(di, di->output_size, random_msg, hash);

    ccrsa_pub_ctx_t pk = ccrsa_ctx_public(fk);
    switch(padding) {
        case PADDING_PKCS1: {
            ok_status_or_goto(ccrsa_sign_pkcs1v15_blinded(global_test_rng, fk, di->oid, sizeof(hash), hash,
                                         &signature->len, signature->bytes), "RSA PKCS v1.5 Signing", errout);

            ok_status_or_goto(ccrsa_verify_pkcs1v15(pk, di->oid, sizeof(hash), hash,
                                           signature->len, signature->bytes,
                                           &valid), "RSA PKCS v1.5 Verifying", errout);
            
            ok_status_or_goto(ccrsa_sign_pkcs1v15_msg_blinded(global_test_rng, fk, di, sizeof(random_msg), random_msg, &signature->len, signature->bytes), "ccrsa_sign_pkcs1v15_msg_blinded failure", errout);
            
            ok_status_or_goto(ccrsa_sign_pkcs1v15_msg(fk, di, sizeof(random_msg), random_msg, &signature->len, signature->bytes), "ccrsa_sign_pkcs1v15_msg failure", errout);

            ok_status_or_goto(ccrsa_verify_pkcs1v15(pk, di->oid, sizeof(hash), hash, signature->len, signature->bytes, &valid), "ccrsa_verify_pkcs1v15 failure", errout);
            
        } break;
        case PADDING_PKCS1_NO_OID: {
            size_t pub_key_bytesize=CC_BITLEN_TO_BYTELEN(ccrsa_pubkeylength(ccrsa_ctx_public(fk)));
            size_t hash_size=1+(size_t)cc_rand((unsigned)pub_key_bytesize-12);

            uint8_t hash_nullOID[hash_size];
            uint8_t fault_canary[sizeof(CCRSA_PKCS1_FAULT_CANARY)];
            ok_status(ccrng_generate(global_test_rng, hash_size, hash_nullOID), "Get some random for hash");
            ok_status_or_goto(ccrsa_sign_pkcs1v15_blinded(global_test_rng, fk, NULL, hash_size, hash_nullOID,
                                                          &signature->len, signature->bytes), "RSA PKCS v1.5 Signing with null OID", errout);
            ok_status_or_goto(ccrsa_verify_pkcs1v15(pk, NULL, hash_size, hash_nullOID,
                                               signature->len, signature->bytes,
                                               &valid), "RSA PKCS v1.5 Verifying with null OID", errout);
            if(!valid) {
                cc_printf("hash_nullOID, modSize %zu, hashSize %zu\n",pub_key_bytesize,hash_size);
                cc_print("hash",hash_size,hash_nullOID);
                goto errout;
            }
            
            is_or_goto(ccrsa_verify_pkcs1v15_digest(pk, NULL, hash_size, hash_nullOID, signature->len, signature->bytes, fault_canary), CCERR_VALID_SIGNATURE, "ccrsa_verify_pkcs1v15_digest failure null OID", errout);
            ok_memcmp_or_goto(CCRSA_PKCS1_FAULT_CANARY, fault_canary, sizeof(CCRSA_PKCS1_FAULT_CANARY), errout, "ccrsa_verify_pkcs1v15_digest buffers differs");
        } break;
        case PADDING_PSS: {
            size_t salt_len=sizeof(hash);
            ok_status_or_goto(ccrsa_sign_pss_blinded(rng,fk, di, di, salt_len, rng, sizeof(hash), hash, &signature->len, signature->bytes), "RSA Signing", errout);
            
            ok_status_or_goto(ccrsa_verify_pss_digest(pk, di, di, sizeof(hash), hash, signature->len, signature->bytes, salt_len, NULL), "RSA Verifying", errout);
            
            ok_status_or_goto(ccrsa_sign_pss_msg(fk, di, di, salt_len, rng, sizeof(random_msg), random_msg, &signature->len, signature->bytes), "ccrsa_sign_pss_msg failure", errout);
            
            ok_status_or_goto(status = ccrsa_verify_pss_digest(pk, di, di, sizeof(hash), hash, signature->len, signature->bytes, salt_len, NULL), "RSA Verifying", errout);

            valid = true;
        } break;
        default: {
            fail("Unknown padding mode");
        } break;
    }
    ok(valid == true, "Signature verifies");
    if(!valid) goto errout;
    free(signature);
    
    return 0;
errout:
    free(signature);
    return -1;
}

static int export_import(ccrsa_full_ctx_t fk)
{
    int pubkeytest = 1;
    int privkeytest = 1;
    int status = 0;
    byteBuffer tmp=NULL;

    if(pubkeytest) {
        ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
        ccrsa_full_ctx_decl_nbits(ccrsa_privkeylength(fk), tmpkey);
        ccrsa_pub_ctx_t pubk2 = ccrsa_ctx_public(tmpkey);
        tmp = mallocByteBuffer(ccrsa_export_pub_size(pubk));
        
        // Public key test
        ok_or_goto((status = ccrsa_export_pub(pubk, tmp->len, tmp->bytes)) == 0, "Exported Public Key",export_import_exit);
        ok_or_goto((ccrsa_ctx_n(pubk2) = ccrsa_import_pub_n(tmp->len, tmp->bytes)) != 0, "Got Key N",export_import_exit);
        ok_or_goto((status = ccrsa_import_pub(pubk2, tmp->len, tmp->bytes)) == 0, "Imported Public Key",export_import_exit);
        ok_or_goto((status = check_sane_key_nbits(tmpkey, 1)) == 0, "key_nbits is realistic",export_import_exit);
        free(tmp);tmp=NULL;
        ccrsa_full_ctx_clear_nbits(ccrsa_privkeylength(fk), tmpkey);
    }
    if(privkeytest) {
        ccrsa_full_ctx_decl_nbits(ccrsa_privkeylength(fk), key2);
        tmp = mallocByteBuffer(ccrsa_export_priv_size(fk));
        
        // Private key test
        ok_or_goto((status = ccrsa_export_priv(fk, tmp->len, tmp->bytes)) == 0, "Exported Private Key",export_import_exit);
        ok_or_goto((ccrsa_ctx_n(key2) = ccrsa_import_priv_n(tmp->len, tmp->bytes)) != 0, "Got Key N",export_import_exit);
        ok_or_goto((status = ccrsa_import_priv(key2, tmp->len, tmp->bytes)) == 0, "Imported Private Key",export_import_exit);
        ok_or_goto((status = check_sane_key_nbits(key2, 0)) == 0, "key_nbits is realistic",export_import_exit);
        ok_or_goto((status = crypt_decrypt(key2)) == 0, "Can round-trip re-imported key",export_import_exit);
        free(tmp);tmp=NULL;
        ccrsa_full_ctx_clear_nbits(ccrsa_privkeylength(fk), key2);
    }
export_import_exit:
    free(tmp);
    if (status==0)
    {
        return 0; // No error
    }
    return 1; // Error;
}

//==============================================================================
//  Keys
//==============================================================================

// Private-Key(2048 bit) (Big Endian, with leading zeros)
const uint8_t key_0_modulus[]={
    0x00, 0x92, 0xe4, 0xa7, 0xd3, 0x2a, 0x34, 0xe1, 0x5d, 0xcb, 0x9e, 0x82,
    0x21, 0x27, 0x52, 0x25, 0x25, 0xf8, 0xba, 0xeb, 0x5f, 0xa0, 0xf3, 0xe5,
    0xd8, 0x82, 0xdf, 0x84, 0x51, 0x03, 0x2a, 0x0f, 0x23, 0x4e, 0x5f, 0xd9,
    0x9b, 0x95, 0x50, 0x05, 0xbc, 0xc3, 0x8b, 0xd8, 0xbe, 0xe4, 0x58, 0x5e,
    0x4e, 0x06, 0x10, 0x0b, 0x0a, 0x80, 0x7a, 0x08, 0x46, 0xff, 0x8e, 0xd7,
    0xf2, 0x61, 0x6e, 0x60, 0xba, 0x9d, 0x17, 0x35, 0x30, 0x4e, 0x4f, 0xdd,
    0xb0, 0xc7, 0xe4, 0xa2, 0x72, 0xf1, 0x3b, 0xb2, 0xe9, 0x5f, 0x37, 0x32,
    0x43, 0xa7, 0xe6, 0x1f, 0xf5, 0x7a, 0xab, 0x44, 0x09, 0x1a, 0x06, 0xa0,
    0x6b, 0x53, 0x0d, 0x42, 0x4b, 0x7a, 0xf2, 0xa4, 0x5a, 0x21, 0x24, 0x29,
    0xe3, 0x25, 0xb9, 0xee, 0x20, 0x65, 0x11, 0x60, 0x6a, 0x66, 0x07, 0xea,
    0x66, 0x71, 0x24, 0x7d, 0x73, 0xc8, 0x2b, 0x56, 0x3b, 0x8e, 0x68, 0x19,
    0xe7, 0xfb, 0x00, 0x88, 0xa7, 0x7a, 0xfb, 0xb9, 0x5b, 0x56, 0xbe, 0x0d,
    0xe9, 0x0c, 0x23, 0x59, 0x43, 0x36, 0xff, 0x7d, 0xc6, 0x94, 0xe9, 0x58,
    0x4f, 0x81, 0x03, 0x15, 0x22, 0xba, 0x36, 0x30, 0x33, 0x6c, 0x5c, 0x5a,
    0xca, 0xdc, 0x2d, 0x51, 0xe0, 0x05, 0x86, 0x0c, 0xec, 0x28, 0x68, 0x29,
    0xd7, 0xba, 0x82, 0xbc, 0xf6, 0xec, 0x02, 0x55, 0x3b, 0x9d, 0xc9, 0x22,
    0xac, 0x0f, 0x26, 0x0f, 0xcb, 0xb0, 0x01, 0x78, 0xbe, 0x3e, 0x47, 0x1e,
    0xbf, 0x53, 0x3f, 0x90, 0x11, 0x65, 0x33, 0xee, 0xb9, 0x58, 0xc1, 0xcb,
    0x56, 0xbb, 0x00, 0xee, 0xd4, 0x24, 0xb9, 0x5b, 0x94, 0x7d, 0x41, 0x63,
    0x4c, 0x83, 0x41, 0xd8, 0x20, 0x4e, 0x62, 0x96, 0xb9, 0x0e, 0x24, 0x2f,
    0xe5, 0x91, 0x0c, 0x04, 0x18, 0x03, 0x7b, 0xfb, 0x60, 0x37, 0x37, 0x52,
    0x01, 0xe7, 0x5a, 0xdf, 0x61
};

const uint32_t key_0_publicExponent=65537;
const uint8_t key_0_privateExponent[]={
    0x13, 0x73, 0x5f, 0x9d, 0xa0, 0x8b, 0x1c, 0x04, 0x75, 0x7f, 0xe9, 0xaf,
    0x46, 0x2b, 0xa4, 0x6b, 0xa0, 0xc1, 0xef, 0x84, 0xdc, 0x25, 0x2f, 0x9c,
    0x39, 0xc8, 0x2b, 0x17, 0x27, 0x1a, 0x1c, 0xa3, 0x0a, 0x2f, 0xba, 0xfa,
    0xd5, 0x0c, 0xa1, 0x95, 0xdb, 0x36, 0xdb, 0x5e, 0x7b, 0x92, 0x0f, 0xfa,
    0xb8, 0xe6, 0xca, 0xef, 0x7b, 0x0f, 0xad, 0xa4, 0xe9, 0x16, 0x1b, 0x16,
    0x27, 0x3c, 0x9c, 0x66, 0x59, 0x82, 0xc7, 0x32, 0x3c, 0x4c, 0x6b, 0x08,
    0x8b, 0x8f, 0x84, 0xcb, 0x3f, 0x92, 0x2e, 0x20, 0xa4, 0xd1, 0x04, 0x40,
    0xdd, 0x2c, 0xa5, 0xb2, 0xb5, 0xa9, 0x93, 0xfa, 0xb8, 0x8d, 0x84, 0x14,
    0x72, 0x0c, 0xe1, 0x68, 0x69, 0x41, 0x53, 0xed, 0xf3, 0x51, 0x7c, 0x92,
    0x6d, 0x5e, 0x6f, 0x5f, 0xae, 0xc2, 0x5c, 0x47, 0xfa, 0x76, 0xb5, 0xdd,
    0x16, 0xc2, 0x44, 0x32, 0x5e, 0xa1, 0x0e, 0x6b, 0xe5, 0x16, 0x15, 0xff,
    0xa8, 0x6e, 0x63, 0x07, 0xf3, 0xe8, 0xce, 0xee, 0x94, 0x40, 0x57, 0xb1,
    0xe0, 0x59, 0xc1, 0x49, 0xd9, 0x9c, 0xc1, 0x95, 0x45, 0xcd, 0x61, 0x18,
    0x1c, 0x0e, 0xb5, 0x8d, 0x0c, 0xc4, 0x71, 0x7b, 0x2c, 0x73, 0xc8, 0x1e,
    0xe3, 0xae, 0x58, 0x99, 0x46, 0x42, 0xa4, 0xca, 0x70, 0x5b, 0x6f, 0x38,
    0xfe, 0x36, 0x00, 0xe9, 0x07, 0x73, 0x17, 0x40, 0x09, 0xdb, 0xb0, 0x3f,
    0x20, 0xc5, 0x45, 0xac, 0x8d, 0x40, 0x2b, 0x16, 0x3c, 0x9b, 0x1c, 0x9a,
    0x92, 0xab, 0x1d, 0x30, 0xf0, 0xbd, 0x5f, 0x1a, 0x84, 0x64, 0x44, 0x80,
    0x48, 0x58, 0x55, 0x76, 0x2c, 0x1e, 0x97, 0x71, 0x6d, 0xd5, 0x60, 0xde,
    0x9f, 0xae, 0x42, 0xf9, 0x5d, 0x4e, 0x3e, 0x0d, 0x70, 0xa7, 0x2f, 0xb8,
    0xdf, 0x4d, 0xf9, 0xb1, 0x58, 0x52, 0x94, 0x64, 0xa6, 0xe5, 0xe6, 0xb4,
    0x77, 0x20, 0x7f, 0xf9
};

const uint8_t key_0_prime1[]={
    0x00, 0xc3, 0x28, 0x4a, 0xdf, 0xa1, 0x76, 0xbc, 0x08, 0xd7, 0x4d, 0x3f,
    0x27, 0x71, 0xe5, 0xca, 0x0d, 0x19, 0x36, 0xa7, 0x45, 0xe5, 0x4a, 0x48,
    0x19, 0xfb, 0x7a, 0xde, 0xf3, 0x1f, 0x5b, 0xbc, 0xda, 0x66, 0x18, 0x00,
    0x41, 0xb6, 0x44, 0xe5, 0x3a, 0xb5, 0xd8, 0x08, 0xa2, 0x17, 0xba, 0x15,
    0xb0, 0xd1, 0xfd, 0x9e, 0x45, 0xbc, 0xc2, 0x0b, 0x0e, 0xe0, 0xbb, 0xbe,
    0x04, 0xb3, 0x57, 0xe8, 0x8d, 0x83, 0x64, 0xc3, 0x0e, 0x71, 0x2b, 0x51,
    0xd5, 0x39, 0xe7, 0x6c, 0x1d, 0x07, 0x86, 0x76, 0x4e, 0x1a, 0xb4, 0x96,
    0xe7, 0xac, 0x7e, 0xe1, 0xda, 0x58, 0xa9, 0x30, 0x62, 0xb9, 0x80, 0xec,
    0x6d, 0x32, 0xb5, 0x60, 0xb5, 0x26, 0xd1, 0x5e, 0x68, 0x54, 0xde, 0x30,
    0xec, 0x8b, 0x9a, 0xe0, 0x96, 0x85, 0x2c, 0x6e, 0x8b, 0xe5, 0x23, 0x9b,
    0xee, 0x1f, 0x38, 0xbf, 0xb0, 0x00, 0x68, 0xae, 0x73
};

const uint8_t key_0_prime2[]={
    0x00, 0xc0, 0xb0, 0x59, 0x28, 0x9c, 0x25, 0xcf, 0x80, 0x2a, 0xf2, 0x10,
    0xf7, 0x16, 0xd9, 0x72, 0x58, 0x33, 0x7b, 0x30, 0xbb, 0x91, 0x1d, 0x5e,
    0x34, 0xc9, 0xf8, 0x18, 0x15, 0xd7, 0xbf, 0x40, 0x55, 0xf2, 0xb9, 0x68,
    0x89, 0x48, 0x9e, 0x6f, 0x0d, 0xa5, 0xe9, 0xc7, 0xbf, 0xa4, 0xe0, 0x1c,
    0xd7, 0x79, 0xe0, 0xf8, 0x5a, 0x6e, 0x1e, 0x2d, 0x2f, 0x7b, 0x6e, 0x46,
    0xe1, 0xec, 0x65, 0xb8, 0x0f, 0x4b, 0x41, 0xab, 0x8e, 0x9b, 0xbd, 0x6b,
    0xcf, 0x5c, 0x7a, 0xcd, 0x4f, 0xa8, 0x99, 0x11, 0x62, 0x1e, 0xd4, 0x12,
    0x42, 0xf7, 0xa3, 0xd2, 0x84, 0xcb, 0xd0, 0xef, 0x65, 0xde, 0x02, 0xef,
    0x2e, 0xb0, 0x00, 0xb0, 0xe0, 0x62, 0xf6, 0x53, 0x9d, 0xa7, 0x0c, 0x0e,
    0x9b, 0x48, 0x85, 0x67, 0x9d, 0x6d, 0x41, 0xca, 0x13, 0xc2, 0x30, 0x95,
    0xfb, 0xf0, 0x27, 0x3b, 0xee, 0xf6, 0xe8, 0x11, 0xdb
};

const uint8_t key_0_exponent1[]={
    0x20, 0x75, 0x4f, 0x1e, 0xaa, 0xa8, 0x28, 0xd5, 0xff, 0x99, 0x25, 0x6b,
    0xd6, 0x11, 0xb5, 0xed, 0x3f, 0xc8, 0x4b, 0x41, 0xe0, 0xc4, 0xde, 0x01,
    0x14, 0x46, 0x77, 0x56, 0x50, 0x5c, 0xdd, 0xa8, 0x25, 0x5a, 0xd0, 0x90,
    0x1d, 0x54, 0x90, 0x1b, 0x97, 0xaa, 0xfa, 0xa4, 0x9a, 0xf5, 0xa4, 0x2d,
    0xe8, 0x7f, 0x1a, 0x17, 0xd7, 0x31, 0x1e, 0xcd, 0xb6, 0xab, 0x03, 0x0b,
    0x9d, 0x18, 0x7d, 0xe1, 0x2b, 0x7d, 0x52, 0xc3, 0xd0, 0x26, 0xb8, 0x51,
    0x92, 0x73, 0xdf, 0x13, 0x64, 0xf1, 0x04, 0x34, 0x31, 0x54, 0xdf, 0xd4,
    0x60, 0x68, 0x2a, 0x00, 0x3a, 0xc6, 0xc8, 0xf9, 0x62, 0x89, 0x02, 0xc9,
    0x96, 0xa9, 0x7c, 0x10, 0x25, 0x08, 0xa5, 0x7f, 0x0c, 0xbe, 0x77, 0xbc,
    0x9f, 0xeb, 0x7e, 0x77, 0x0a, 0x67, 0x3d, 0x6b, 0x9f, 0x0c, 0xb1, 0x1e,
    0x85, 0xaa, 0xd6, 0x96, 0xdb, 0x3a, 0x8d, 0xe9
};

const uint8_t key_0_exponent2[]={
    0x5f, 0x5a, 0x25, 0x14, 0xca, 0x88, 0x8f, 0x71, 0x5e, 0x4f, 0x21, 0x84,
    0x14, 0xa3, 0x90, 0x49, 0x03, 0x58, 0xcf, 0xd9, 0xd1, 0xca, 0xd5, 0xa6,
    0x8b, 0xd7, 0xa0, 0x9b, 0x96, 0x83, 0x06, 0xe4, 0x41, 0x53, 0xec, 0xde,
    0x1a, 0xb8, 0x84, 0x3e, 0x1d, 0xbf, 0x5d, 0x60, 0x81, 0xc7, 0x81, 0x9e,
    0x43, 0xaa, 0xc7, 0x5b, 0x80, 0xa8, 0xa0, 0x35, 0xa2, 0x00, 0x05, 0x45,
    0xa1, 0x85, 0x08, 0x9b, 0x50, 0xe3, 0x73, 0x71, 0x03, 0xb2, 0xad, 0xda,
    0x14, 0x6a, 0x94, 0x94, 0xf9, 0xda, 0x9d, 0x56, 0x8f, 0xe8, 0xe4, 0x0c,
    0x8d, 0x9d, 0x5c, 0xfc, 0xe8, 0x1b, 0x41, 0x8c, 0x88, 0x5b, 0xad, 0x5e,
    0xce, 0x2b, 0xd9, 0x5b, 0x80, 0xbd, 0x62, 0xcd, 0x5e, 0x2f, 0xc2, 0x3e,
    0xa7, 0x99, 0x94, 0x97, 0xbb, 0xcc, 0x55, 0xa2, 0x87, 0x73, 0x21, 0x95,
    0x65, 0xd7, 0x14, 0x7a, 0x81, 0x66, 0x80, 0x07
};

const uint8_t key_0_coefficient[]={
    0xb3, 0x83, 0xf8, 0x90, 0x24, 0x74, 0xba, 0x23, 0xe9, 0x3a, 0xe6,
    0x39, 0x4c, 0x63, 0x9d, 0x35, 0xe3, 0x6f, 0x86, 0x16, 0xa7, 0xcb, 0x35,
    0xa5, 0x60, 0xd4, 0x3f, 0xe3, 0x07, 0xac, 0x4c, 0x74, 0x49, 0x85, 0x5c,
    0x0e, 0x2d, 0xe4, 0x4b, 0xd5, 0x7f, 0x26, 0x98, 0x82, 0x94, 0x1a, 0xc5,
    0xda, 0x9c, 0x65, 0x29, 0x46, 0x0b, 0xb7, 0xf6, 0x64, 0xc8, 0xf2, 0x7d,
    0xbc, 0x70, 0x6d, 0x63, 0x91, 0x6a, 0xcb, 0x0c, 0x61, 0x8c, 0x0a, 0xaf,
    0x1f, 0x7f, 0xd0, 0x77, 0x96, 0x78, 0x0d, 0xbd, 0x57, 0x72, 0xc6, 0xab,
    0x01, 0x4f, 0x49, 0xb9, 0x70, 0x62, 0x40, 0x5e, 0x9f, 0x0e, 0x00, 0xb5,
    0xc6, 0xd0, 0x59, 0xd1, 0x07, 0x82, 0xa2, 0x75, 0xe3, 0x26, 0x49, 0x3a,
    0x39, 0x5c, 0x61, 0x9b, 0xd7, 0x3a, 0x40, 0xaa, 0x26, 0xc0, 0xec, 0x62,
    0x15, 0x14, 0x16, 0x36, 0xc0, 0x29, 0x3b, 0x74, 0x79
};

// Private-Key(1024 bit) (Big Endian)
const uint8_t key_1_1024_modulus[]={
    0xac,0x79,0xe8,0xb0,0xd2,0x11,0x64,0x9a,0x1c,0xe4,0x24,0xf6,0x3c,0xfe,
    0x7c,0x6a,0x3a,0x3e,0x0b,0x07,0xae,0xa9,0x79,0x6f,0x64,0x4e,0xf0,0x5c,0x4c,
    0xb4,0xa7,0x38,0xc9,0xde,0x4a,0x36,0x68,0x7f,0x98,0x05,0xe3,0x3c,0xf8,0xd6,
    0xd2,0xf1,0x9f,0xd9,0x88,0x9d,0xa7,0xcf,0x0d,0xe5,0x92,0x8d,0x2b,0x44,0x24,
    0xa3,0xa7,0x20,0xf4,0xd4,0xd7,0xe5,0xf8,0x07,0x24,0xd7,0xd2,0x32,0x2c,0x8f,
    0xcb,0xd8,0xf8,0xe0,0x97,0x69,0xcb,0xab,0x4c,0xfb,0xf3,0xa2,0xe5,0x43,0x8c,
    0xb1,0x9f,0xa6,0xac,0xe9,0x86,0x88,0x85,0x74,0xf2,0xb2,0xdc,0x87,0x56,0xf5,
    0x99,0x96,0x03,0x70,0xa2,0x5d,0x26,0x26,0x12,0x20,0x09,0x3e,0x5f,0xb0,0x3b,
    0xbd,0xee,0x19,0x9c,0x96,0xd8,0x82,0x22,0x91};
const uint32_t key_1_1024_publicExponent=65537; // (0x10001)
const uint8_t  key_1_1024_privateExponent[]={
    0x03,0xe5,0xc9,0x5d,0x5d,0x91,0xe9,0x0d,0x16,0x84,0x0d,0x55,0xc7,0x31,0x15,
    0x0c,0xad,0x7e,0x43,0x6f,0x8c,0x01,0xe6,0x6d,0x9e,0xfd,0xad,0xae,0xd8,0x48,
    0xe8,0xd2,0x7e,0xb5,0x58,0x45,0xfc,0x7c,0x8d,0xa9,0xec,0x65,0xaf,0x55,0xe3,
    0x74,0x74,0x61,0x4d,0x16,0x0a,0xf9,0xc1,0xdd,0xa3,0x3f,0x2f,0x70,0x1d,0xc7,
    0xd8,0xfa,0x04,0xae,0x52,0x7d,0xe3,0x20,0xc6,0xb5,0x5b,0x6b,0xd7,0x0b,0x02,
    0x2a,0xcf,0x28,0xf4,0x34,0x7d,0x46,0x69,0x15,0xf0,0x95,0xd0,0x7b,0x9a,0xa4,
    0x24,0x9b,0x27,0x49,0x99,0x49,0x14,0x27,0xa9,0x95,0x89,0x6e,0xff,0x96,0x0c,
    0x02,0xb7,0x46,0xab,0x95,0x46,0x34,0x33,0xee,0xe1,0x1a,0x4c,0x3a,0x09,0x19,
    0xf3,0xda,0x2c,0x67,0x8e,0xcc,0x10,0x71};
const uint8_t key_1_1024_prime1[]={
    0x01,0xb5,0x09,0x1a,0x06,0xe7,0xfa,0x1f,0x6b,0x52,0x3f,0xe9,0x57,0x3c,0xd9,
    0xe0,0xdb,0x1a,0x32,0x05,0x0c,0xf8,0xba,0x84,0x55,0xc5,0x17,0x64,0xb6,0x02,
    0x4f,0xcf,0x30,0x07,0x3a,0x1c,0x13,0x14,0xfb,0x5f,0xf6,0xcf,0x4b,0xeb,0x4d,
    0x11,0x6e,0x78,0x93,0x2b,0x38,0xd9,0x8a,0x59,0x0f,0xba,0x57,0xb6,0xc5,0x50,
    0x20,0xf0,0xd5,0x23,0x55};
const uint8_t key_1_1024_prime2[]={
    0x65,0x07,0xcd,0x1e,0x84,0x0f,0x49,0x20,0xa8,0x61,0xff,0x94,0x00,0x2c,0x28,
    0xe9,0x5c,0x19,0xa1,0x11,0x16,0xf3,0xf2,0xbf,0x42,0x8c,0x03,0x66,0xeb,0x1e,
    0x5e,0xe6,0x28,0xb5,0xf5,0x03,0x2b,0x31,0x36,0x40,0xb7,0xd5,0xb6,0x68,0x8f,
    0x62,0xdf,0xca,0xe2,0x38,0xc4,0xac,0xb5,0x7f,0xf3,0xa8,0xc6,0x16,0x32,0xec,
    0x9f,0x50,0x7a,0x4d};
const uint8_t key_1_1024_exponent1[]={
    0x00,0xa2,0x5d,0x8b,0x49,0xdd,0x8d,0x53,0x76,0xef,0xcb,0xc6,0xc9,0x1e,0x56,
    0x63,0xef,0x82,0xbf,0xea,0x98,0x73,0x1f,0xf8,0x62,0x55,0x22,0xe7,0xcb,0xa6,
    0xf8,0x37,0xa5,0x44,0x4a,0x16,0x7c,0x10,0x63,0x83,0xb7,0x92,0x34,0x46,0x6b,
    0x0f,0x7a,0xd7,0x58,0xf5,0xc9,0xdd,0x28,0x45,0x06,0x4e,0xd8,0x9f,0x92,0x96,
    0xbe,0x66,0x3b,0x09,0x31};
const uint8_t key_1_1024_exponent2[]={
    0x38,0xf7,0xaf,0x27,0x97,0xdb,0x6e,0xa6,0xa5,0x8b,0xac,0xab,0x6d,0x75,0x79,
    0x14,0x2c,0xc4,0x9e,0xd7,0x9e,0x13,0xac,0x3b,0x40,0x70,0xe6,0xb2,0x2f,0xbd,
    0x8e,0x51,0x45,0x7f,0x64,0x4a,0x87,0x1e,0x56,0xb3,0x23,0x75,0xb4,0x47,0x3d,
    0x22,0xc9,0x82,0x03,0x11,0x73,0x84,0xd7,0x4a,0xf0,0xbf,0xa8,0x02,0x78,0x70,
    0x88,0x5c,0xbe,0xb9};
const uint8_t key_1_1024_coefficient[]={
    0x01,0xb1,0x42,0xc6,0xc3,0xa0,0x76,0x2c,0x68,0x0f,0x42,0xd1,0x7c,0xe3,0x63,
    0xc4,0xb9,0xb7,0x12,0x56,0xa7,0x59,0xe1,0x20,0xb0,0xd7,0xa4,0xb8,0xa0,0x20,
    0x75,0x99,0x8d,0xf3,0x66,0x4a,0x90,0x9e,0x0a,0xc9,0x93,0x23,0x9f,0xb5,0xbb,
    0x17,0xc1,0xf4,0xe5,0x2f,0x2a,0xfe,0xa3,0xd5,0x4b,0xf0,0xf3,0xec,0xd2,0x55,
    0xe3,0x24,0x7d,0x91,0x4e};
const uint8_t key_1_1024_coefficient_inv[]={
    0xdf,0x63,0x35,0xd4,0x04,0xf5,0x2c,0x4b,0xbe,0x63,0xe6,0xa6,
    0xe6,0xdf,0x1d,0xac,0xaf,0x9f,0xa1,0xa9,0x8a,0x34,0x2c,0x17,
    0xd2,0xe1,0x63,0x12,0x82,0x86,0xad,0x3b,0xc4,0x03,0x9f,0xac,
    0x44,0x20,0x16,0x51,0xcd,0xf7,0xdf,0x2e,0xba,0x22,0xb2,0xed,
    0x14,0xe6,0xb4,0x8b,0x2c,0x8f,0xb2,0xc8,0xe5,0xa7,0xa5,0x48,
    0x0a,0x71,0xac};

// Private-Key(2048 bit) (Big Endian)
const uint8_t key_1_2048_modulus[]={
    0xd5,0x00,0x56,0x84,0x9b,0x61,0xe6,0x7e,0xf8,0xfb,0xb8,0xce,0x49,0x76,
    0x0e,0x03,0xfb,0xfc,0x40,0x34,0x6e,0xcf,0x50,0xae,0x0a,0xe5,0x2e,0x04,0x1a,
    0x6b,0xff,0x14,0x75,0x6a,0xde,0xe8,0x2f,0xd6,0xa7,0xf1,0xdf,0xad,0x44,0x22,
    0x96,0xf0,0x98,0xde,0x25,0x6f,0xb4,0x7e,0x66,0x28,0x5b,0x86,0xe5,0x5d,0xc9,
    0x73,0x17,0xa2,0x2d,0x5f,0x1e,0x62,0xe7,0x90,0xfc,0xa4,0xe7,0x1d,0x22,0xdd,
    0x89,0xfd,0x04,0x8c,0x3e,0x68,0x0e,0x6c,0x00,0x44,0x45,0x11,0xd8,0xb8,0x7b,
    0x86,0xea,0xa4,0x8e,0xf3,0x6d,0xd7,0x14,0xbd,0x4f,0x5a,0x1d,0x81,0x21,0x4d,
    0x16,0x5f,0x81,0xd9,0x3b,0x13,0xee,0xa4,0xda,0xdd,0x63,0x9c,0x64,0x3d,0xff,
    0xc3,0x33,0xaa,0x50,0x99,0x7c,0xa0,0x1a,0xa2,0x68,0x9e,0xd5,0xee,0x3b,0x42,
    0xf6,0x06,0x6e,0x44,0xb5,0x02,0x7c,0x7e,0x3c,0x00,0x73,0x1d,0x1e,0xef,0x66,
    0xa7,0xa0,0x8b,0xc9,0x2b,0x55,0x63,0xf1,0x19,0x1f,0x55,0xb6,0xba,0xa0,0xaf,
    0xc7,0x87,0xd7,0xf2,0x2c,0x2f,0x08,0x70,0xd2,0xa6,0x8b,0x7d,0x11,0xa2,0x13,
    0x5c,0x19,0x1c,0x5e,0x9b,0x66,0x7b,0xd8,0x37,0xba,0x1b,0x3b,0x23,0xef,0xa2,
    0xfc,0x0b,0xc5,0xfd,0x0f,0x94,0xf0,0x4c,0xb2,0x89,0x14,0xfa,0x79,0xc2,0xbc,
    0x02,0xb0,0x06,0x71,0x32,0x45,0x0e,0x89,0xa9,0x2b,0x58,0x2a,0x12,0x31,0xb6,
    0xe1,0x7d,0xfb,0x4e,0x55,0xb5,0x92,0xe6,0xf4,0xfc,0xcb,0x49,0xc7,0x1d,0x1e,
    0x4a,0x73,0xdc,0xd1,0x67,0x2b,0x81,0xcd,0x60,0x83,0xb7,0xf9,0xde,0xa6,0x68,
    0x7c,0xd1
};
const uint32_t key_1_2048_publicExponent=65537; // (0x10001)
const uint8_t  key_1_2048_privateExponent[]={
    0x2d,0x5f,0x0d,0x0e,0xe2,0x2a,0x50,0x76,0xeb,0x82,0x73,0x33,0x3d,0xe2,0xaf,
    0xc9,0x99,0x7b,0x7a,0x11,0xb1,0x28,0xe7,0xfe,0xaa,0xc3,0x76,0xb1,0xd9,0x0e,
    0xf8,0x1e,0xdb,0x84,0x10,0x47,0x55,0x29,0x5c,0x4c,0xe1,0x60,0x7f,0x0a,0xff,
    0x2b,0xf0,0xe4,0x21,0x05,0x52,0x65,0x3a,0x4d,0x8e,0x71,0x85,0x9a,0x1c,0xb7,
    0x2f,0x69,0x94,0x50,0x96,0xa0,0x6a,0xc3,0x2f,0x8d,0xd0,0xcd,0x1c,0x08,0x24,
    0xc4,0x88,0x9b,0x77,0x0f,0xa3,0x42,0xce,0x2b,0xbc,0xaa,0xb8,0x87,0x53,0x88,
    0xc1,0xa2,0x9b,0xf0,0xae,0x8d,0x0a,0x15,0xe9,0x39,0x40,0xdf,0xa8,0xc0,0x4a,
    0xeb,0xbd,0x35,0x10,0xa8,0x86,0x45,0x07,0x79,0xf1,0x25,0xf7,0x14,0x5d,0xce,
    0xae,0xca,0xb0,0xb0,0x81,0x23,0x79,0x88,0x8b,0x23,0xa7,0x64,0xf2,0x6c,0xf4,
    0x68,0xa3,0x77,0xed,0x1d,0xe0,0xf1,0xe5,0x6e,0x9b,0x3b,0x6f,0x19,0x1f,0x0d,
    0x9d,0xc6,0x86,0xcf,0x50,0x1d,0x62,0x73,0x28,0x54,0x6b,0xaa,0x4d,0x20,0xab,
    0xd1,0x46,0xd2,0x8c,0x4a,0xee,0x07,0xe6,0xcf,0x7b,0x61,0xdc,0xd5,0xe6,0x72,
    0x4e,0x1c,0x4d,0x29,0xb4,0xf9,0x37,0x49,0xfe,0x3a,0x7c,0x84,0x4f,0x68,0x17,
    0x4c,0xd3,0xe7,0xf3,0x29,0xc5,0x45,0xe8,0xf6,0x6a,0x90,0x82,0xa2,0x2c,0x38,
    0x7c,0xe2,0x78,0x18,0xf0,0xf2,0xe2,0x63,0x46,0x05,0x2e,0xbf,0xc3,0x46,0xa9,
    0xcc,0xb8,0x30,0x3f,0xa1,0x85,0x5f,0x4f,0x1d,0x80,0x29,0xd1,0x5d,0x4d,0xd7,
    0x1f,0xa2,0xf0,0xf0,0xbe,0x9f,0xbb,0x00,0x63,0x4b,0xdc,0x07,0x36,0x1e,0xa7,
    0x21};
const uint8_t key_1_2048_prime1[]={
    0xdb,0x6b,0x23,0x85,0x3d,0x03,0x9f,0x1a,0xe5,0x68,0x97,0x32,0xd1,0x9f,
    0xb7,0xa6,0x6a,0xfe,0xd8,0x4d,0xd9,0x75,0x6a,0xfd,0xd8,0xf5,0x30,0x92,0x8c,
    0xc7,0x36,0x53,0x28,0xbb,0x63,0x8b,0x3b,0x0d,0x1a,0x1f,0x16,0x76,0x4d,0x3e,
    0x34,0x80,0x68,0x47,0x58,0xa2,0xa5,0x82,0x00,0xf0,0x17,0x55,0xb7,0xec,0xa5,
    0x63,0xdd,0x68,0xfe,0xcd,0x0c,0x56,0xed,0x81,0x8a,0x98,0x3e,0xfc,0x13,0x4a,
    0x41,0x04,0xdb,0x44,0x86,0xf1,0xa5,0xd6,0xf4,0x8a,0xab,0x2b,0x20,0x13,0x7f,
    0x75,0x75,0x1b,0x4b,0x7b,0xa3,0x22,0x84,0xfc,0xde,0x6d,0x42,0xf3,0x41,0xdf,
    0x3f,0x5d,0x87,0xbd,0xad,0x73,0xfd,0xdb,0x1a,0xce,0x0c,0x87,0x83,0x15,0xfd,
    0xe7,0x0c,0x83,0x74,0xa5,0x11,0xb6,0xb9,0x1f};
const uint8_t key_1_2048_prime2[]={
    0xf8,0x83,0x4f,0xaa,0xae,0xfd,0xee,0x37,0x87,0xad,0x03,0x71,0xcf,0xd7,
    0xcc,0x5f,0xe3,0x42,0x07,0x76,0xe4,0xf2,0xe4,0x0e,0xa9,0x3e,0xf7,0x40,0xd7,
    0x2e,0x10,0x30,0x1b,0x4c,0x18,0xff,0xb5,0x5f,0xd8,0x99,0xf5,0xa3,0xb5,0xb7,
    0xbc,0xac,0xc5,0xbb,0xf4,0x1f,0xca,0x6b,0x3f,0xa9,0x81,0x1c,0x45,0x9c,0x9e,
    0x02,0x8f,0x4c,0xf5,0x80,0xc6,0x05,0xa9,0x84,0x4e,0x15,0x9c,0x7c,0x3f,0x74,
    0x51,0x9a,0x2a,0x9e,0xac,0x7e,0xf3,0xf0,0x97,0x0b,0xe4,0xa0,0x6e,0x8e,0x6a,
    0xc4,0x80,0x89,0x11,0x8c,0xfb,0xe7,0x4d,0xa0,0x07,0xf4,0xbc,0x2b,0xb4,0xa0,
    0xa3,0xed,0xe9,0x30,0x87,0x43,0xea,0x38,0x3b,0xad,0xc9,0x5a,0x9a,0xc4,0xd4,
    0x9b,0x62,0xbc,0x3c,0x1c,0x0d,0xc3,0xdc,0x0f};
const uint8_t key_1_2048_exponent1[]={
    0x9a,0xf4,0xb7,0xfa,0x21,0x93,0xcc,0x2a,0x47,0x77,0x2c,0xc8,0x73,0xe8,
    0x12,0xdf,0x91,0x52,0x76,0xd9,0xcb,0xc8,0x33,0x8e,0x20,0x49,0x50,0x4b,0x3e,
    0xe6,0x75,0x44,0x17,0x50,0xf7,0x44,0xdd,0xa8,0x2c,0x19,0x66,0x58,0x97,0xc6,
    0x65,0x77,0x85,0xad,0x55,0x38,0x50,0x20,0x56,0x9f,0x38,0x2b,0x8e,0x1f,0xae,
    0xd1,0xaf,0x0c,0xb6,0x5d,0x82,0xe8,0x65,0x05,0x06,0x26,0xec,0xdc,0x42,0x97,
    0x3f,0x01,0xba,0x04,0x54,0x34,0x96,0x05,0x0f,0x60,0x5a,0xef,0xb2,0xd0,0x72,
    0x44,0x36,0x36,0xd7,0x80,0xf2,0x3d,0xaf,0xa3,0x91,0x45,0xa2,0x71,0x7e,0xc4,
    0xb5,0xd0,0x4c,0xcb,0xb4,0x92,0x64,0xe5,0xf6,0xb1,0x2b,0x82,0x0c,0x1e,0x5c,
    0xd8,0x6e,0x2a,0xec,0x16,0xa3,0x42,0xe2,0xcb};
const uint8_t key_1_2048_exponent2[]={
    0x0c,0x71,0xf7,0x01,0x63,0x36,0x10,0x41,0xf3,0xa7,0x74,0x6e,0xb4,0xab,0xe7,
    0xee,0x3d,0x61,0x47,0x22,0x6b,0x20,0xc6,0xce,0xfd,0x26,0xcc,0x17,0x11,0x2f,
    0x9b,0x5b,0xed,0x62,0x08,0x36,0x76,0x0c,0xd0,0xba,0x15,0x15,0x17,0xba,0x95,
    0xd6,0x49,0x28,0xba,0x77,0x05,0x1a,0x0d,0xdc,0x1d,0x3d,0x1f,0x37,0x52,0xaa,
    0x6a,0x26,0xbe,0x7c,0xae,0x6e,0x06,0x29,0x3c,0x07,0xd5,0x08,0x5b,0xdd,0x25,
    0x61,0x05,0x15,0x61,0x2a,0x12,0x69,0x50,0x07,0x26,0x71,0xea,0x57,0x73,0x7d,
    0x57,0xba,0x85,0x88,0x7b,0xec,0xff,0x74,0x2e,0x31,0xd1,0x62,0x96,0xef,0x1c,
    0x86,0x83,0x91,0x0c,0x95,0x18,0x1b,0xac,0xd1,0x6d,0x2d,0xfe,0x66,0x31,0x07,
    0x7f,0x10,0x52,0x2a,0x4d,0x7e,0x2b,0x7d};
const uint8_t key_1_2048_coefficient[]={
    0x0c,0x23,0xef,0x4e,0x84,0xf3,0x92,0x9f,0x2d,0xcd,0x4c,0x45,0xde,0x10,0x85,
    0x52,0x22,0xf8,0x6c,0x6e,0xb3,0x86,0x14,0x94,0x5b,0x64,0xf3,0x83,0xfd,0xd9,
    0x56,0x72,0xbf,0x98,0x53,0x14,0x69,0x30,0xf1,0xb1,0xad,0x9c,0xc5,0x12,0x00,
    0xf6,0x4e,0x13,0x6c,0xa1,0x20,0xf2,0x1b,0x39,0xa0,0xa3,0xff,0xe6,0xc7,0x0e,
    0x7f,0xa5,0x2e,0xad,0x2a,0x97,0xb3,0x45,0x6d,0xb5,0xdf,0x77,0x28,0x09,0x20,
    0x8c,0xed,0x1d,0x1e,0xfe,0xa2,0xab,0x23,0x6a,0x43,0x90,0x9f,0xe1,0x48,0xfd,
    0x32,0x88,0x13,0xb6,0xc5,0xbf,0x43,0x6c,0xd2,0xb4,0x0e,0xa1,0x34,0x9f,0x47,
    0x71,0xf6,0xb8,0xde,0x24,0x11,0x32,0xfb,0x30,0x9f,0xb5,0x2f,0x18,0x90,0xa8,
    0x15,0xd7,0xaa,0x65,0xe9,0x3e,0xd0,0x76};

const uint8_t key_1_2048_coefficient_inv[]={
    0xea,0xc3,0x45,0x5b,0x36,0x39,0x99,0xd0,0xb5,0x4d,0xc4,0xfb,
    0x97,0x74,0xf2,0x6f,0x7a,0x7c,0xf4,0xa3,0xdb,0xd4,0x42,0x22,
    0xba,0x85,0xba,0xf8,0x9c,0x16,0x83,0xcd,0xb3,0xe7,0x53,0x3c,
    0x93,0x1a,0xd3,0x97,0xf2,0xea,0xae,0x45,0xcc,0x6c,0xc2,0x0b,
    0x98,0x2d,0xab,0x70,0xf0,0x4d,0xa0,0xe2,0xf0,0x6b,0x62,0xe1,
    0x28,0xae,0x44,0xb6,0x02,0x86,0x2d,0x20,0xe6,0xd2,0x9c,0xd5,
    0x81,0x2f,0x0a,0xd6,0x31,0x14,0x81,0xbc,0xb6,0x86,0xd2,0xc7,
    0x25,0x6a,0xb4,0x32,0x6e,0x1b,0x28,0x0d,0x40,0xc3,0xc8,0x6a,
    0x47,0x3f,0x8e,0xd5,0xe5,0xa8,0xb7,0x52,0xc8,0xa4,0x33,0x05,
    0x2a,0xbc,0x44,0xdc,0x87,0x12,0x9b,0x29,0x06,0xa7,0xe3,0x96,
    0x58,0x73,0x75,0x89,0xdb,0x47,0x1d,0x18};

const uint8_t key_1026_prime_1[]={
    0x03,0xb1,0x2f,0x3e,0x76,0x6a,0xff,0xdd,0x2f,0x2b,
    0x04,0x16,0xae,0xb0,0x6c,0xf0,0xff,0x1b,0x14,0x5d,
    0x3a,0x47,0x5b,0xef,0x72,0xd5,0x07,0xa4,0xeb,0x48,
    0x7d,0x69,0xce,0x8b,0x4c,0x66,0x69,0x6b,0xde,0x1f,
    0xf8,0x1c,0x06,0x53,0xaf,0x27,0x17,0x28,0x57,0x52,
    0xe5,0xc3,0x02,0xc6,0x66,0xa1,0x80,0xbc,0xfa,0x01,
    0xd8,0x9d,0x34,0x08,0x8b,
};

const uint8_t key_1026_prime_2[]={
    0x9e,0x81,0x62,0x91,0x77,0x44,0x63,0xae,0x83,0xd0,
    0x8e,0x49,0x88,0xf9,0x70,0xde,0xf5,0x9e,0x62,0xb0,
    0x23,0x18,0xbd,0x2a,0x7a,0x5b,0x40,0x22,0xbc,0x84,
    0x26,0x23,0x3f,0xae,0x89,0x6e,0xf7,0x47,0xba,0x53,
    0x26,0x3a,0x6e,0x9c,0xb9,0x7b,0xd4,0xf2,0x57,0x02,
    0x58,0xac,0x61,0x29,0x0a,0xa5,0xa7,0xb7,0xc2,0x39,
    0x64,0xeb,0x5a,0x45,
};

const uint8_t key_1026_modulus[]={
    0x02,0x49,0x38,0xdd,0x48,0xb9,0xbb,0x02,0x19,0x5c,
    0x0c,0x55,0x94,0x94,0xb2,0x31,0x81,0x61,0x59,0x19,
    0x01,0x4a,0x07,0xd3,0xac,0x3f,0xd1,0x27,0xfb,0xc6,
    0xec,0x31,0xd9,0x0c,0x9c,0xd9,0x9a,0x97,0x3b,0x91,
    0x0c,0x6e,0x7e,0xae,0xa2,0x01,0xb0,0x2b,0x7b,0x38,
    0x2c,0xc4,0x0d,0xcc,0x86,0xd9,0x2f,0xf5,0x1d,0xcd,
    0x60,0x79,0xd8,0xe6,0x0d,0xbd,0xb0,0x0d,0xca,0xee,
    0x3d,0x9a,0xd4,0xa2,0x0a,0x7b,0x57,0x8d,0xb0,0x82,
    0x15,0x79,0x98,0x9f,0x9d,0xe1,0x3e,0x31,0x12,0x32,
    0xd5,0xac,0xbe,0x72,0xe2,0x91,0xe5,0xd0,0x6f,0x0e,
    0x54,0xeb,0x75,0xa8,0xff,0x2d,0xd9,0x38,0xb9,0xec,
    0xc4,0xa2,0xd7,0x59,0x87,0x84,0x4e,0xa7,0x07,0xbe,
    0x13,0x5a,0xb5,0x85,0xb3,0xcd,0xa0,0x2b,0x77,
};

const uint8_t key_1026_public_exponent[]={
    0x01,0x00,0x01,
};

const uint8_t key_1026_private_exponent[]={
    0x35,0xa7,0x5d,0x7e,0x53,0xec,0xe5,0xc9,0xde,0x6b,0x11,
    0x13,0x90,0xb8,0x6f,0x9a,0x7d,0x8a,0xd6,0x24,0x8c,0x9d,
    0x80,0x16,0x1c,0x39,0xb8,0x51,0x38,0x91,0x22,0x16,0xd4,
    0xb5,0xb2,0xab,0x9e,0x2e,0xeb,0x62,0xf8,0xe4,0x6b,0x6d,
    0x55,0xfb,0x49,0x59,0x40,0x32,0xb6,0x7c,0xcf,0x62,0x13,
    0x9a,0x76,0x7e,0x17,0x7c,0xbf,0x5f,0x17,0xe4,0x08,0x6e,
    0x31,0x12,0x06,0xd0,0x83,0x23,0x85,0x73,0xcb,0xa6,0x2c,
    0xcb,0xa8,0xfd,0x7b,0x84,0x0b,0xc8,0xdf,0xdc,0xa4,0xe4,
    0xb4,0x8f,0xaa,0xe8,0x2d,0x82,0xc2,0x13,0x95,0xc6,0x6a,
    0x1f,0x1f,0xbe,0x35,0x64,0xc0,0x76,0x57,0x71,0x4a,0x73,
    0xe8,0xca,0x3f,0x2e,0x3d,0xc0,0xd5,0xc6,0x73,0xda,0x46,
    0x49,0xdc,0xe0,0x51,0x10,0x8b,0x15,
};

const uint8_t key_1026_exponent1 []={
    0x02,0x7f,0xc0,0x91,0x8f,0xc7,0x96,0xcd,0xd8,0x6a,
    0x4e,0x47,0x28,0x10,0x84,0x7c,0x8e,0xbf,0x7e,0x86,
    0x27,0xb7,0x3b,0x34,0x14,0xce,0xba,0x70,0xd7,0x4c,
    0x66,0x8e,0xe2,0x5d,0x88,0xe5,0xdc,0xbf,0x45,0x46,
    0xf0,0x41,0xcf,0xca,0x7e,0xc8,0x7f,0xb5,0x2f,0x7e,
    0x0d,0xc4,0x74,0x31,0x64,0x30,0x36,0x9a,0x32,0xc2,
    0x63,0x22,0xec,0xa0,0x47,
};

const uint8_t key_1026_exponent2 []={
    0x10,0x7a,0x48,0xe1,0xf0,0x71,0x26,0x9f,0xb4,0xca,
    0x50,0x90,0x6a,0x71,0xeb,0xfe,0xf1,0xaf,0xc6,0x78,
    0xa3,0x1d,0x66,0x44,0xed,0x35,0x61,0x44,0x7b,0x2e,
    0x8d,0xbc,0x6a,0x59,0x5d,0xa6,0x30,0x84,0xbf,0x64,
    0xf7,0x7b,0x69,0x96,0x57,0x5d,0xfd,0x34,0x38,0x41,
    0x61,0x30,0x82,0x65,0x3e,0xdb,0x1b,0xc5,0x69,0xa6,
    0x87,0xcc,0x43,0xb5,
};

const uint8_t key_1026_coefficient []={
    0x01,0x7d,0x95,0xd8,0xa6,0x3a,0xa5,0x4a,0x3d,0x23,
    0x30,0x64,0x7e,0x8f,0x15,0x70,0xe5,0x4e,0xe7,0x1f,
    0xb6,0xb3,0x6c,0x73,0x68,0xca,0x3b,0x6e,0x4d,0x81,
    0xb5,0x60,0x8d,0xdb,0x8a,0x38,0xd5,0x8d,0xf3,0xae,
    0x3e,0x11,0x00,0xd7,0xc3,0xf3,0x8d,0x3e,0xbe,0x9b,
    0x4d,0xa1,0x24,0x23,0x3a,0x79,0xf4,0xf0,0xf5,0x68,
    0xf1,0xb5,0xfb,0x63,0x56,
};

const uint8_t key_1027_prime_1[]={
    0x05,0xf6,0xb7,0xbd,0x4b,0xa9,0x62,0x61,0x49,0x43,
    0x04,0x58,0x6f,0xb0,0x82,0x3d,0x0b,0xee,0xa7,0x38,
    0x61,0xa8,0xe2,0x99,0x7e,0x43,0x4d,0x83,0x40,0x54,
    0xa8,0x99,0xf1,0xaa,0xb7,0xd5,0xe8,0x53,0x70,0x75,
    0x17,0xa4,0xbd,0x3f,0x46,0xd3,0x65,0x69,0x8e,0xa9,
    0xd3,0x24,0x3b,0x3c,0x58,0xfc,0xed,0x9d,0xe6,0xe5,
    0x7e,0x87,0xc8,0x1d,0x5d,
};

const uint8_t key_1027_prime_2[]={
    0x88,0x0e,0x76,0xfa,0x5f,0x0f,0xd4,0xe4,0x4c,0xd7,
    0x42,0x66,0xbd,0xb5,0x9e,0x90,0x65,0xca,0x5a,0x5a,
    0xca,0xcb,0xa4,0x33,0xa7,0x51,0xa3,0xdf,0x62,0x45,
    0x43,0x29,0xd4,0xc0,0x11,0x62,0xf0,0xe2,0xf4,0x7f,
    0x09,0x40,0x77,0x25,0xff,0x4b,0xe1,0xec,0x14,0x78,
    0xea,0x59,0xa8,0x76,0xd4,0xd9,0x18,0xe2,0x5d,0x48,
    0x80,0x39,0x8a,0x8d,
};

const uint8_t key_1027_modulus[]={
    0x03,0x2b,0x67,0xe0,0x2a,0x63,0xbb,0xdc,0xab,0xda,
    0x7a,0xba,0xb0,0x5e,0x73,0xb7,0x6c,0x8d,0x66,0xff,
    0x0e,0x8f,0xa5,0x83,0x0f,0xde,0xee,0x8d,0xa8,0x02,
    0x3c,0xca,0x48,0xd2,0x9e,0xac,0x4b,0x2b,0x30,0xdf,
    0x41,0xfb,0x4d,0x34,0xc4,0xad,0x97,0xfb,0xc6,0x14,
    0x71,0xff,0xe4,0xfb,0x2d,0x41,0x33,0xd5,0x34,0x0b,
    0x76,0x52,0x1a,0x61,0x8c,0x26,0x2e,0xa2,0x97,0x82,
    0xf1,0xa7,0x2d,0x8a,0x49,0xd7,0x30,0xb6,0x7d,0xe3,
    0x64,0xcc,0x95,0xd6,0x29,0x5d,0xa9,0xc1,0xb9,0xf4,
    0xff,0xae,0xe3,0xd8,0x4d,0xe6,0x63,0x02,0x80,0xc5,
    0xf1,0xf7,0xe5,0x14,0x50,0xf6,0xfc,0x90,0x88,0x03,
    0x77,0xc4,0x40,0xee,0xe0,0xc3,0x85,0x77,0xc5,0x0d,
    0x50,0x53,0xff,0xf1,0x47,0xb2,0xc1,0x4e,0x39,
};

const uint8_t key_1027_public_exponent[]={
    0x01,0x00,0x01,
};

const uint8_t key_1027_private_exponent[]={
    0x01,0x1f,0x2c,0xad,0x86,0xf3,0x33,0x7b,0x1f,0x8b,
    0xbc,0xe2,0x34,0x27,0xc9,0xb6,0xc2,0x81,0xad,0x51,
    0x5a,0x3a,0xf6,0xee,0x53,0x00,0xa8,0xd7,0x93,0xfd,
    0xee,0xbb,0xfd,0x58,0x25,0xf6,0x7e,0xc8,0x33,0x8c,
    0xe0,0xd2,0x6b,0x79,0xe0,0x9e,0x3b,0xeb,0x4d,0x28,
    0xd1,0x4c,0x2b,0x23,0xc6,0xd9,0x8b,0xd9,0xca,0x88,
    0xc0,0x00,0xc0,0xfb,0x81,0x0d,0x46,0x05,0xbd,0x6a,
    0xa8,0x8e,0x3a,0xda,0xcc,0x87,0x29,0xc0,0xe8,0xa0,
    0x3a,0x90,0x62,0xed,0x46,0x2f,0xed,0xe7,0xc5,0xdc,
    0xbe,0x5b,0x6e,0xcc,0x0d,0x2c,0x5b,0x96,0x01,0xde,
    0xa3,0x8b,0x6c,0x63,0xcb,0x78,0xa8,0x52,0x53,0x4b,
    0x49,0x03,0x57,0xc9,0xbb,0xe7,0xea,0x39,0x68,0xf8,
    0x00,0x75,0x96,0xf3,0xdd,0xf0,0x10,0xd2,0x71,
};

const uint8_t key_1027_exponent1 []={
    0x03,0xa0,0xfa,0x70,0xbe,0xc7,0x54,0xcb,0xa9,0xce,
    0x93,0xa8,0x54,0x5d,0xed,0x01,0xc4,0x6e,0xf5,0x65,
    0x83,0x57,0x46,0x7a,0xeb,0xaf,0x7c,0x4c,0xef,0x2a,
    0x14,0x65,0x87,0xfd,0xbf,0x5a,0xf3,0xc1,0x41,0xde,
    0x9e,0x02,0x69,0xfd,0x44,0xd5,0x81,0x11,0xd7,0xf3,
    0x52,0x3c,0xeb,0xa6,0x6e,0xe7,0x88,0x96,0xda,0x56,
    0xae,0xc5,0x64,0x69,0x29,
};

const uint8_t key_1027_exponent2 []={
    0x75,0x37,0xf9,0x1b,0xa6,0x71,0x0e,0x5b,0x0f,0x34,
    0xda,0x19,0x88,0x52,0x84,0x65,0x25,0xbd,0x9b,0xf0,
    0xe3,0x0d,0x65,0xcf,0xb6,0xd4,0xe8,0x99,0x99,0xa1,
    0xd0,0xc6,0xa6,0x6c,0x3f,0xce,0x7d,0x79,0x1b,0x6a,
    0xa3,0x7e,0xed,0xe8,0x47,0xb6,0x89,0xd3,0x8a,0xa3,
    0xce,0x4c,0x26,0x8f,0x12,0xbc,0x63,0xeb,0x0a,0xb1,
    0x5e,0xff,0xb4,0x35,
};

const uint8_t key_1027_coefficient []={
    0x04,0x0b,0x4e,0x71,0x30,0x9b,0xa2,0x68,0x9a,0x83,
    0xe1,0x64,0xf3,0x37,0x17,0x4d,0x5f,0xfd,0x1e,0x98,
    0xcf,0x44,0x9b,0xbc,0x49,0x67,0x93,0x1a,0x2c,0xb2,
    0x00,0x6f,0x04,0x7d,0xa0,0xc1,0x0e,0xce,0xbc,0xfb,
    0x6d,0xe8,0xd0,0x14,0xf7,0x8c,0xca,0x76,0x1e,0xa7,
    0x3f,0xf9,0xc3,0x2b,0xfa,0x10,0x0f,0x8e,0xd2,0xcc,
    0xda,0xb4,0xe2,0x48,0xb7,
};

// Define the key
#define CCRSA_TEST_KEY_GOOD                                 0
#define CCRSA_TEST_KEY_BAD_PUBLIC                           1
#define CCRSA_TEST_KEY_BAD_PRIVATE                          2
#define CCRSA_TEST_KEY_BAD_PRIVATE_PUBLIC_MISMATCH          3
#define CCRSA_TEST_KEY_P_AND_Q_GAP                          4
#define CCRSA_TEST_KEY_WRONG_INDEX                          -1
#define CCRSA_TEST_KEY_NOT_ENOUGH_MEMORY                    -2

typedef struct ccrsa_test_key_t {
    const uint8_t *modulus;
    size_t size_modulus;
    const uint32_t publicExponent;
    const uint8_t *privateExponent;
    size_t size_privateExponent;
    const uint8_t *prime1;
    size_t size_prime1;
    const uint8_t *prime2;
    size_t size_prime2;
    const uint8_t *exponent1;
    size_t size_exponent1;
    const uint8_t *exponent2;
    size_t size_exponent2;
    const uint8_t *coefficient;
    size_t size_coefficient;
    int key_type;
} ccrsa_test_key;

#define array(x) x,sizeof(x)

const uint8_t one[]={1};

const ccrsa_test_key rsa_key_list[] = {
    // ====== GOOD KEYS =======

    // 0
    {array(key_0_modulus),key_0_publicExponent,array(key_0_privateExponent),array(key_0_prime1),array(key_0_prime2),array(key_0_exponent1),array(key_0_exponent2),array(key_0_coefficient),CCRSA_TEST_KEY_GOOD},
    // 1
    {array(key_1_1024_modulus),key_1_1024_publicExponent,array(key_1_1024_privateExponent),array(key_1_1024_prime1),array(key_1_1024_prime2),array(key_1_1024_exponent1),array(key_1_1024_exponent2),array(key_1_1024_coefficient),CCRSA_TEST_KEY_GOOD},
    // 2
    {array(key_1_2048_modulus),key_1_2048_publicExponent,array(key_1_2048_privateExponent),array(key_1_2048_prime1),array(key_1_2048_prime2),array(key_1_2048_exponent1),array(key_1_2048_exponent2),array(key_1_2048_coefficient),CCRSA_TEST_KEY_GOOD},
    // 3
    {array(key_1_2048_modulus),key_1_2048_publicExponent,array(key_1_2048_privateExponent),array(key_1_2048_prime2),array(key_1_2048_prime1),array(key_1_2048_exponent2),array(key_1_2048_exponent1),array(key_1_2048_coefficient_inv),CCRSA_TEST_KEY_GOOD},

    // ====== BAD KEYS =======

    // 4 - Not supported ( size(prime1) > size(prime2))
    {array(key_1_1024_modulus),key_1_1024_publicExponent,array(key_1_1024_privateExponent),array(key_1_1024_prime2),array(key_1_1024_prime1),array(key_1_1024_exponent2),array(key_1_1024_exponent1),array(key_1_1024_coefficient_inv),CCRSA_TEST_KEY_BAD_PRIVATE},
    // 5 - Not supported ( publicExponent == 1 )
    {array(key_1_2048_modulus),1,array(key_1_2048_privateExponent),array(key_1_2048_prime1),array(key_1_2048_prime2),array(key_1_2048_exponent1),array(key_1_2048_exponent2),array(key_1_2048_coefficient),CCRSA_TEST_KEY_BAD_PUBLIC},
    // 6 - Not supported ( exponent1 == 1 )
    {array(key_1_2048_modulus),key_1_2048_publicExponent,array(key_1_2048_privateExponent),array(key_1_2048_prime1),array(key_1_2048_prime2),array(one),array(key_1_2048_exponent2),array(key_1_2048_coefficient),CCRSA_TEST_KEY_BAD_PRIVATE},
    // 7 - Not supported ( exponent2 == 1 )
    {array(key_1_2048_modulus),key_1_2048_publicExponent,array(key_1_2048_privateExponent),array(key_1_2048_prime1),array(key_1_2048_prime2),array(key_1_2048_exponent1),array(one),array(key_1_2048_coefficient),CCRSA_TEST_KEY_BAD_PRIVATE},
    // 8 - Public key does not match the private key
    {array(key_1_1024_modulus),65539,array(key_1_1024_privateExponent),array(key_1_1024_prime1),array(key_1_1024_prime2),array(key_1_1024_exponent1),array(key_1_1024_exponent2),array(key_1_1024_coefficient),CCRSA_TEST_KEY_BAD_PRIVATE_PUBLIC_MISMATCH},
};

typedef struct ccrsa_test_makekey_t {
    const uint8_t *modulus;
    size_t size_modulus;
    const uint8_t *publicExponent;
    size_t size_publicExponent;
    const uint8_t *privateExponent;
    size_t size_privateExponent;
    const uint8_t *prime1;
    size_t size_prime1;
    const uint8_t *prime2;
    size_t size_prime2;
    const uint8_t *exponent1;
    size_t size_exponent1;
    const uint8_t *exponent2;
    size_t size_exponent2;
    const uint8_t *coefficient;
    size_t size_coefficient;
    int key_type;
} ccrsa_test_makekey;

uint8_t public_e[]={0x01,0x00,0x01};
size_t public_e_length = 3;

const ccrsa_test_makekey rsa_makepriv_key_list[] = {
    // ====== GOOD KEYS =======
    
    // 0
    {array(key_0_modulus),array(public_e),array(key_0_privateExponent),array(key_0_prime1),array(key_0_prime2),array(key_0_exponent1),array(key_0_exponent2),array(key_0_coefficient),CCRSA_TEST_KEY_GOOD},
    // 1
    {array(key_1_1024_modulus),array(public_e),array(key_1_1024_privateExponent),array(key_1_1024_prime1),array(key_1_1024_prime2),array(key_1_1024_exponent1),array(key_1_1024_exponent2),array(key_1_1024_coefficient),CCRSA_TEST_KEY_GOOD},
    // 2
    {array(key_1_2048_modulus),array(public_e),array(key_1_2048_privateExponent),array(key_1_2048_prime1),array(key_1_2048_prime2),array(key_1_2048_exponent1),array(key_1_2048_exponent2),array(key_1_2048_coefficient),CCRSA_TEST_KEY_GOOD},
    // 3
    {array(key_1_2048_modulus),array(public_e),array(key_1_2048_privateExponent),array(key_1_2048_prime2),array(key_1_2048_prime1),array(key_1_2048_exponent2),array(key_1_2048_exponent1),array(key_1_2048_coefficient_inv),CCRSA_TEST_KEY_GOOD},
    
    // 4 -
    {array(key_1_1024_modulus),array(public_e),array(key_1_1024_privateExponent),array(key_1_1024_prime2),array(key_1_1024_prime1),array(key_1_1024_exponent2),array(key_1_1024_exponent1),array(key_1_1024_coefficient_inv),CCRSA_TEST_KEY_GOOD},

    // 5 -
    {array(key_1026_modulus),array(key_1026_public_exponent),array(key_1026_private_exponent),array(key_1026_prime_1),array(key_1026_prime_2),array(key_1026_exponent1),array(key_1026_exponent2),array(key_1026_coefficient),CCRSA_TEST_KEY_GOOD},

    // ====== BAD KEYS =======

    // 6 - Not supported ( publicExponent == 1 )
    {array(key_1_2048_modulus), array(one), array(key_1_2048_privateExponent),array(key_1_2048_prime1),array(key_1_2048_prime2),array(key_1_2048_exponent1),array(key_1_2048_exponent2),array(key_1_2048_coefficient),CCRSA_TEST_KEY_BAD_PUBLIC},

    // 7 - Not supported ( gap betwene P' and Q's bitlength is greater than 2)
    {array(key_1027_modulus),array(key_1027_public_exponent),array(key_1027_private_exponent),array(key_1027_prime_1),array(key_1027_prime_2),array(key_1027_exponent1),array(key_1027_exponent2),array(key_1027_coefficient), CCRSA_TEST_KEY_P_AND_Q_GAP},

};


// Initialize a fullkey structure "fullkey" from the key at "index" in "rsa_key_list"
static int ccrsa_test_setkey(ccrsa_full_ctx_t fk, size_t fk_bit_size, size_t index) {

    if (index >= CC_ARRAY_LEN(rsa_key_list)) return CCRSA_TEST_KEY_WRONG_INDEX;

    cc_size n = ccn_nof_size(rsa_key_list[index].size_modulus);
    cc_unit tmp_u[n];
    ccn_read_uint(n,tmp_u,rsa_key_list[index].size_modulus,rsa_key_list[index].modulus);

    if (n>ccn_nof(fk_bit_size)) return CCRSA_TEST_KEY_NOT_ENOUGH_MEMORY; // Full key is too small for this key

    ccrsa_ctx_n(fk) = n;
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);

    // p
    ccn_read_uint(n,tmp_u,rsa_key_list[index].size_prime1,rsa_key_list[index].prime1);
    CCZP_N(ccrsa_ctx_private_zp(fk)) = ccn_n(n,tmp_u);

    // q
    ccn_read_uint(n,tmp_u,rsa_key_list[index].size_prime2,rsa_key_list[index].prime2);
    CCZP_N(ccrsa_ctx_private_zq(fk)) = ccn_n(n,tmp_u);

    // Rest of it
    ccn_seti(n, ccrsa_ctx_e(pubk), rsa_key_list[index].publicExponent);
    ccn_read_uint(n,CCZP_PRIME(ccrsa_ctx_zm(pubk)),rsa_key_list[index].size_modulus,rsa_key_list[index].modulus);
    ccn_read_uint(n,ccrsa_ctx_d(fk),rsa_key_list[index].size_privateExponent,rsa_key_list[index].privateExponent);
    ccn_read_uint(cczp_n(ccrsa_ctx_private_zp(fk)),CCZP_PRIME(ccrsa_ctx_private_zp(fk)),rsa_key_list[index].size_prime1,rsa_key_list[index].prime1);
    ccn_read_uint(cczp_n(ccrsa_ctx_private_zp(fk)),ccrsa_ctx_private_dp(fk),rsa_key_list[index].size_exponent1,rsa_key_list[index].exponent1);
    ccn_read_uint(cczp_n(ccrsa_ctx_private_zq(fk)),CCZP_PRIME(ccrsa_ctx_private_zq(fk)),rsa_key_list[index].size_prime2,rsa_key_list[index].prime2);
    ccn_read_uint(cczp_n(ccrsa_ctx_private_zq(fk)),ccrsa_ctx_private_dq(fk),rsa_key_list[index].size_exponent2,rsa_key_list[index].exponent2);
    ccn_read_uint(cczp_n(ccrsa_ctx_private_zp(fk)),ccrsa_ctx_private_qinv(fk),rsa_key_list[index].size_coefficient,rsa_key_list[index].coefficient);

    // Perform initialization
    is(cczp_init(ccrsa_ctx_private_zp(fk)), CCERR_OK, "cczp_init() failed");
    is(cczp_init(ccrsa_ctx_private_zq(fk)), CCERR_OK, "cczp_init() failed");
    is(cczp_init(ccrsa_ctx_zm(pubk)), CCERR_OK, "cczp_init() failed, index=%zu", index);

    return rsa_key_list[index].key_type;
}

//==============================================================================
//  Keys
//==============================================================================

#define RSA_MAX_BIT_SIZE 4096
static int
test_sample_pkcs1v15(void)
{
    byteBuffer digest=hexStringToBytes("2812fd163b700eaad52a82c2d330eb1d2b23c1db");
    byteBuffer nullOIDdigest=hexStringToBytes("3021300906052b0e03021a050004142812fd163b700eaad52a82c2d330eb1d2b23c1db");
    uint8_t fault_canary[sizeof(CCRSA_PKCS1_FAULT_CANARY)];
    const unsigned char *oid=CC_DIGEST_OID_SHA1;
    uint32_t status=0,test_step=0;
    byteBuffer encoded_message=hexStringToBytes("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a050004142812fd163b700eaad52a82c2d330eb1d2b23c1db");

    byteBuffer expected_sig=hexStringToBytes("203b16fdecf3989a60d161914b60c0459ff3f4925ca1298c1514f97a12086214647e7ff1162ea1b22e1a0133a60fcd9a6bd2efc91de7561c6c67e7b9f1b945cf51242c4169d84c29a1231decf292fe44b972090ebb057a10425f26962e755d76bee595e803d8f79b423af780a97b9d149f84d24a6623642e16ae013ec78f10c6");

    ccrsa_full_ctx_decl_nbits(RSA_MAX_BIT_SIZE, fk);
    int rc = ccrsa_test_setkey(fk,RSA_MAX_BIT_SIZE,1); ok(rc==CCRSA_TEST_KEY_GOOD,"Initialize key");
    if(rc!=CCRSA_TEST_KEY_GOOD){
        free(expected_sig);
        free(encoded_message);
        free(digest);
        return -1;
    }

    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
    cc_size n = ccrsa_ctx_n(fk);
    cc_unit tmp_u[n];
    uint8_t result[ccn_sizeof_n(n)];
    bool valid;

    // Convert in uint
    ccn_zero(n, tmp_u);
    ccn_read_uint(n,tmp_u,encoded_message->len,encoded_message->bytes);

    //==========================================================================
    //  KAT for ccrsa_verify_pkcs1v15
    //==========================================================================
    // "Sign"
    CC_DECL_WORKSPACE_TEST(ws);
    if (0==ccrsa_priv_crypt_blinded_ws(ws, global_test_rng, fk, tmp_u, tmp_u)) status|=1<<test_step;
    CC_FREE_WORKSPACE(ws);
    test_step++;

    // Export as byte array
    ccn_write_uint_padded_ct(n, tmp_u, expected_sig->len, result);
    if (0==memcmp(result,expected_sig->bytes,expected_sig->len)) status|=1<<test_step;
    test_step++;

    // With OID
    if (0==ccrsa_verify_pkcs1v15(pubk, oid,
                                 digest->len, digest->bytes,
                                 expected_sig->len,expected_sig->bytes,
                                 &valid) && (valid==true)) {
        status|=1<<test_step;
    }
    test_step++;
    
    if (ccrsa_verify_pkcs1v15_digest(pubk, oid, digest->len, digest->bytes, expected_sig->len, expected_sig->bytes, NULL) == CCERR_VALID_SIGNATURE) {
        status |= 1 << test_step;
    }
    test_step++;
    
    if (ccrsa_verify_pkcs1v15_digest(pubk, oid, digest->len, digest->bytes, expected_sig->len, expected_sig->bytes, fault_canary) == CCERR_VALID_SIGNATURE) {
        status |= 1 << test_step;
    }
    test_step++;
    
    if (memcmp(CCRSA_PKCS1_FAULT_CANARY, fault_canary, sizeof(CCRSA_PKCS1_FAULT_CANARY)) == 0) {
        status |= 1 << test_step;
    }
    test_step++;

    // Without OID
    if (0==ccrsa_verify_pkcs1v15(pubk, NULL,
                                 nullOIDdigest->len, nullOIDdigest->bytes,
                                 expected_sig->len,expected_sig->bytes,
                                 &valid) && (valid==true)) status|=1<<test_step;
    test_step++;

    //==========================================================================
    //  KAT for ccrsa_sign_pkcs1v15
    //==========================================================================
    size_t result_size;

    // With OID
    result_size=sizeof(result);
    if (0==ccrsa_sign_pkcs1v15_blinded(global_test_rng, fk, oid,
                               digest->len, digest->bytes,
                               &result_size,result)) status|=1<<test_step;
    test_step++;
    if ((result_size==expected_sig->len) &&
        (0==memcmp(result,expected_sig->bytes,expected_sig->len))) status|=1<<test_step;
    test_step++;
    
    // Without OID
    result_size=sizeof(result);
    if (0==ccrsa_sign_pkcs1v15_blinded(global_test_rng, fk, NULL,
                               nullOIDdigest->len, nullOIDdigest->bytes,
                               &result_size,result)) status|=1<<test_step;
    test_step++;
    if ((result_size==expected_sig->len) &&
        0==memcmp(result,expected_sig->bytes,expected_sig->len)) status|=1<<test_step;
    test_step++;

    //==========================================================================

    free(expected_sig);
    free(encoded_message);
    free(digest);
    free(nullOIDdigest);

    ccrsa_full_ctx_clear_nbits(RSA_MAX_BIT_SIZE, fk);
    // Check the final status
    if (((1<<test_step)-1) == status)
    {
        return 0;
    }
    return -1;
}


static int
test_rsa_roundtrip(ccrsa_full_ctx_t fk, int test_all_algos)
{
    int status = 1;
    struct ccrng_state *rng = global_test_rng;

    ok((status = check_sane_key_nbits(fk, 1)) == 0, "key_nbits is realistic");
    ok((status = check_sane_key_nbits(fk, 0)) == 0, "key_nbits is realistic");
    ok((status = crypt_decrypt(fk)) == 0, "Can perform round-trip encryption");
    ok((status = sign_verify(fk, PADDING_PKCS1, rng, ccsha1_di())) == 0, "Can perform round-trip PKCS1Padding-SHA1 sign/verify");
    if (test_all_algos==TEST_ALL_ALGOS) {
        ok((status = pkcs1v15_encrypt_error_test(fk)) == 0, "Can check invalid PKCS1 v1.5 encryption");
        ok((status = oaep_decrypt_error_test(fk)) == 0, "Can check invalid ciphertext OAEP padding");
        ok((status = pkcs1v15_decrypt_error_test(fk)) == 0, "Can check invalid ciphertext PKCS1 v1.5 padding");
        ok((status = pkcs1v15_decode_length_test(fk, rng)) == 0, "Can decode invalid PKCS1 v1.5 padding to valid message lengths");
        ok((status = wrap_unwrap(fk, PADDING_PKCS1, rng)) == 0, "Can perform round-trip PKCS1 wrap/unwrap");
        ok((status = wrap_unwrap(fk, PADDING_OAEP, rng)) == 0, "Can perform round-trip OAEP wrap/unwrap");
        ok((status = sign_verify(fk, PADDING_PKCS1, rng, ccsha256_di())) == 0, "Can perform round-trip PKCS1Padding-SHA256 sign/verify");
        ok((status = sign_verify(fk, PADDING_PKCS1_NO_OID, rng, ccsha1_di())) == 0, "Can perform round-trip PKCS1Padding sign/verify");
        ok((status = sign_verify(fk, PADDING_PSS, rng, ccsha1_di())) == 0, "Can perform round-trip PSS sign/verify");
        ok((status = export_import(fk)) == 0, "Can perform round-trip import/export");
    }
    return status;
}

static int test_rsa_keys(void)
{
    size_t key_nbits = 2048 + 8;
    ccrsa_full_ctx_decl_nbits(key_nbits, full_key);
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();
    ccrsa_pub_ctx_t pub_key;
    size_t modulus_size;
    size_t output_size;
    bool valid;
    int key_type;
    size_t i = 0;
    const int verbose = 0;
    while ((key_type = ccrsa_test_setkey(full_key, key_nbits, i++)) >= 0) {
        int expected_result = 0;
        cc_unit unit_tmp[ccn_nof(key_nbits)];
        uint8_t *byte_tmp = (uint8_t *)unit_tmp;

        ccn_seti(ccn_nof(key_nbits), unit_tmp, 2);
        // ccrsa_dump_full_key(full_key);
        modulus_size = CC_BITLEN_TO_BYTELEN(ccrsa_pubkeylength(ccrsa_ctx_public(full_key)));
        output_size = modulus_size;
        pub_key = ccrsa_ctx_public(full_key);
        if (verbose)
            diag("Testing key %d, %s (%d)", i - 1, (key_type > 0) ? "Invalid key, expect assert" : "valid", key_type);
        switch (key_type) {
            case CCRSA_TEST_KEY_GOOD:
                // =============================================================
                // Good key, test all round trips
                // =============================================================
                for (int j = 0; j < RSA_KNOWN_KEY_STRESS; j++)
                    test_rsa_roundtrip(full_key, TEST_KEY_SANITY);
                break;
            case CCRSA_TEST_KEY_BAD_PUBLIC:
                // =============================================================
                // Test that public key operations fail as expected
                // =============================================================
                // Encryptions
                is(ccrsa_pub_crypt(pub_key, unit_tmp, unit_tmp), CCRSA_KEY_ERROR, "Key ok");
                is(ccrsa_encrypt_eme_pkcs1v15(pub_key, rng, &output_size, byte_tmp, modulus_size - 16, byte_tmp),
                   CCRSA_KEY_ERROR,
                   "Key ok");
                output_size = modulus_size;
                is(ccrsa_encrypt_oaep(
                                      pub_key, di, rng, &output_size, byte_tmp, modulus_size - (2 * di->output_size + 2), byte_tmp, 0, NULL),
                   CCRSA_KEY_ERROR,
                   "Key ok");

                // Verifications
                valid = true;
                is(ccrsa_verify_pkcs1v15(pub_key, di->oid, di->output_size, byte_tmp, modulus_size, byte_tmp, &valid),
                   CCRSA_KEY_ERROR,
                   "Key ok");
                is(valid, false, "Fail close");

                is(ccrsa_verify_pss_digest(pub_key, di, di, di->output_size, byte_tmp, modulus_size, byte_tmp, 20, NULL),
                   CCRSA_KEY_ERROR,
                   "Key ok");
                break;
            case CCRSA_TEST_KEY_BAD_PRIVATE:
                expected_result = CCRSA_KEY_ERROR;
            case CCRSA_TEST_KEY_BAD_PRIVATE_PUBLIC_MISMATCH:
                if (expected_result == 0) {
                    expected_result = CCRSA_PRIVATE_OP_ERROR;
                }
                // =============================================================
                // Test that private key operations fail as expected
                // =============================================================
                // Decryptions
                CC_DECL_WORKSPACE_TEST(ws);
                is(ccrsa_priv_crypt_blinded_ws(ws, rng, full_key, unit_tmp, unit_tmp), expected_result, "Key ok");
                is(ccrsa_decrypt_eme_pkcs1v15_blinded_ws(ws, rng, full_key, &output_size, byte_tmp, modulus_size, byte_tmp),
                   expected_result,
                   "Key ok");
                output_size = modulus_size;

                is(ccrsa_decrypt_oaep_blinded_ws(ws, rng, full_key, di, &output_size, byte_tmp, modulus_size, byte_tmp, 0, NULL),
                   expected_result,
                   "Key ok");
                CC_FREE_WORKSPACE(ws);

                // Signature
                is(ccrsa_sign_pkcs1v15_blinded(rng, full_key, di->oid, di->output_size, byte_tmp, &modulus_size, byte_tmp),
                   expected_result,
                   "Key ok");
                is(ccrsa_sign_pss_blinded(rng, full_key, di, di, 20, rng, di->output_size, byte_tmp, &modulus_size, byte_tmp),
                   expected_result,
                   "Key ok");

                break;
            default:
                // =============================================================
                // Unexpected error
                // =============================================================
                fail("Unexpected key setup error");
                break;
        }
    }
    is(key_type, CCRSA_TEST_KEY_WRONG_INDEX, "Expected termination");
    ccrsa_full_ctx_clear_nbits(key_nbits, full_key);
    return 0;
}

// return 0 iff success
static int
RSAStd_Gen_Test(size_t key_nbits, uint32_t exponent)
{
#if CC_DISABLE_RSAKEYGEN
    (void) key_nbits;
    (void) exponent;
    return 0;
#else
    ccrsa_full_ctx_decl_nbits(key_nbits, full_key);
    uint8_t e4[4];
    for(int i=0; i<4; i++) e4[3-i] = ((exponent >> (i*8)) & 0x000000ff);
    int status = 1;

    struct ccrng_state *rng = global_test_rng;
    is(ccrsa_generate_key(key_nbits, full_key, 4, e4, rng), 0, "RSA Key generation");
    is(ccn_bitlen(ccrsa_ctx_n(full_key),ccrsa_ctx_m(full_key)),key_nbits, "RSA expected key_nbits");
    is((status = test_rsa_roundtrip(full_key,TEST_KEY_SANITY)), 0, "RSA Round-Trip Key Tests");
    ccrsa_full_ctx_clear_nbits(key_nbits, full_key);
    return status;
#endif
}

// Test ccrsa_make_priv using data from "rsa_key_list"
static int ccrsa_test_make_priv(void)
{
    // rsa_makepriv_key_list contains a number of keys we can test against. Iterate through them
    // load each key using ccrsa_make_priv, and ensure that the resulting key or error is as expected.
    for (size_t i = 0; i < CC_ARRAY_LEN(rsa_makepriv_key_list); i++) {
        cc_size key_nbits = 2048 + 8;                           // Largest key size we care about
        ccrsa_full_ctx_decl_nbits(key_nbits, full_context); // create context to give make_priv
        ccrsa_full_ctx_decl_nbits(key_nbits, fk);           // create context to hold test data.
        
        // Retrieve the size of the modulus we're using.
        cc_size n = ccn_nof_size(rsa_makepriv_key_list[i].size_modulus);
        if (n > ccn_nof(key_nbits))
            return CCRSA_TEST_KEY_NOT_ENOUGH_MEMORY;
        
        // create space to hold the modulus; retrieve its length and later compare that we compute correct value.
        cc_unit tmp_u[n];
        ccn_read_uint(n, tmp_u, rsa_makepriv_key_list[i].size_modulus, rsa_makepriv_key_list[i].modulus);
        
        // Initialize context with appropriate modulus size
        ccrsa_ctx_n(fk) = n;
        ccrsa_ctx_n(full_context) = n;
        ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
        
        // Get the lengths of p and q, so we can get the accessor functions properly setup
        // so we can load appropraite values later.
        // p
        ccn_read_uint(n, tmp_u, rsa_makepriv_key_list[i].size_prime1, rsa_makepriv_key_list[i].prime1);
        CCZP_N(ccrsa_ctx_private_zp(fk)) = ccn_n(n, tmp_u);
        
        // q  (Note: ccrsa_ctx_private_zq must be called after the length of ccrsa_ctx_private_zp->n has been set)
        ccn_read_uint(n, tmp_u, rsa_makepriv_key_list[i].size_prime2, rsa_makepriv_key_list[i].prime2);
        CCZP_N(ccrsa_ctx_private_zq(fk)) = ccn_n(n, tmp_u);
        
        // Rest of it
        ccn_read_uint(
                      n, ccrsa_ctx_e(pubk), rsa_makepriv_key_list[i].size_publicExponent, rsa_makepriv_key_list[i].publicExponent);
        ccn_read_uint(n, CCZP_PRIME(ccrsa_ctx_zm(pubk)), rsa_makepriv_key_list[i].size_modulus, rsa_makepriv_key_list[i].modulus);
        ccn_read_uint(
                      n, ccrsa_ctx_d(fk), rsa_makepriv_key_list[i].size_privateExponent, rsa_makepriv_key_list[i].privateExponent);
        ccn_read_uint(cczp_n(ccrsa_ctx_private_zp(fk)),
                      CCZP_PRIME(ccrsa_ctx_private_zp(fk)),
                      rsa_makepriv_key_list[i].size_prime1,
                      rsa_makepriv_key_list[i].prime1);
        ccn_read_uint(cczp_n(ccrsa_ctx_private_zp(fk)),
                      ccrsa_ctx_private_dp(fk),
                      rsa_makepriv_key_list[i].size_exponent1,
                      rsa_makepriv_key_list[i].exponent1);
        ccn_read_uint(cczp_n(ccrsa_ctx_private_zq(fk)),
                      CCZP_PRIME(ccrsa_ctx_private_zq(fk)),
                      rsa_makepriv_key_list[i].size_prime2,
                      rsa_makepriv_key_list[i].prime2);
        ccn_read_uint(cczp_n(ccrsa_ctx_private_zq(fk)),
                      ccrsa_ctx_private_dq(fk),
                      rsa_makepriv_key_list[i].size_exponent2,
                      rsa_makepriv_key_list[i].exponent2);
        ccn_read_uint(cczp_n(ccrsa_ctx_private_zp(fk)),
                      ccrsa_ctx_private_qinv(fk),
                      rsa_makepriv_key_list[i].size_coefficient,
                      rsa_makepriv_key_list[i].coefficient);
        
        // Now make another ccrsa_full_context by passing the e, p and q; N, d, dp and dq should self-generate via ccrsa_make_priv
        int result_of_make_priv;
        result_of_make_priv = ccrsa_make_priv(full_context,
                                              rsa_makepriv_key_list[i].size_publicExponent,
                                              rsa_makepriv_key_list[i].publicExponent,
                                              rsa_makepriv_key_list[i].size_prime1,
                                              rsa_makepriv_key_list[i].prime1,
                                              rsa_makepriv_key_list[i].size_prime2,
                                              rsa_makepriv_key_list[i].prime2);
        
        // Make sure everything went as expected.
        switch (rsa_makepriv_key_list[i].key_type) {
                // case where key generation should have gone smoothly
            case CCRSA_TEST_KEY_GOOD:
                is(result_of_make_priv, 0, "Failed in call ccrsa_make_priv in ccrsa_test_make_priv on a good key");
                ok_memcmp(ccrsa_ctx_e(fk),
                          ccrsa_ctx_e(full_context),
                          CCN_UNIT_SIZE * cczp_n(ccrsa_ctx_zm(fk)),
                          "Comparing given vs computed e in ccrsa_test_make_priv on rsa_makepriv_key_list[%d]",
                          i);
                ok_memcmp(ccrsa_ctx_d(fk),
                          ccrsa_ctx_d(full_context),
                          CCN_UNIT_SIZE * ccrsa_ctx_zm(fk)->n,
                          "Comparing given vs computed d in ccrsa_test_make_priv on rsa_makepriv_key_list[%d]",
                          i);
                ok_memcmp(ccrsa_ctx_zm(fk)->ccn,
                          ccrsa_ctx_zm(full_context)->ccn,
                          CCN_UNIT_SIZE * ccrsa_ctx_zm(fk)->n,
                          "Comparing given vs computed zm in ccrsa_test_make_priv on rsa_makepriv_key_list[%d]",
                          i);
                
                // Because ccrsa_make_priv will switch ordering of p and q if needed, we need to switch the order of the test cases
                // for comparison. if q > p in the original test vector, we re-read it into the comparison context with their orders
                // reverse.
                int swap_pq = 0; // Since ccrsa_make_priv takes p and q
                if (ccn_cmpn(ccn_n(ccrsa_ctx_private_zp(fk)->n, ccrsa_ctx_private_zp(fk)->ccn),
                             ccrsa_ctx_private_zp(fk)->ccn,
                             ccn_n(ccrsa_ctx_private_zq(fk)->n, ccrsa_ctx_private_zq(fk)->ccn),
                             ccrsa_ctx_private_zq(fk)->ccn) < 0) {
                    swap_pq = 1; // Set swap flag to 1, to help with debugging.
                    cc_size swap_p_size = CCZP_N(ccrsa_ctx_private_zp(fk));
                    CCZP_N(ccrsa_ctx_private_zp(fk)) = CCZP_N(ccrsa_ctx_private_zq(fk));
                    CCZP_N(ccrsa_ctx_private_zq(fk)) = swap_p_size;
                    
                    ccn_read_uint(cczp_n(ccrsa_ctx_private_zp(fk)),
                                  CCZP_PRIME(ccrsa_ctx_private_zp(fk)),
                                  rsa_makepriv_key_list[i].size_prime2,
                                  rsa_makepriv_key_list[i].prime2);
                    ccn_read_uint(cczp_n(ccrsa_ctx_private_zp(fk)),
                                  ccrsa_ctx_private_dp(fk),
                                  rsa_makepriv_key_list[i].size_exponent2,
                                  rsa_makepriv_key_list[i].exponent2);
                    ccn_read_uint(cczp_n(ccrsa_ctx_private_zq(fk)),
                                  CCZP_PRIME(ccrsa_ctx_private_zq(fk)),
                                  rsa_makepriv_key_list[i].size_prime1,
                                  rsa_makepriv_key_list[i].prime1);
                    ccn_read_uint(cczp_n(ccrsa_ctx_private_zq(fk)),
                                  ccrsa_ctx_private_dq(fk),
                                  rsa_makepriv_key_list[i].size_exponent1,
                                  rsa_makepriv_key_list[i].exponent1);
                }
                ok_memcmp(ccrsa_ctx_private_zp(fk)->ccn,
                          ccrsa_ctx_private_zp(full_context)->ccn,
                          CCN_UNIT_SIZE * cczp_n(ccrsa_ctx_private_zp(fk)),
                          "Comparing given vs computed zp in ccrsa_test_make_priv in rsa_makepriv_key_list[%d].prime1. Value of "
                          "swap_pq is %d",
                          i,
                          swap_pq);
                ok_memcmp(ccrsa_ctx_private_zq(fk)->ccn,
                          ccrsa_ctx_private_zq(full_context)->ccn,
                          CCN_UNIT_SIZE * cczp_n(ccrsa_ctx_private_zq(fk)),
                          "Comparing given vs computed zq in ccrsa_test_make_priv in rsa_makepriv_key_list[%d].prime2. Value of "
                          "swap_pq is %d",
                          i,
                          swap_pq);
                ok_memcmp(ccrsa_ctx_private_dp(fk),
                          ccrsa_ctx_private_dp(full_context),
                          CCN_UNIT_SIZE * cczp_n(ccrsa_ctx_private_zq(fk)),
                          "Comparing given vs computed dp in ccrsa_test_make_priv.  Value of swap_pq is %d",
                          i,
                          swap_pq);
                ok_memcmp(ccrsa_ctx_private_dq(fk),
                          ccrsa_ctx_private_dq(full_context),
                          CCN_UNIT_SIZE * cczp_n(ccrsa_ctx_private_zq(fk)),
                          "Comparing given vs computed dq in ccrsa_test_make_priv.  Value of swap_pq is %d",
                          i,
                          swap_pq);
                
                // Perform a full test of the generated context, to make sure it works as expected.
                test_rsa_roundtrip(full_context, TEST_ALL_ALGOS);
                break;
            case CCRSA_TEST_KEY_P_AND_Q_GAP:
                is(result_of_make_priv,
                   CCRSA_KEYGEN_PQ_DELTA_ERROR,
                   "Accepeted as a good key a known bad key in rsa_makepriv_key_list[%zu]",
                   i);
                break;
            default:
                is(result_of_make_priv,
                   CCRSA_INVALID_INPUT,
                   "Accepeted as a good key a known bad key in rsa_makepriv_key_list[%zu]",
                   i);
                break;
        }
        ccrsa_full_ctx_clear_nbits(key_nbits, full_context);
        ccrsa_full_ctx_clear_nbits(key_nbits, fk);
    }
    return 0;
}

/* Generation of random keys */
// return 0 iff success
static int
RSAFIPS_Gen_Test(size_t key_nbits, uint32_t exponent)
{
	cc_assert(key_nbits <= 4096); //for Windows debugging
    ccrsa_full_ctx_decl_nbits(key_nbits, full_key);
	cc_assert(full_key != NULL);//for Windows debugging
    uint8_t e4[4];
    for(int i=0; i<4; i++) e4[3-i] = ((exponent >> (i*8)) & 0x000000ff);
    int status = 1;
    struct ccrng_state *rng = global_test_rng;
    is((status = ccrsa_generate_fips186_key(key_nbits, full_key, 4, e4, rng, rng)),0, "RSA FIPS Key generation");
    if (status) return 1;
    is(ccn_bitlen(ccrsa_ctx_n(full_key),ccrsa_ctx_m(full_key)),key_nbits, "RSA FIPS expected key_nbits");
    is((status = test_rsa_roundtrip(full_key,TEST_ALL_ALGOS)),0, "RSA FIPS Round-Trip Key Tests");
    ccrsa_full_ctx_clear_nbits(key_nbits, full_key);
    return status;
}

/* Known Answer Tests */
static int
RSAFIPS_Gen_KAT_Test(  char *estr,
                   char *xp1str, char *xp2str, char *xpstr,
                   char *xq1str, char *xq2str, char *xqstr,
                   char *pstr, char *qstr, char *mstr, char *dstr, bool withTrace)
{
    byteBuffer e = hexStringToBytes(estr);
    ccnBuffer xp1 = hexStringToCcn(xp1str);
    ccnBuffer xp2 = hexStringToCcn(xp2str);
    ccnBuffer xp = hexStringToCcn(xpstr);
    ccnBuffer xq1 = hexStringToCcn(xq1str);
    ccnBuffer xq2 = hexStringToCcn(xq2str);
    ccnBuffer xq = hexStringToCcn(xqstr);
    ccnBuffer expectedP = hexStringToCcn(pstr);
    ccnBuffer expectedQ = hexStringToCcn(qstr);
    ccnBuffer expectedM = hexStringToCcn(mstr);
    ccnBuffer expectedD = hexStringToCcn(dstr);
    int success = 1;
    cc_size nbits = ccn_bitlen(expectedM->len, expectedM->units);
    cc_size n = ccn_sizeof(nbits);

    ccrsa_full_ctx_decl_n(n, full_key);

    struct ccrng_rsafips_test_state rng1;
    struct ccrng_rsafips_test_state rng2;

    // Rngs
    ccrng_rsafips_test_init(&rng1,xp1->len,xp1->units,xp2->len,xp2->units,xp->len,xp->units);
    ccrng_rsafips_test_init(&rng2,xq1->len,xq1->units,xq2->len,xq2->units, xq->len, xq->units);
    ccrng_rsafips_test_set_next(&rng1, &rng2);

    // Computations
    if (withTrace) {
        struct ccrsa_fips186_trace trace[CCRSA_FIPS186_TRACE_NUM];
        success&=ok((ccrsa_generate_fips186_key_trace(nbits, full_key, e->len, e->bytes,
                                   (struct ccrng_state *)&rng1,
                                   global_test_rng,&trace[0])==0), "RSA FIPS Key generation with trace");
        // Check that the trace is initialized as expected
        success&=ok_ccn_cmp(expectedP->len,trace[1].p, expectedP->units, "trace p is set correctly");
        success&=ok_ccn_cmp(expectedQ->len,trace[0].p, expectedQ->units, "trace q is set correctly");
    }
    else {
        success&=ok((ccrsa_generate_fips186_key(nbits, full_key, e->len, e->bytes,
                                   (struct ccrng_state *)&rng1,
                                   global_test_rng)==0), "RSA FIPS Key generation");
    }
    success&=ok((ccn_bitlen(ccrsa_ctx_n(full_key),ccrsa_ctx_m(full_key))==nbits), "RSA FIPS expected key_nbits");

    /*
     if ( (ccn_cmp(expectedQ->len,cczp_prime((((full_key)).zp)), expectedQ->units)==0)
     && (ccn_cmp(expectedP->len,cczp_prime(((cczp_t)(((full_key)).zp.zp->ccn + 2 * (((full_key)).zp).zp->n + 1))), expectedP->units)==0)) {
     printf("Swapped P and Q\n");
     }
     */
    // Verify results
    if (  (ccn_cmp(expectedQ->len,cczp_prime(ccrsa_ctx_private_zp(full_key)), expectedQ->units)==0)
       && (ccn_cmp(expectedP->len,cczp_prime(ccrsa_ctx_private_zq(full_key)), expectedP->units)==0)) {
        printf("Swapped P and Q\n");
    }

    success&=ok_ccn_cmp(expectedP->len,cczp_prime(ccrsa_ctx_private_zp(full_key)), expectedP->units, "p is built correctly");
    success&=ok_ccn_cmp(expectedQ->len,cczp_prime(ccrsa_ctx_private_zq(full_key)), expectedQ->units, "q is built correctly");
    success&=ok_ccn_cmp(expectedD->len,ccrsa_ctx_d(full_key), expectedD->units, "d is built correctly");
    success&=ok_ccn_cmp(expectedM->len,ccrsa_ctx_m(full_key), expectedM->units, "m is built correctly");

    if (!success) goto errout; // Skip roundtrip if make failed

    success&=is(test_rsa_roundtrip(full_key,TEST_ALL_ALGOS),0, "RSA Round-Trip Key Tests");
errout:
    free(e);free(xp1); free(xp2); free(xp); free(xq1); free(xq2); free(xq);
    free(expectedP); free(expectedQ); free(expectedM); free(expectedD);
    ccrsa_full_ctx_clear_n(n, full_key);
    if (success) return 0;
    return 1;         // Error
}

/* Negative tests */
static int
RSAFIPS_Negative_Test(void)
{
    cc_size key_nbits=2048;
    ccrsa_full_ctx_decl_nbits(key_nbits, full_key);
    uint8_t e1[4]={0,0,0,1};
    uint8_t e_even[4]={0,1,0,2};
    uint8_t e_small[4]={0,0,0xff,0xff}; // 2^16-1
    uint8_t e_large[33]={1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}; // 2^256+1
    uint8_t e65537[4]={0,1,0,1};
    uint8_t seq[3]={0x00,0xff,0xba};
    struct ccrng_sequence_state rng_seq;
    struct ccrng_rsafips_test_state rng1;
    struct ccrng_rsafips_test_state rng2;

    struct ccrng_state *trng=global_test_rng;

    // The key_nbits for generation is smaller than the required size
    ok((ccrsa_generate_fips186_key(511, full_key, 4, e65537,
                                   trng,
                                   trng)!=0), "Fail for small size");
    
    // The key_nbits for generation is larger than the allowed size
    ok((ccrsa_generate_fips186_key(8193, full_key, 4, e65537,
                                   trng,
                                   trng)!=0), "Fail for large size");

    // Exponent is one while it must be >1
    ok((ccrsa_generate_fips186_key(key_nbits, full_key, 4, e1,
                                   trng,
                                   trng)!=0), "Fail for exponent=1");

    // Exponent is one while it must be >1
    ok((ccrsa_generate_key(key_nbits, full_key, 4, e1, trng)!=0), "Fail for exponent=1");

    // Exponent is one while it must be >2^16
    ok((ccrsa_generate_fips186_key(key_nbits, full_key, sizeof(e_small), e_small,
                                   trng,
                                   trng)!=0), "Fail for small exponent size");

    // Exponent is one while it must be <2^256
    ok((ccrsa_generate_fips186_key(key_nbits, full_key, sizeof(e_large), e_large,
                                   trng,
                                   trng)!=0), "Fail for large exponent size");

    // Exponent is even while it must be odd
    ok((ccrsa_generate_fips186_key(key_nbits, full_key, 4, e_even,
                    trng,
                    trng)!=0), "Fail for even exponent");

    // Exponent is even while it must be odd
    ok((ccrsa_generate_key(key_nbits, full_key, 4, e_even, trng)!=0), "Fail for even exponent");

    // Rng fails
    ccrng_sequence_init(&rng_seq, 0, NULL);
    ok((ccrsa_generate_fips186_key(key_nbits, full_key, 4, e65537,
                    (struct ccrng_state *)&rng_seq,
                    trng)!=0), "Fail for bad RNG P");

    // Rng single values
    ccrng_sequence_init(&rng_seq, 1, &seq[0]);
    ok((ccrsa_generate_fips186_key(key_nbits, full_key, 4, e65537,
                                   (struct ccrng_state *)&rng_seq,
                                   trng)!=0), "RNG returns all 0x00");
    ccrng_sequence_init(&rng_seq, 1, &seq[1]);
    ok((ccrsa_generate_fips186_key(key_nbits, full_key, 4, e65537,
                                   (struct ccrng_state *)&rng_seq,
                                   trng)!=0), "RNG returns all 0xff");

    // Check identical P&Q are rejected
    ccrng_sequence_init(&rng_seq, 1, &seq[2]);
    ok((ccrsa_generate_fips186_key(key_nbits, full_key, 4, e65537,
                                   (struct ccrng_state *)&rng_seq,
                                   trng)!=0), "P&Q are seeded with 0xba");


    // P&Q and Xp,Xq delta too small, using a 2048 key.
    {
        //cc_size n=ccn_nof(nbits);
        ccnBuffer ccn_xp1 = hexStringToCcn("1747cbbd8b16c4dbc259e53b8a5c7db1b9f5");
        ccnBuffer ccn_xp2 = hexStringToCcn("18946d3a6f5e3e088446dd0e04aa62bc87e8");
        ccnBuffer ccn_xp = hexStringToCcn("6fccd146d52a5b4adda4a45a45f2eabb41da13fe6de477dad87d361d69c2cbb79640e76ac7c28abbce096dbf2e638b2053fc39c503bfcdc64d0ae2d7d818bb984896f115a76a8edad23e996b536856f808c717999dbb3955c4213b001a6d9722ce8d69e6b57e103a2f24765da3a2a413254b0c388172ad2f2cd623a9ce296c99");
        cc_unit xq1[ccn_xp1->len];
        cc_unit xq2[ccn_xp2->len];
        cc_unit xq[ccn_xp->len];
        cc_unit tmp[ccn_xp->len];

        // |Xp-Xq|=2^(nbits/2-100) => fail
        // 2.q1.q2 > 2.r1.r2 so that |p-q|>2^(nbits/2-100)
        ccn_zero(ccn_xp->len,tmp);
        ccn_set_bit(tmp,((key_nbits/2)-100),1);
        ccn_add(ccn_xp->len,xq,ccn_xp->units,tmp);
        ccn_set(ccn_xp1->len,xq1,ccn_xp1->units);        // xq1=xp1
        ccn_add1(ccn_xp2->len,xq2,ccn_xp2->units,((cc_unit)1)<<31); // xq2=xp1+2^31
        ccrng_rsafips_test_init(&rng1,ccn_xp1->len,ccn_xp1->units,ccn_xp2->len,ccn_xp2->units,ccn_xp->len,ccn_xp->units);
        ccrng_rsafips_test_init(&rng2,ccn_xp1->len,xq1,ccn_xp2->len,xq2, ccn_xp->len, xq);
        ccrng_rsafips_test_set_next(&rng1, &rng2);
        ok((ccrsa_generate_fips186_key(key_nbits, full_key, 4, e65537,
                                       (struct ccrng_state *)&rng1,
                                       trng)!=0), "RSA FIPS Key generation");
        ccrng_rsafips_test_init(&rng1,ccn_xp1->len,ccn_xp1->units,ccn_xp2->len,ccn_xp2->units,ccn_xp->len,ccn_xp->units);
        ccrng_rsafips_test_init(&rng2,ccn_xp1->len,xq1,ccn_xp2->len,xq2, ccn_xp->len, xq);
        ccrng_rsafips_test_set_next(&rng1, &rng2);
        ok((ccrsa_generate_fips186_key(key_nbits, full_key, 4, e65537,
                                       (struct ccrng_state *)&rng1,
                                       trng)!=0), "RSA FIPS Key generation");

        // |Xp-Xq|=2^(nbits/2-100)+2 => pass
        // 2.q1.q2 > 2.r1.r2 so that |p-q|>2^(nbits/2-100)
        ccn_zero(ccn_xp->len,tmp);
        ccn_set_bit(tmp,((key_nbits/2)-100),1);
        ccn_set_bit(tmp,(cc_unit)1,1);
        ccn_add(ccn_xp->len,xq,ccn_xp->units,tmp);
        ccn_zero(ccn_xp1->len,xq1);
        ccn_zero(ccn_xp2->len,xq2);
        ccrng_rsafips_test_init(&rng1,ccn_xp1->len,xq1,ccn_xp2->len,xq2,ccn_xp->len,ccn_xp->units);
        ccrng_rsafips_test_init(&rng2,ccn_xp1->len,ccn_xp1->units,ccn_xp2->len,ccn_xp2->units, ccn_xp->len, xq);
        ccrng_rsafips_test_set_next(&rng1, &rng2);
        ok((ccrsa_generate_fips186_key(key_nbits, full_key, 4, e65537,
                                       (struct ccrng_state *)&rng1,
                                       trng)!=0), "RSA FIPS Key generation");
        ccrng_rsafips_test_init(&rng1,ccn_xp1->len,xq1,ccn_xp2->len,xq2,ccn_xp->len,ccn_xp->units);
        ccrng_rsafips_test_init(&rng2,ccn_xp1->len,ccn_xp1->units,ccn_xp2->len,ccn_xp2->units, ccn_xp->len, xq);
        ccrng_rsafips_test_set_next(&rng1, &rng2);
        ok((ccrsa_generate_fips186_key(key_nbits, full_key, 4, e65537,
                                       (struct ccrng_state *)&rng1,
                                       trng)!=0), "RSA FIPS Key generation");

        // Free
        free(ccn_xp1); free(ccn_xp2); free(ccn_xp);
    }
    ccrsa_full_ctx_clear_nbits(key_nbits, full_key);
    // Close rng fd.
    return 0;
}


/* Known answer tests with construct function */
static int
RSAFIPS_Make_Test(cc_unit e,
                 char *xp1str, char *xp2str, char *xpstr,
                 char *xq1str, char *xq2str, char *xqstr,
                 char *pstr, char *qstr, char *mstr, char *dstr)
{
    ccnBuffer xp1 = hexStringToCcn(xp1str);
    ccnBuffer xp2 = hexStringToCcn(xp2str);
    ccnBuffer xp = hexStringToCcn(xpstr);
    ccnBuffer xq1 = hexStringToCcn(xq1str);
    ccnBuffer xq2 = hexStringToCcn(xq2str);
    ccnBuffer xq = hexStringToCcn(xqstr);
    ccnBuffer expectedP = hexStringToCcn(pstr);
    ccnBuffer expectedQ = hexStringToCcn(qstr);
    ccnBuffer expectedM = hexStringToCcn(mstr);
    ccnBuffer expectedD = hexStringToCcn(dstr);
    ccnBuffer retP = mallocCcnBuffer(MAXKEYSPACE);
    ccnBuffer retQ = mallocCcnBuffer(MAXKEYSPACE);
    ccnBuffer retM = mallocCcnBuffer(MAXKEYSPACE);
    ccnBuffer retD = mallocCcnBuffer(MAXKEYSPACE);
    int success = 1;
    cc_size n = xp->len + xq->len;
    cc_size nbits = ccn_bitsof_n(n);

    ccrsa_full_ctx_decl_nbits(nbits, full_key);

    CC_DECL_WORKSPACE_TEST(ws);
    success&=is(ccrsa_make_fips186_key_ws(ws, nbits, 1, &e, xp1->len, xp1->units, xp2->len, xp2->units, xp->len, xp->units,
                                          xq1->len, xq1->units, xq2->len, xq2->units, xq->len, xq->units,
                                          full_key,
                                          &retP->len, retP->units, &retQ->len, retQ->units,
                                          &retM->len, retM->units, &retD->len, retD->units), CCERR_OK, "ccrsa_make_fips186_key");
    CC_FREE_WORKSPACE(ws);

    if(ccnAreEqual(retP, expectedQ) && ccnAreEqual(retQ, expectedP)) {
        ccnBuffer tmp = retP;
        retP = retQ;
        retQ = tmp;
        printf("Swapped P and Q\n");
    }

    success&=ok_ccn_cmp(expectedP->len,retP->units, expectedP->units, "p is built correctly");
    success&=ok_ccn_cmp(expectedQ->len,retQ->units, expectedQ->units, "q is built correctly");
    success&=ok_ccn_cmp(expectedD->len,retD->units, expectedD->units, "d is built correctly");
    success&=ok_ccn_cmp(expectedM->len,retM->units, expectedM->units, "m is built correctly");

    if (!success) goto errout; // Skip roundtrip if make failed

    success&=is(test_rsa_roundtrip(full_key,TEST_KEY_SANITY),0, "RSA Round-Trip Key Tests");
errout:
    free(retP); free(retQ); free(retD); free(retM);
    free(xp1); free(xp2); free(xp); free(xq1); free(xq2); free(xq); free(expectedP); free(expectedQ); free(expectedM); free(expectedD);
    ccrsa_full_ctx_clear_nbits(nbits, full_key);
    if (success) return 0;
    return 1;         // Error
}

// Der Public key for EFI
static int test_import_der_pub_key(void) {
    uint8_t foo[256];
    int i;
    for(i=0; i<256; i++) foo[i] = (uint8_t)i;
    static uint8_t derbuf[] = {
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
        0x00, 0xa5, 0xcd, 0xd7, 0xaf, 0xeb, 0x44, 0xd6, 0xa2, 0xe4, 0xe4, 0x4d, 0xb8, 0xc8, 0xd5, 0x80,
        0x51, 0xc1, 0x12, 0xe1, 0xc2, 0x0c, 0xc6, 0x89, 0x29, 0x3a, 0xe9, 0x6d, 0x7e, 0x7d, 0x9d, 0xc3,
        0x5a, 0xaf, 0xce, 0xdc, 0x1e, 0x92, 0x28, 0xbe, 0x00, 0x34, 0x05, 0xc8, 0x19, 0x4f, 0x7c, 0x23,
        0x00, 0x3d, 0x7b, 0xdb, 0x80, 0xd1, 0x82, 0xb9, 0xca, 0xb4, 0xe4, 0x01, 0x43, 0xdc, 0x11, 0xd3,
        0x20, 0xec, 0xd8, 0x44, 0xd6, 0xa8, 0x7e, 0xa7, 0xa3, 0xc2, 0x85, 0x61, 0xff, 0xd4, 0x88, 0x8e,
        0x40, 0x4b, 0x1c, 0xe9, 0x2f, 0x5e, 0x48, 0x26, 0x46, 0x79, 0x65, 0xf4, 0x4f, 0x52, 0x04, 0x09,
        0x0b, 0x1a, 0x05, 0x27, 0x18, 0xe9, 0x22, 0x6d, 0x10, 0xa6, 0x4b, 0xe3, 0x7a, 0x4b, 0x32, 0x8d,
        0x65, 0xbf, 0x1c, 0x8d, 0x24, 0x9c, 0x12, 0xfe, 0xd3, 0xc9, 0xd6, 0x3a, 0xb2, 0xca, 0x50, 0xab,
        0x37, 0x56, 0x79, 0x97, 0x79, 0xe6, 0xed, 0xf8, 0x3a, 0xc6, 0xf7, 0xec, 0x4d, 0x33, 0x9a, 0x63,
        0x9c, 0xc9, 0x14, 0x7d, 0x09, 0x41, 0xe2, 0x07, 0x91, 0x1d, 0xf6, 0xe8, 0x3f, 0xe5, 0x47, 0x26,
        0x6e, 0x4d, 0x20, 0x6c, 0x9e, 0x21, 0x60, 0xa0, 0xf6, 0xc8, 0x73, 0xc8, 0xa5, 0x3f, 0xbf, 0x74,
        0xd3, 0x2c, 0xc5, 0xce, 0xb0, 0x71, 0xa2, 0x11, 0xee, 0xe2, 0x88, 0x43, 0x87, 0x02, 0x96, 0xe0,
        0x76, 0xcb, 0x45, 0x2f, 0xe2, 0xe6, 0x01, 0xee, 0x6e, 0xab, 0x17, 0x4a, 0x20, 0xee, 0x9e, 0x7c,
        0x35, 0x81, 0xe5, 0xf4, 0x82, 0x74, 0xbf, 0xe4, 0x15, 0x1e, 0x2c, 0xf7, 0x5c, 0xf6, 0x3a, 0x14,
        0x16, 0xcd, 0x1a, 0xb2, 0x67, 0xfe, 0xbd, 0x34, 0x25, 0x56, 0xc1, 0x2c, 0xcd, 0xf5, 0xbf, 0x7f,
        0xae, 0x63, 0x8f, 0xdc, 0x37, 0xac, 0x09, 0x9d, 0xb4, 0x3f, 0x7f, 0x0e, 0x3e, 0xb6, 0xa4, 0xa2,
        0xdb, 0x02, 0x03, 0x01, 0x00, 0x01,
    };
    size_t derlen = sizeof(derbuf);
    cc_size n = ccrsa_import_pub_n(derlen, derbuf);
    ok((ccn_sizeof_n(n) == ccn_sizeof(2048)), "size is correct");
    ccrsa_pub_ctx_decl_n(n, pubkey);
    ccrsa_ctx_n(pubkey) = n;
    if(ccrsa_import_pub(pubkey, derlen, derbuf) != 0) {
        printf("Internal Error importing pubkey\n");
        return 0;
    }
    ccrsa_pub_ctx_clear_n(n, pubkey);
    return 1;
}

unsigned char derdat[] = {
    0x30, 0x82, 0x01, 0xdb, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xaf,
    0xb5, 0xc5, 0xc6, 0x7b, 0xc5, 0x3a, 0x34, 0x90, 0xa9, 0x54, 0xc0, 0x8f,
    0xb7, 0xeb, 0xa1, 0x54, 0xd2, 0x4f, 0x22, 0xde, 0x83, 0xf5, 0x03, 0xa6,
    0xc6, 0x68, 0x46, 0x9b, 0xc0, 0xb8, 0xc8, 0x6c, 0xdb, 0x26, 0xf9, 0x3c,
    0x49, 0x2f, 0x02, 0xe1, 0x71, 0xdf, 0x4e, 0xf3, 0x0e, 0xc8, 0xbf, 0x22,
    0x9d, 0x04, 0xcf, 0xbf, 0xa9, 0x0d, 0xff, 0x68, 0xab, 0x05, 0x6f, 0x1f,
    0x12, 0x8a, 0x68, 0x62, 0xeb, 0xfe, 0xc9, 0xea, 0x9f, 0xa7, 0xfb, 0x8c,
    0xba, 0xb1, 0xbd, 0x65, 0xac, 0x35, 0x9c, 0xa0, 0x33, 0xb1, 0xdd, 0xa6,
    0x05, 0x36, 0xaf, 0x00, 0xa2, 0x7f, 0xbc, 0x07, 0xb2, 0xdd, 0xb5, 0xcc,
    0x57, 0x5c, 0xdc, 0xc0, 0x95, 0x50, 0xe5, 0xff, 0x1f, 0x20, 0xdb, 0x59,
    0x46, 0xfa, 0x47, 0xc4, 0xed, 0x12, 0x2e, 0x9e, 0x22, 0xbd, 0x95, 0xa9,
    0x85, 0x59, 0xa1, 0x59, 0x3c, 0xc7, 0x83, 0x02, 0x03, 0x01, 0x00, 0x01,
    0x02, 0x01, 0x00, 0x02, 0x41, 0x00, 0xec, 0xbe, 0xe5, 0x5b, 0x9e, 0x7a,
    0x50, 0x8a, 0x96, 0x80, 0xc8, 0xdb, 0xb0, 0xed, 0x44, 0xf2, 0xba, 0x1d,
    0x5d, 0x80, 0xc1, 0xc8, 0xb3, 0xc2, 0x74, 0xde, 0xee, 0x28, 0xec, 0xdc,
    0x78, 0xc8, 0x67, 0x53, 0x07, 0xf2, 0xf8, 0x75, 0x9c, 0x4c, 0xa5, 0x6c,
    0x48, 0x94, 0xc8, 0xeb, 0xad, 0xd7, 0x7d, 0xd2, 0xea, 0xdf, 0x74, 0x20,
    0x62, 0xc9, 0x81, 0xa8, 0x3c, 0x36, 0xb9, 0xea, 0x40, 0xfd, 0x02, 0x41,
    0x00, 0xbe, 0x00, 0x19, 0x76, 0xc6, 0xb4, 0xba, 0x19, 0xd4, 0x69, 0xfa,
    0x4d, 0xe2, 0xf8, 0x30, 0x27, 0x36, 0x2b, 0x4c, 0xc4, 0x34, 0xab, 0xd3,
    0xd9, 0x8c, 0xd6, 0xb8, 0x0d, 0x37, 0x5e, 0x59, 0x4b, 0x76, 0x70, 0x68,
    0x2b, 0x1f, 0x4c, 0x3d, 0x47, 0x5f, 0xa5, 0xb1, 0xcd, 0x74, 0x56, 0x88,
    0xfe, 0x7c, 0xf8, 0x3b, 0x30, 0x6f, 0xfd, 0xc3, 0xed, 0x87, 0x3c, 0xa1,
    0x53, 0x84, 0xc3, 0xd2, 0x7f, 0x02, 0x40, 0x60, 0x71, 0x9b, 0xe9, 0xe8,
    0xf3, 0x97, 0x1f, 0xfe, 0x13, 0xd4, 0xbf, 0x7a, 0xa2, 0x0d, 0xf6, 0x7b,
    0xcf, 0x3e, 0xaa, 0x17, 0x47, 0x75, 0xc3, 0x7f, 0xec, 0xd9, 0x44, 0x9e,
    0xc9, 0x6a, 0x02, 0xe9, 0xe4, 0xaf, 0x56, 0x51, 0xd5, 0x47, 0xa9, 0x09,
    0xb2, 0xc5, 0x16, 0xa7, 0x8b, 0x2b, 0x34, 0xa0, 0x33, 0x6e, 0x2f, 0x3d,
    0x95, 0x7b, 0xe8, 0xef, 0x02, 0xe4, 0x14, 0xbf, 0x44, 0x28, 0xd9, 0x02,
    0x40, 0x10, 0x0e, 0x2e, 0x18, 0xad, 0x5d, 0xe4, 0x43, 0xfe, 0x81, 0x1e,
    0x17, 0xaa, 0xd0, 0x52, 0x31, 0x5e, 0x10, 0x76, 0xa2, 0x35, 0xd9, 0x37,
    0x43, 0xb0, 0xf5, 0x0c, 0x04, 0x81, 0xe3, 0x45, 0x24, 0x6d, 0x53, 0xbe,
    0x59, 0xb6, 0x81, 0x58, 0xc4, 0x49, 0x3e, 0xd5, 0x31, 0x89, 0x5d, 0x2e,
    0xa2, 0x62, 0xa9, 0x0f, 0x47, 0x5e, 0x8f, 0x51, 0x19, 0x27, 0x4e, 0x66,
    0x4b, 0x8a, 0x72, 0x89, 0xbd, 0x02, 0x40, 0x3e, 0x53, 0x0a, 0xf4, 0x8e,
    0x75, 0xe1, 0x52, 0xc6, 0x24, 0xe9, 0xf7, 0xbb, 0xac, 0x3f, 0x22, 0x5f,
    0xe8, 0xe0, 0x79, 0x35, 0xff, 0x91, 0xee, 0x22, 0x56, 0xd2, 0x00, 0x68,
    0x32, 0xc4, 0xe1, 0x5f, 0xff, 0xf8, 0xb1, 0x1d, 0xee, 0xdc, 0x57, 0x81,
    0xd1, 0xab, 0x8b, 0x37, 0x22, 0xe3, 0x9f, 0xd0, 0xa1, 0xc1, 0xce, 0x1d,
    0xd0, 0x24, 0x23, 0xa0, 0x0e, 0xf7, 0xa6, 0xdb, 0xa3, 0xea, 0xd3
};

// |p| = |q| but p < q.
unsigned char derdat2[] = {
    0x30, 0x82, 0x01, 0x3b,
    0x02, 0x01, 0x00,
    0x02, 0x41, 0x00, 0xcd, 0xad, 0x7e, 0xa7, 0x4a, 0x7a, 0x3a, 0x8e, 0xc1,
    0xcd, 0x25, 0x93, 0xf0, 0x0b, 0xd6, 0x45, 0x61, 0x94, 0xa0, 0x11, 0xf0,
    0x00, 0x14, 0x16, 0x52, 0x9d, 0x08, 0x76, 0xd3, 0x01, 0x20, 0x54, 0xe3,
    0x75, 0x21, 0x72, 0xee, 0x11, 0x40, 0x45, 0x9d, 0x13, 0x92, 0x49, 0x39,
    0x69, 0xd8, 0x94, 0xc7, 0xc0, 0x17, 0xab, 0x81, 0x48, 0x84, 0x2b, 0xfc,
    0xdc, 0xee, 0x42, 0xac, 0x9a, 0x3d, 0x75,
    0x02, 0x03, 0x01, 0x00, 0x01,
    0x02, 0x41, 0x00, 0xad, 0x88, 0x19, 0xfa, 0x0f, 0x8e, 0x7c, 0xe5, 0x81,
    0x82, 0x12, 0x98, 0x74, 0xc9, 0xa7, 0xe9, 0x35, 0xe1, 0x6e, 0x04, 0x74,
    0x57, 0xbc, 0x9a, 0xf0, 0xec, 0xe8, 0xfd, 0x48, 0x1e, 0x05, 0x25, 0xd5,
    0xcc, 0xb8, 0xd0, 0x64, 0x6c, 0xb9, 0x83, 0x11, 0xf5, 0xb3, 0x49, 0x35,
    0x17, 0x7f, 0x2a, 0x99, 0xf2, 0xe0, 0xc6, 0x4c, 0xb9, 0x64, 0x22, 0x24,
    0xda, 0x84, 0x39, 0x70, 0x0c, 0xdc, 0xc1,
    0x02, 0x21, 0x00, 0xd4, 0xcc, 0xb2, 0xfd, 0xfb, 0x1c, 0x88, 0xe1, 0xdf,
    0xea, 0x0a, 0x02, 0x7a, 0x3b, 0x4d, 0x5c, 0xd9, 0x18, 0xca, 0x1c, 0xdc,
    0x04, 0x15, 0x01, 0x68, 0x78, 0x2e, 0x5a, 0x3b, 0xc0, 0x3d, 0xbd,
    0x02, 0x21, 0x00, 0xf7, 0x6e, 0xaa, 0xd3, 0x00, 0x94, 0xb4, 0x34, 0x8b,
    0x92, 0xd3, 0xa0, 0x71, 0x57, 0xa7, 0xbc, 0xd2, 0x1e, 0x2c, 0x9d, 0x89,
    0x8e, 0x06, 0x88, 0xfa, 0x06, 0x17, 0xd3, 0xf9, 0xd1, 0x6e, 0x19,
    0x02, 0x20, 0x06, 0x0a, 0xee, 0x06, 0x42, 0x4c, 0x34, 0x22, 0xdd, 0xdd,
    0xe2, 0x7c, 0xe1, 0x85, 0xaf, 0x93, 0xb4, 0x62, 0x7c, 0xd2, 0xc6, 0xf8,
    0xa2, 0xb4, 0x10, 0x88, 0x61, 0x20, 0x94, 0xd3, 0xc7, 0xad,
    0x02, 0x20, 0x52, 0x30, 0x1f, 0x6b, 0xf1, 0x30, 0x73, 0xdf, 0x54, 0x51,
    0x54, 0x1c, 0x62, 0x29, 0xb4, 0x9c, 0xe2, 0xca, 0x85, 0x15, 0x5b, 0x20,
    0xa3, 0x09, 0x12, 0xcb, 0xbd, 0x54, 0x7b, 0x11, 0xd6, 0xd9,
    0x02, 0x21, 0x00, 0xa1, 0xb3, 0x6d, 0xe2, 0xd4, 0x9b, 0x59, 0xf4, 0xe6,
    0x28, 0x6f, 0xbd, 0x89, 0x89, 0x90, 0x9b, 0xdc, 0x11, 0xec, 0x19, 0xca,
    0xea, 0x2d, 0x57, 0x3d, 0xad, 0x36, 0xb5, 0xf5, 0x4c, 0x0d, 0x49
};

// |p| < |q|.
unsigned char derdat3[] = {
    0x30, 0x82, 0x01, 0x3c,
    0x02, 0x01, 0x00,
    0x02, 0x41, 0x01, 0xa5, 0x67, 0x6e, 0x0c, 0x29, 0xf1, 0x4f, 0x9b, 0xca,
    0x40, 0xbd, 0x3c, 0x54, 0xc7, 0x7d, 0x84, 0x86, 0x16, 0x4e, 0xf1, 0x9c,
    0x5f, 0xed, 0x1e, 0x99, 0xc8, 0x3e, 0x75, 0x92, 0x52, 0x6a, 0xc3, 0x8d,
    0xbf, 0x79, 0x79, 0x52, 0x7c, 0xb8, 0xbc, 0xf1, 0x7d, 0x5f, 0xc1, 0xfa,
    0xd5, 0x01, 0x25, 0x58, 0xb9, 0x50, 0x37, 0x47, 0x3a, 0xd2, 0x66, 0xe1,
    0x86, 0x3d, 0xa1, 0x6a, 0x7c, 0x24, 0xbb,
    0x02, 0x03, 0x01, 0x00, 0x01,
    0x02, 0x41, 0x00, 0x87, 0xb2, 0xf6, 0xcd, 0x13, 0xf4, 0x91, 0x1e, 0x29,
    0xd3, 0x0f, 0x1d, 0x0e, 0x6f, 0xef, 0x0b, 0x6d, 0xe2, 0x61, 0x29, 0x8c,
    0xa1, 0x97, 0x49, 0xf3, 0x5b, 0x78, 0x41, 0x84, 0x0c, 0xe6, 0x33, 0x96,
    0xad, 0xa8, 0x73, 0xfb, 0xb3, 0xf7, 0xe9, 0x78, 0x37, 0xdb, 0x8d, 0x62,
    0xb2, 0x3e, 0xf0, 0x3f, 0x4b, 0x03, 0x35, 0xd0, 0xba, 0xb5, 0xf7, 0xd8,
    0xb1, 0xaf, 0x11, 0x74, 0x6f, 0x0d, 0x01,
    0x02, 0x21, 0x00, 0xf7, 0x6e, 0xaa, 0xd3, 0x00, 0x94, 0xb4, 0x34, 0x8b,
    0x92, 0xd3, 0xa0, 0x71, 0x57, 0xa7, 0xbc, 0xd2, 0x1e, 0x2c, 0x9d, 0x89,
    0x8e, 0x06, 0x88, 0xfa, 0x06, 0x17, 0xd3, 0xf9, 0xd1, 0x6e, 0x19,
    0x02, 0x21, 0x01, 0xb3, 0xfe, 0xe9, 0xcd, 0x47, 0xe9, 0x55, 0x1c, 0x18,
    0xa7, 0x59, 0x05, 0xcd, 0xd0, 0x02, 0x9f, 0x15, 0xe6, 0x38, 0x5b, 0x95,
    0xe1, 0x81, 0xb1, 0xdc, 0xe7, 0x80, 0x67, 0x1d, 0x34, 0x1b, 0xf3,
    0x02, 0x20, 0x52, 0x30, 0x1f, 0x6b, 0xf1, 0x30, 0x73, 0xdf, 0x54, 0x51,
    0x54, 0x1c, 0x62, 0x29, 0xb4, 0x9c, 0xe2, 0xca, 0x85, 0x15, 0x5b, 0x20,
    0xa3, 0x09, 0x12, 0xcb, 0xbd, 0x54, 0x7b, 0x11, 0xd6, 0xd9,
    0x02, 0x21, 0x01, 0x38, 0xb7, 0x17, 0xbe, 0xf3, 0x5b, 0x3a, 0x7e, 0x62,
    0x78, 0x75, 0x73, 0xa2, 0x41, 0x16, 0x00, 0x40, 0xd6, 0xd5, 0x89, 0x6b,
    0x21, 0x49, 0xc2, 0xe6, 0xec, 0xec, 0xbe, 0x08, 0xc6, 0x3d, 0x5d,
    0x02, 0x21, 0x00, 0x92, 0x60, 0x47, 0xb4, 0x02, 0xb3, 0x9e, 0x1f, 0x2c,
    0x9b, 0x78, 0x88, 0x82, 0xfe, 0x6e, 0x18, 0x5f, 0x9f, 0xc0, 0x35, 0x4f,
    0xa8, 0x7b, 0xef, 0x12, 0x13, 0x30, 0xef, 0x3e, 0x31, 0x90, 0x23
};

static int test_import_der_priv_key(void)
{
    // Import an RSA key with |p| = |q| and p > q.
    cc_size n=ccrsa_import_priv_n(sizeof(derdat), derdat);
    ok(!(n==0),"Import size");
    ccrsa_full_ctx_decl_n(n, tmpkey);
    ccrsa_ctx_n(tmpkey)=n;
    ok_or_fail(ccrsa_import_priv(tmpkey, sizeof(derdat), derdat) == 0, "Imported Private Key");
    //ccrsa_dump_full_key(tmpkey); /* manually enable for debug purposes */
    ok_or_fail(test_rsa_roundtrip(tmpkey,TEST_KEY_SANITY) == 0, "Can round-trip imported key");

    cczp_const_t zp = ccrsa_ctx_private_zp(tmpkey);
    cczp_const_t zq = ccrsa_ctx_private_zq(tmpkey);
    is(cczp_n(zp), cczp_n(zq), "cczp_n is equal");
    is(ccn_cmp(cczp_n(zp), cczp_prime(zp), cczp_prime(zq)), 1, "p > q");

    ccrsa_full_ctx_clear_n(n,tmpkey);

    // Import an RSA key with |p| = |q| but p < q.
    n=ccrsa_import_priv_n(sizeof(derdat2), derdat2);
    ok(!(n==0),"Import size");
    ccrsa_full_ctx_decl_n(n, tmpkey2);
    ccrsa_ctx_n(tmpkey2)=n;
    ok_or_fail(ccrsa_import_priv(tmpkey2, sizeof(derdat2), derdat2) == 0, "Imported Private Key");
    ok_or_fail(test_rsa_roundtrip(tmpkey2,TEST_KEY_SANITY) == 0, "Can round-trip imported key");

    zp = ccrsa_ctx_private_zp(tmpkey2);
    zq = ccrsa_ctx_private_zq(tmpkey2);
    is(cczp_n(zp), cczp_n(zq), "cczp_n is equal");
    is(ccn_cmp(cczp_n(zp), cczp_prime(zp), cczp_prime(zq)), -1, "p < q");

    ccrsa_full_ctx_clear_n(n,tmpkey2);

    // Import an RSA key with |p| < |q|.
    n=ccrsa_import_priv_n(sizeof(derdat3), derdat3);
    ok(!(n==0),"Import size");
    ccrsa_full_ctx_decl_n(n, tmpkey3);
    ccrsa_ctx_n(tmpkey3)=n;
    ok_or_fail(ccrsa_import_priv(tmpkey3, sizeof(derdat3), derdat3) == 1, "Private Key import should fail");
    ccrsa_full_ctx_clear_n(n,tmpkey3);

    return 1; // No error
}

static void test_recover_priv_key(void)
{
#if !CC_DISABLE_RSAKEYGEN
    size_t key_nbits = 1024;
    const uint8_t e[] = { 0x1, 0x00, 0x01 };
    ccrsa_full_ctx_decl_nbits(key_nbits, fk);
    is(ccrsa_generate_key(key_nbits, fk, sizeof(e), e, global_test_rng), 0, "Generate a key");

    cc_size n = ccrsa_ctx_n(fk);
    cczp_t zm = ccrsa_ctx_zm(fk);

    uint8_t m_buf[ccn_write_uint_size(n, cczp_prime(zm))];
    ccn_write_uint(n, cczp_prime(zm), sizeof(m_buf), m_buf);

    uint8_t e_buf[ccn_write_uint_size(n, ccrsa_ctx_e(fk))];
    ccn_write_uint(n, ccrsa_ctx_e(fk), sizeof(e_buf), e_buf);

    uint8_t d_buf[ccn_write_uint_size(n, ccrsa_ctx_d(fk))];
    ccn_write_uint(n, ccrsa_ctx_d(fk), sizeof(d_buf), d_buf);

    ccrsa_full_ctx_decl_nbits(key_nbits, fk2);
    is(ccrsa_recover_priv(fk2, sizeof(m_buf), m_buf,
                               sizeof(e_buf), e_buf,
                               sizeof(d_buf), d_buf, global_test_rng), 0,
      "Recover prime factors (p,q)");

    is(ccrsa_recover_priv(fk2, 1, m_buf, sizeof(d_buf), d_buf, 1, d_buf, global_test_rng),
      CCRSA_INVALID_INPUT, "ccrsa_recover_priv() with e too large");
    is(ccrsa_recover_priv(fk2, 1, m_buf, 1, e_buf, sizeof(d_buf), d_buf, global_test_rng),
      CCRSA_INVALID_INPUT, "ccrsa_recover_priv() with d too large");

    struct { const char *m, *d; int rv; } vectors[] = {
        // Sanity check, should succeed.
        { "50a4af219805b5db", "2883beed740268d", CCERR_OK },
        // An even modulus must fail.
        { "50a4af219805b5dc", "2883beed740268d", CCRSA_INVALID_INPUT },
        // k = de - 1 must be even.
        { "50a4af219805b5db", "2883beed740268c", CCRSA_INVALID_INPUT },
        // (e,d) are not consistent.
        { "50a4af219805b5db", "193c800facb0e601", CCRSA_INVALID_INPUT },
        // p = q.
        { "fa76894d721aac91", "7685fb39", CCRSA_INVALID_INPUT },
        // p is 4 bits larger than q.
        { "5e96b91bfdabbd45", "7a3ba71173e7251", CCRSA_INVALID_INPUT },
        // d = d' + 2 * lambda
        { "6791c0874492e0ef", "2822953b21ac6631", CCRSA_INVALID_INPUT },
    };

    for (unsigned i = 0; i < CC_ARRAY_LEN(vectors); i++) {
        byteBuffer m_bytes = hexStringToBytes(vectors[i].m);
        byteBuffer d_bytes = hexStringToBytes(vectors[i].d);

        int rv = ccrsa_recover_priv(fk2, m_bytes->len, m_bytes->bytes,
            sizeof(e_buf), e_buf, d_bytes->len, d_bytes->bytes, global_test_rng);
        is(rv, vectors[i].rv, "ccrsa_recover_priv() test vector #%u", i);

        free(m_bytes);
        free(d_bytes);
    }
    ccrsa_full_ctx_clear_nbits(key_nbits, fk);
    ccrsa_full_ctx_clear_nbits(key_nbits, fk2);
#endif
}

static void test_generate_deterministic_key(void)
{
#if !CC_DISABLE_RSAKEYGEN
    size_t key_nbits = 1024;

    const uint8_t e[] = { 0x1, 0x00, 0x01 };

    const uint8_t entropy[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t nonce[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    ccrsa_full_ctx_decl_nbits(key_nbits, fk);
    is(ccrsa_generate_key_deterministic(key_nbits, fk, sizeof(e), e,
        sizeof(entropy), entropy, sizeof(nonce), nonce,
        CCRSA_GENKEY_DETERMINISTIC_LEGACY, global_test_rng), 0, "Generate a key");

    const cc_unit p[] = {
        CCN64_C(fb,de,a3,f5,34,13,9b,eb),CCN64_C(ef,14,51,b9,24,24,1e,14),
        CCN64_C(f2,c3,57,15,d2,67,ef,a0),CCN64_C(c7,1a,61,3f,06,c6,bd,37),
        CCN64_C(9f,47,52,90,cf,43,7e,15),CCN64_C(3d,34,45,f9,21,74,3b,46),
        CCN64_C(31,c4,17,ae,c9,68,1e,24),CCN64_C(9f,19,6a,60,d6,21,13,70),
        CCN8_C(01)
    };

    const cc_unit q[] = {
        CCN64_C(9a,f1,c9,8c,d9,82,6b,53),CCN64_C(ee,bf,ad,f2,60,28,84,23),
        CCN64_C(25,c8,4e,97,7c,91,22,14),CCN64_C(30,2f,29,ec,ab,cc,63,81),
        CCN64_C(dd,9f,d1,63,c1,25,ca,b9),CCN64_C(3c,69,e6,e6,4e,67,28,95),
        CCN64_C(bd,24,dc,62,3b,31,85,47),CCN64_C(6a,8a,d8,6a,e3,aa,6a,50)
    };

    cczp_const_t zp = ccrsa_ctx_private_zp(fk);
    cczp_const_t zq = ccrsa_ctx_private_zq(fk);

    ok_ccn_cmp(cczp_n(zp), p, cczp_prime(zp), "p is correct");
    ok_ccn_cmp(cczp_n(zq), q, cczp_prime(zq), "q is correct");
    ccrsa_full_ctx_clear_nbits(key_nbits, fk);
#endif
}

#define SMALL_PRIME_BITS 10
#define LARGE_PRIME_BITS 512

static void test_generate_prime(void)
{
#if !CC_DISABLE_RSAKEYGEN
    cc_size n = ccn_nof(LARGE_PRIME_BITS);
    cc_unit p[n], exp[n];
    ccn_seti(n, exp, 3);

    CC_DECL_WORKSPACE_TEST(ws);

    for (size_t depth = 1; depth < 10; depth++) {
        int result = ccrsa_generate_prime_ws(ws, SMALL_PRIME_BITS, p, exp, global_test_rng, global_test_rng);
        is(result, 0, "ccrsa_generate_prime failed to generate a prime");

        result = ccrsa_generate_prime_ws(ws, LARGE_PRIME_BITS, p, exp, global_test_rng, global_test_rng);
        is(result, 0, "ccrsa_generate_prime failed to generate a prime");
    }

    CC_FREE_WORKSPACE(ws);
#endif
}

static int test_emsa_pkcs1v15_encode_invalid_args(size_t emlen, size_t dgstlen, const uint8_t *oid)
{
    uint8_t em[emlen];
    uint8_t dgst[dgstlen];

    cc_memset(em, 0, emlen);
    cc_memset(dgst, 0, dgstlen);

    return ccrsa_emsa_pkcs1v15_encode(emlen, em, dgstlen, dgst, oid) != CCERR_OK;
}

struct SizeRanges {
    unsigned long first;
    unsigned long last;
};

// Test a bunch of different sizes.
// Slow but these have helped catch issues.
const struct SizeRanges sizesToTest[] =
{
    { .first = 512, .last = 512 },
    { .first = 1024, .last = 1088 },
    { .first = 1280, .last = 1280 },
    { .first = 2048, .last = 2048 },
    { .first = 2056, .last = 2056 },
    { .first = 3072, .last = 3072 },
    { .first = 4096, .last = 4096 }
};
#define nSizesToTest CC_ARRAY_LEN(sizesToTest)

#if defined(_WIN32) || CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
#define RSA_KEYGEN_INCR_VALUE 17
#else
#define RSA_KEYGEN_INCR_VALUE 1
#endif

int ccrsa_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int verbose = 1;
#if CC_DISABLE_RSAKEYGEN
    int stdgen = 0;
    int fipsgen_rand = 0;
    int fipsgen_kat = 0;
    int fipsmake_kat = 0;
#elif CORECRYPTO_HACK_FOR_WINDOWS_DEVELOPMENT
    int stdgen = 1;
    int fipsgen_rand = 1;
    int fipsgen_kat = 0;
    int fipsmake_kat = 0;
#else
    int stdgen = 1;
    int fipsgen_rand = 1;
    int fipsgen_kat = 1;
    int fipsmake_kat = 1;
#endif

    plan_tests(90771);

    if(verbose) diag("Import DER keys");
    ok(test_import_der_pub_key(), "Import RSA DER public key");
    ok(test_import_der_priv_key(), "Import RSA DER private key");

    if(verbose) diag("PKCS1 v1.5 RSA sample signature");
    ok(test_sample_pkcs1v15() == 0, "Sample PKCS1 v1.5 RSA signature");

    if(verbose) diag("PKCS v1.5 Known Answer Tests");
    ok(test_verify_pkcs1v15_known_answer_test() == 0, "PKCS v1.5 Known Answer Tests");

    if(verbose) diag("RSAPSS Known Answer Tests");
    ok(test_rsa_pss_known_answer()==0, "RSAPSS Known Answer Tests");

    if(verbose) diag("Test hardcoded valid and invalid keys");
    ok(test_rsa_keys()==0, "Test hardcoded valid and invalid keys");

    if (verbose) diag("Test EMSA PKCS#1v1.5 encoding invalid arguments");
    for (size_t r = 0; r < nSizesToTest; r++) {
        for (size_t key_nbits = sizesToTest[r].first; key_nbits <= sizesToTest[r].last; key_nbits += RSA_KEYGEN_INCR_VALUE) {
            /* use digests close to the size of the key */
            for (size_t i = 0; i < 523; i += 1) {
                size_t dgstlen = key_nbits - 10 + i;
                ok(test_emsa_pkcs1v15_encode_invalid_args(key_nbits, dgstlen, NULL),
                   "Test EMSA PKCS#1v1.5 encoding emlen %llu dgstlen %llu null oid", key_nbits, dgstlen);
                ok(test_emsa_pkcs1v15_encode_invalid_args(key_nbits, dgstlen, CC_DIGEST_OID_SHA256),
                   "Test EMSA PKCS#1v1.5 encoding emlen %llu dgstlen %llu sha256 oid", key_nbits, dgstlen);
            }

            /* use digests close to the size of UINT8_MAX */
            for (size_t i = 230; i <= 280; i += 1) {
                size_t dgstlen = i;
                ok(test_emsa_pkcs1v15_encode_invalid_args(key_nbits, dgstlen, CC_DIGEST_OID_SHA256),
                   "Test EMSA PKCS#1v1.5 encoding emlen %llu dgstlen %llu sha256 oid", key_nbits, dgstlen);
            }
        }
    }

    if (verbose) diag ("Test ccrsa_make_priv");
    ccrsa_test_make_priv();

    if(verbose) diag("Test ccrsa_recover_priv");
    test_recover_priv_key();

    if(verbose) diag("Test ccrsa_generate_key_deterministic");
    test_generate_deterministic_key();

    if(verbose) diag("Test ccrsa_generate_prime\n");
    test_generate_prime();

    if(stdgen) {
#if CORECRYPTO_HACK_FOR_WINDOWS_DEVELOPMENT
        diag("*skipping tests on Windows");
#else
        for (size_t r=0;r<nSizesToTest;r++) {
            //while developing code, you may want to use key_nbits++, to generate more keys
            for (size_t key_nbits = sizesToTest[r].first;key_nbits<=sizesToTest[r].last;key_nbits+=RSA_KEYGEN_INCR_VALUE) {
                if(verbose) diag("Generating %lu bit STD keypair", key_nbits);
                ok(RSAStd_Gen_Test(key_nbits, 65537) == 0, "Generate Standard %lu bit RSA Key Pair",key_nbits);
            }
        }
#endif
        if(verbose) diag_linereturn();
    } /* stdgen */

    if(fipsgen_rand) {
        ok(RSAFIPS_Negative_Test() == 0, "Negative test");
#if CORECRYPTO_HACK_FOR_WINDOWS_DEVELOPMENT
        diag("*skipping tests on Windows");
#else
        for (size_t r=0;r<nSizesToTest;r++) {
            //while developing code, you may want to use key_nbits++, to generate more keys
            for (size_t key_nbits = sizesToTest[r].first;key_nbits<=sizesToTest[r].last;key_nbits+=RSA_KEYGEN_INCR_VALUE) {
                if(verbose) diag("Generating %lu bit FIPS keypair", key_nbits);
                ok(RSAFIPS_Gen_Test(key_nbits, 65537) == 0, "Generate FIPS %lu bit RSA Key Pair",key_nbits);
            }
        }
#endif
        if(verbose) diag_linereturn();
    } /* fipsgen_rand */

    /* KAT where xp1, xp2, xq1, xq2 need to be at the exact expected size:
     * 101bits for 1024 key, 141bits for 2048 key and 171bits for 3072 key
     */
    if(fipsgen_kat) {
        if(verbose) diag("KAT tests with ccrsa_generate_fips186_key");
        char *xp1, *xp2, *xp, *xq1, *xq2, *xq, *p, *q, *m, *d, *e;
        int i = 1;

        xp1 = "16bf0a0a1ffb86ecc83b0811b4";
        xp2 = "1ff1fd983eca621b679339f637";
        xp  = "f065e44770423a1a42a2729480d6fadd2d3a5a776b1b2296ab2dde3a7b495b89fd41190a02c8077f33b31a350ea6bfe73684d97be6a358aa988a12e0d952e0b5";
        q   = "f065e44770423a1a42a2729480d6fadd2d3a5a776b1b2296ab2dde3a7b495b89fd41190a02cb5274d198e05fd1bbed9431e02f235a47b5cde34a83036e2d0313";
        xq1 = "1284a138ea6c6820e9afdc8212";
        xq2 = "148e0ab29e93dcc7d1f26eb5e3";
        xq  = "7242adc365806d8796c47a8fc1aeac797f9ace90f081b04074b6a4b58e82b984690a630abd3a2a14b06015a1a8da0ad7b5a3f3b73f27b6004970e14b95e70f87";
        p   = "f242adc365806d8796c47a8fc1aeac797f9ace90f081b04074b6a4b58e82b984690a630abd3a5c9e26598329e0bf22b49ab318478a2d75c2e0d3bcf550810d5f";
        m   = "e37eef3cbabb822419fd0298746375e011fa7bb259b7cfc2df6469505bed13e410debfef68774a848198c3239ff8895524d2749f256104a4228b36c66d5ed16784fecf3c5872beae02a9c3eb0dd9ca6396b73a5399f9eea59b7bab54d67581c9d175bc93e3e7c448222444f8bf5f8f2149ba08742c3ad9d0e07545b1a86f1b0d";
        e   = "010001";
        d   = "0515dc51363764d45bc45d1f7d528fdaff6be301fca1704281ede3b0c92d46898d9afd1d63ef6eba018fa1a515396010882f302e328eb5a4d9a4d507a080431c0b81f4023c52a5613f36e04837595d2337c336f1c0a6222dfe734592e344524aea3d5a8dbd069bc4c179b5f95e8769127bd1b6f4f726c31b69c6c438faf8b6bd";

        if(verbose) diag("FIPS KAT key pair %d", i++);
        ok(RSAFIPS_Gen_KAT_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d, true) == 0, "Successfully Built RSA KeyPair");

        xp1 = "1747cbbd8b16c4dbc259e53b8a5c7db1b9f5";
        xp2 = "18946d3a6f5e3e088446dd0e04aa62bc87e8";
        xp  = "6fccd146d52a5b4adda4a45a45f2eabb41da13fe6de477dad87d361d69c2cbb79640e76ac7c28abbce096dbf2e638b2053fc39c503bfcdc64d0ae2d7d818bb984896f115a76a8edad23e996b536856f808c717999dbb3955c4213b001a6d9722ce8d69e6b57e103a2f24765da3a2a413254b0c388172ad2f2cd623a9ce296c99";
        p   = "efccd146d52a5b4adda4a45a45f2eabb41da13fe6de477dad87d361d69c2cbb79640e76ac7c28abbce096dbf2e638b2053fc39c503bfcdc64d0ae2d7d818bb984896f115a76a8edad23e996b536856f808c717999dbb3955c4213b006440c777347d91c61db9c8362e47f98be3046ed928149472f50e6d5892066f6f85e4eeab";
        xq1 = "12b99070aad5f8eb5a1eb542cc7954964713";
        xq2 = "174fff7a7dbe800b669794255534fc85907c";
        xq  = "ceac510d2dbc456cc1bb7d960927c45da1556751e4922fe7efeee3e3c44f4a268872cd88e44682e4d0708971791707030e4f130078c4e8b5fa6989cee8dfb623a5e4adbf2f2010938ed46721e69e3dcadc7f1f14be39d33ee75bb1c51fc12f52686118044659b1b1801e9b7cd85ba5399a9f8c9f94af3c2db548a4c8eb7fe549";
        q   = "ceac510d2dbc456cc1bb7d960927c45da1556751e4922fe7efeee3e3c44f4a268872cd88e44682e4d0708971791707030e4f130078c4e8b5fa6989cee8dfb623a5e4adbf2f2010938ed46721e69e3dcadc7f1f14be39d33ee75bb1cbc87166c1b1a46868c7ff638f06d2b1878fa4587091c665b60ac1ff8d23db1f96da61d153";
        m   = "c19839efc194b43206772251c8f015c9dafabdcfba2f85fdac2d309e890de1185a0bae4fb1dc01015939023bb569276f747624e894df7332244275e88a5cf3a4f07b1f4f7206372a3a1851f6e131f3e1d85fc668522d8436d94e9e3df20fcec951b8d4837ad3bc8876fca31b442232ba1b843074b575f1409e7fa341e1f5f7ff6ebebe92e4cd0cdc3820e77569312999ea027f70a5862dd0ca7f5a49672b0bb84e5f77756fb158a7e9115bafb2000a04023612d8764f78b7167bc00074a94934aa2091ef72e3e3da800cb284cf419346e1308cb6f511a9b02bddab4805899f00e93081fff58edf7c9d16f0f878f3e447179035856693ff7b84aa69a65cddfc71";
        e   = "010001";
        d   = "06873d9cea283b935c48742dd1dad6c141d326c7747dd9c4de237ffa38a0f130430915cdb62fb710f6934791ffe215e45a4709a396319acedc0e29afb7cabea4973f6fa4dc317d76bd12c8e0cc6344d81ed5cbf9049c6852f92cff85133e99388cbaf0dfa62ab1b6e05c509bc0c66e737c2e0efc408a43a26c35dda981172c4fafbc0932cda7598a3a6475c4b14684c70915e093be794d89f763f2ccfcafecca78c51000143afe9cb655389c581c7c18650c23b5cc1a9c46236919d4728cca17562c8fce1beb9eb50eae58e4027244d6ea8dd26ce3cce5376232e0f9882c6baf32fb30754a5568840ccba307c0189457aeeb479f2c0ff84778fba8f3b02ee169";

        if(verbose) diag("FIPS KAT key pair %d", i++);
        ok(RSAFIPS_Gen_KAT_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d,false) == 0, "Successfully Built RSA KeyPair");


        xp1 = "06758b895a2569a5f3750675ffa1ccf21a361772995d";
        xp2 = "04c8a6de0443deeb337153b22e1aaa37c6f1c1acc7a0";
        xp  = "f8db6812f6afb06d609ffe1e355a6d7a3fd0dd5cda682140f07192cd690bf584bba6424ea4741f7e792fc455b0c33fda7da63ff5b2a0372cc636ed3cc09e296073bdab77a13f1cb5fc7af05a9eb59abf1005dac7aab6d67868ce77fc86c5f2cd799c38a475156319587ed9b84e22187150120b9846df8805ec81e49e2224fd80b173116efce75d3eb178f3948bfbb73ff41080c3b5b9e0b672dba421f07165720d9ca1cacbb1288c06e0f50a337a22cff4e1c205f679f4ada5a965c37b97e0fa";
        p   = "f8db6812f6afb06d609ffe1e355a6d7a3fd0dd5cda682140f07192cd690bf584bba6424ea4741f7e792fc455b0c33fda7da63ff5b2a0372cc636ed3cc09e296073bdab77a13f1cb5fc7af05a9eb59abf1005dac7aab6d67868ce77fc86c5f2cd799c38a475156319587ed9b84e22187150120b9846df8805ec81e49e2224fd80b173116efce75d3eb178f3948bfbb73ff41080c46e5d93daf1d83a8874fd51981b2406206696fb055f151a8e6fab00a789a4967603ddeae5a2cab0ef0bde773d";
        xq1 = "07707e60b84e01ed744f4b2cc4d898d63115c50419b4";
        xq2 = "067e05048874d2c690293b7b02b488b450c267a54a22";
        xq  = "6506916267c5c26007953864284eda97d9f95c63952e33635204ff313f936d941f3413a4adebc1f963a895bac448526d2d1cc3b35e5579ccb90f72d3366bba676dae2214b385247154a8d411c33be2ff737b7297b4a9b3ab5670774ea8e8fe23c887de95caf1ae88cbc9fcfaf993d55a0b3f94e5ac2b1455d2859bb41ce9c27928d12809bc10cfdf8ef716cf608f5d88656bf3b6758d8196b80178d5758a8a36989f845ed7aa4e7b87c41a54409e15fc1337b4baeb635e8191ed1bb6d5dfa557";
        q   = "e506916267c5c26007953864284eda97d9f95c63952e33635204ff313f936d941f3413a4adebc1f963a895bac448526d2d1cc3b35e5579ccb90f72d3366bba676dae2214b385247154a8d411c33be2ff737b7297b4a9b3ab5670774ea8e8fe23c887de95caf1ae88cbc9fcfaf993d55a0b3f94e5ac2b1455d2859bb41ce9c27928d12809bc10cfdf8ef716cf608f5d88656bf3b690335fa2989e646e160b75e6b6bde76235a86b0d214f10f71d701feb2d2fb348f9eb9de8d73b1511d6331ad1";
        m   = "dea2a69155ee0a96428bd94475ae6d7e58a419f856bf06284b1f53ba8bbf09d893a10c9d7ea88a7664e23e5e3e9d1eb4fed6ef36aef29fef5e79f35b8c31b427741b74c8f8728fae3488ba96949d77f5e85e76c47fd24bdd955a07f71d03bdc3ea2fc299f20c5b334616a1ac3e4bdbfef34ee0d9c915b413bc178c17b7dcdfd142a0f865d0d29f822bcac419e30f7cc392b4531fa55652b62456ab7580dcc6b73006366f0f7c9355a86608caa4d3a801c3c6f35d48de60cc6f2fbc70fa68dbea90709f11811f139df5644dd8a3aec2301aed0cea43f6613c9d7ba57ec6a9494989af565a654f2e4d445c14bdb14134900101ddaf8f6935df7bb5185f6df81d69c4536d60a605545813f402f789b016936131674900a48eeec68f25e7145397bd1cc2663da56bc8bff2dc02a94866bfd39ca3eb6d3559adf17bcb8acba8949ad5512ee06adb0f888705054f541312d6aec39af31cea32316c8b37823802277938b2a1810afd8a5c5e3e91f9c1a92dd355715db37d68a15cd6509afb6907e28acd";
        e   = "010001";
        d   = "078ed6ffc26933d923b0dd5dda6ee2f9b1e6feee097d2fa77e3160901f2960f0b0c6515d7c0cc5b2923c84a88210a717b6e508b6e9b12e911b90769caa2c3a74f26c9cdb810fb13aaa943a5d5d4b368f806575e662d3cff92eeba104986abaee4e8cc8daf2b6cd0121c527ea3c827fc3ee72443b85d238f6f33636192207f0b333c35a30beaa3fcefff9eb6158ee257ffad828a594e1282aab1e241ba24071cb35e952bf6a1e57b41b3a3cdc80444d2fa37bfab6b52abe222d38c8cebf0ed5e9ac3cca78d14bc291573c52305417e0819496a03b8b21a8467879e4ce69cbfa9161860a9ef52b6edccf1da4e08d00371e4f35e559e8c0b6dcc5e3e3aee841db1958a620acbe5b6ab187938be40123e7caa62ca71c8c24792883fae04d0cdc8815b88f679847c0bd0a03d6c6dc71968f1d724b9463fdf372e1e09d7920e3b3af192f36ca6c6d902f181095b9583bbe9fc1ae383dcd4a68ad67bd35f9cbb6fb06f136a4da4c7c1d10326f10dd5a4e0babca3a3740573e07a358e6c5d1a128fe28a1";

        if(verbose) diag("FIPS KAT key pair %d", i++);
        ok(RSAFIPS_Gen_KAT_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d,false) == 0, "Successfully Built RSA KeyPair");
        if(verbose) diag_linereturn();
    }

    /* KAT where xp1, xp2, xq1, xq2 can be of any arbitrary size
     * Allows to run the CAVs
     */
    if(fipsmake_kat) {
        if(verbose) diag("KAT Tests with ccrsa_make_fips186_key");
        char *xp1, *xp2, *xp, *xq1, *xq2, *xq, *p, *q, *m, *d;
        uint32_t e;
        int i = 1;

        e = 3;
        xp1 = "1eaa9ade4a0da46dd40824d814";
        xp2 = "17379044dc2c6105423da807f8";
        xp = "fd3f368d01a95944bc1578f8ae58a9b6c17f529da1599a8bcd361df6efede4176924944e30cbe5c2ddea5648019d2086b95c68588380b8725003b047db88f92a";
        xq1 = "1da08feb13d9fba526190d3756";
        xq2 = "10d93d84466d213a3e776c61f6";
        xq = "f67b5f051126a8956171561b62f572090cde4b09b13f73ee28a90bea2bfb4001fe7b16bd51266524684520e77941dddc56b892ae4bd09dd44acc08bf45dd0a58";
        
        
        p = "fd3f368d01a95944bc1578f8ae58a9b6c17f529da1599a8bcd361df6efede4176924944e30d114d4c767d573d1149e005267e6fe36c51d86968cf6f65afcb973";
        q = "f67b5f051126a8956171561b62f572090cde4b09b13f73ee28a90bea2bfb4001fe7b16bd5129f06dc6e1f8b4f739c7eb1eb8dcacca3b41cd484fc0c693367037";
        m = "f3d4c9ca2dca5d4b893919ae7bee0d174d1e7bd2190287f79a7db6f21366108e8b0aa37cc972989ff3730d629620076555884da0e895d4e426449c60e36fad1d0208dd4ade1c45fc90da5e76c9c89fd95d13ce76a97530ee83ea3cfbe96cf28f85c4756797cd0123683194b7b2fcd185c3ea984cb0ef90580f95d57a44b027b5";
        d = "28a376f707a1ba3741898447bf525783e22fbf4daed5c153ef14f3d3033bad6d172c7094cc3dc41aa8932ce5c3b0013b8e4162457c18f8d0b10b6f657b3d478482626149773760b0688ded3b1ebf16044273b2cd3924b068c2572dd9cceb4d13afb0cc64ae4da9facefbf66d271d11ef0dcc4e1af2a7dd80b2c984f4e3bf7fad";
        
        if(verbose) diag("Build FIPS key pair %d", i++);
        ok(RSAFIPS_Make_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d) == 0, "Successfully Built RSA KeyPair");
        
        e = 0x010001;
        xp1 = "155e67ddb99eefb13e4b77a7f0";
        xp2 = "17044df236c14e8ec333e92506";
        xp = "d4f2b30f4f062ad2d05fc742e91bc20ca3ee8a2d126aff592c7de19edb3b884550ddd6f99b0a6b2b785617b46c0995bc112176dbae9a5b7f0bec678e84d6f44c";
        p = "d4f2b30f4f062ad2d05fc742e91bc20ca3ee8a2d126aff592c7de19edb3b884550ddd6f99b13e5dd56ffb2ac1867030f385597e712f65ac8dd1de502857c1a41";
        xq1 = "1e2923b103c935e3788ebd10e4";
        xq2 = "11a2ccec655a8b362b5ec5fcc4";
        xq = "f7c6a68cff2467f300b82591e5123b1d1256546d999a37f4b18fe4896464df6987e7cc80efee3ce4e2f5c7a3cc085bbe33e4d375ed59cbc591f2b3302bd823bc";
        q = "f7c6a68cff2467f300b82591e5123b1d1256546d999a37f4b18fe4896464df6987e7cc80efeeb4c59165f7d1aec9be2b34889dbe221147e7ceefb5c9bd5cb945";
        m = "ce1b6904ec27f4a8f420414860704f4797a202ed16a9a35f63a16511a31675ccb046b02b192ef121b328385922f5faa032113332d42f84c70d4323133e216b0f339ebaf672f6214d0d7c13bea301174485ec44f44fae0e8a7f8d3c81ced5df77723331816158c3added7dc55f1436a7e5f14730be22cf3bebab1b62915c80c85";
        d = "18d16522721b5793169e61ae08eacd291641ac6f8718933313c8a5e66b487393dbb00f5b89334556e4ff5555aa678b2fca07972e2a2db4a3d15d81b639f7852ffe71657918d0280ff1be2f8f5d90b3e68195ab35e5069a3053540958bc6d58489fecf8baab0981f4af7b4db43550bcf01114e5ecdcb18f228db1c617b5d09781";
        if(verbose) diag("Build FIPS key pair %d", i++);
        ok(RSAFIPS_Make_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d) == 0, "Successfully Built RSA KeyPair");
        
        e = 3;
        xp1 = "1c36bd0874761109bb0575ee16";
        xp2 = "1777c33935db08546dd66b6d96";
        xp = "d040fa5fe5e32eab84bac6cab4c512dae938cbbe4a29f972b78b149b0b5f6a639e29c0830fa13ca140ac83dda18a1ea7b25122d3c39a10effe7afad4a8b4e77ba42c7912399fcd4f1592a3059188bff536788fe6807e0df8e3d1e7350cf5dd69";
        p = "d040fa5fe5e32eab84bac6cab4c512dae938cbbe4a29f972b78b149b0b5f6a639e29c0830fa13ca140ac83dda18a1ea7b25122d3c39a10effe7afad4a8b4e77ba42c791239acf889977037a0efe181d54b93279b7e46a2fdcf674039fb11e89b";
        xq1 = "14c70e475b12870bc6efd3b944";
        xq2 = "1432548a4959eed65b858cd316";
        xq = "e4d222daf062a01a3a9ddfc82a229613403b772ff05fa9fab1fc77de51744af98b65d47bdb2e8f5091af66002550b1d3ca446738450f8f670045f8465a952a8942079c1e048228c86291bb0ae7665146782021262c49143b5ea37ce400240372";
        q = "e4d222daf062a01a3a9ddfc82a229613403b772ff05fa9fab1fc77de51744af98b65d47bdb2e8f5091af66002550b1d3ca446738450f8f670045f8465a952a8942079c1e04937b7eb94b8d322faefd691b6fa2b0ef4a2333ed791afe8ac3ac41";
        m = "ba24d0a5878c01f6ad9140b6271b42309887a6815d5ef1bc3415a381b7b511a42b8d2b8d9df59faa0b69456ff908e24b4ccb835420404ce449c9ce4ca65dc4ae4eb6bb8403b809d530ef4b37e5b211c13a03e2a69afb8c748b90c97d52023ae9a24c1f1f4b3b87685eaa649f54e41b6439e29700543f0747f09658ed392f96ee568a50ad7b5441c88ad37c581526ff296b1c6cc87e352d4f921960b6b630f8f546f1077a7586b839ee07717de84e0a19cd52eceb358ff2c69387b13a83e5335b";
        d = "1f0622c641420053c7983573b12f35b2c4169bc03a3a7d9f5e039b404948d846074231ecefa8eff1ac918b92a9817b0c8ccc95e35ab562260c4c4d0cc664f61d0d1e7496009eac4e32d28c8950f302f589ab507119d49768c1ed76ea3855b47bfcded5a6137e49706fe2f50213aa1313ad67b8adaef390a46bd7ccbdfa0f5042dcd4749d181613a3c9694314626207c7a7c125ca139742296de412449dd1267d6574d30c5e8bb60844e1f21c76ca41cf3bb805c521553218ce71390055029a6b";
        if(verbose) diag("Build FIPS key pair %d", i++);
        ok(RSAFIPS_Make_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d) == 0, "Successfully Built RSA KeyPair");
        
        e = 3;
        xp1 = "1408766e2cb2d47ebfee7ea614";
        xp2 = "16292b77507cffd2f798b7c9f2";
        xp = "f74435451a7ddaa163c8c8ad03dfde97fe066360dfee52e3a9d8f41310fdb484e92e302de0b88c6c698a0b4af99ae001758441bbeb74be9d8047d104a9edb60e9e127c5d0cfd5d170ab84b314f71cbeea22006a2916a1dbc66c5be0357def520fd38445d0815f5ac3099afeb6f2d48666d22da9e3c961949459ce399829719c1";
        p = "f74435451a7ddaa163c8c8ad03dfde97fe066360dfee52e3a9d8f41310fdb484e92e302de0b88c6c698a0b4af99ae001758441bbeb74be9d8047d104a9edb60e9e127c5d0cfd5d170ab84b314f71cbeea22006a2916a1dbc66c5be0357def520fd38445d081fbe68dd24e14f0711cc0351fec8641d8ea7d22c4709f233e6349b";
        xq1 = "161d77eb77c6f257d8f8a3b0ca";
        xq2 = "152f11dfc70b78f0fc6c9137b8";
        xq = "c4d3feeb0e561be3727fd83dedaeaaecba01c798e917dd8bb11a03ce07fcf08f6f006ac6137d021912dffffc1aee981c395366fef05718e38aef69f0abf64f8b2cb9750826b8ec854dab1e1280c403169e3497ee9af08bd6d2b53a0d9c49e034220506f7719041f0cced1cc846b853a090ac42af0f699c2c3174606e02800952";
        q = "c4d3feeb0e561be3727fd83dedaeaaecba01c798e917dd8bb11a03ce07fcf08f6f006ac6137d021912dffffc1aee981c395366fef05718e38aef69f0abf64f8b2cb9750826b8ec854dab1e1280c403169e3497ee9af08bd6d2b53a0d9c49e034220506f771942204f0890fb5e617c580aa98a7482b5457215badc119f23b21c3";
        m = "be1cfc39868d8e9a8239f504482be60c01071cbdab4355b03c10edafe85d9ca10689d86036b6d35829a364a8a2b69f28743e50e5e27ac6b6fe8962809e1c2e0765b2d7508d61bfa538085dfb685595c6965bc5e0855a6dd8807a83e2ee7fc50b5b48f2d232195b672f2c325eb6649dee9758ce76f690107f3b0d10afef427777fb0bac0a41e23717fc54d9194a344d1823bdc18fa364e5373da39a3e41bcc4d88a688a711b56c6387b669d37c4fd7878559b93473869ae8190c46605f03cf25038bf771246fb81a27bc9d44ba67bfce94a3051856511661dbe0803d220809695ad707022c4acd24d40e011eb3752e39568f66cdd2d90369a67295e19dadb0d11";
        d = "1faf7f5eebc2426f15b45380b6b1fbacaad684ca4735e39d5f58279d5164ef702bc1a410091e788eb19b3b717073c53168b50d7ba5bf211e7fc1906ac504b25690f323e2c23af546340164ff3c0e43a1190f4ba56b8f124ec0146b507d154b81e48c28785daee49132875dba73bb6fa7c3e42269291802bfdf2cd81d528b13e90a7de94f042d0ac33102095d0ec64b433c9e43c3a4651e215072c5ba3175aff6085efd3f868589487fd4c2fd72be000f1bcb51c20f6fa3d56b97872d6f0ed21e67a896478336340105e6672bf90bb250ac4f487e0973ca17161781f58763f58ac25ddb77b7297da53dddb02661b18dad920fd4dd7b7233f125336dd79e1ef3c9";
        if(verbose) diag("Build FIPS key pair %d", i++);
        ok(RSAFIPS_Make_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d) == 0, "Successfully Built RSA KeyPair");
        
        e = 3;
        xp1 = "164511563871556a9babc022c8";
        xp2 = "1ae2a7a04f23efe080f48a24b0";
        xp = "db5c4ccf412b17041b6e20b7e0cb45d807ef4da8282428e05e26782fef3251ea2f613d00a134842c6070aa6ebd2c38bb2a28c0f457601b159ae1f5af94dc8c9812f9b4e031ed1f08c64fdb6ffca71c0d3fc93c63596100b2dbce1d6cbf34fae84bccb859397f700114b4bba2e56678360f79c9df784e5f21e995f84fb8622543a48351520012ff80144653efc08ed49e62e17050fa4fc1c98cdd8e40c68f9512e3c687b4cfcc55eb8caeaa3fd44ab8ad00a8389c288eac128c4ee82832e3d0bb";
        p = "db5c4ccf412b17041b6e20b7e0cb45d807ef4da8282428e05e26782fef3251ea2f613d00a134842c6070aa6ebd2c38bb2a28c0f457601b159ae1f5af94dc8c9812f9b4e031ed1f08c64fdb6ffca71c0d3fc93c63596100b2dbce1d6cbf34fae84bccb859397f700114b4bba2e56678360f79c9df784e5f21e995f84fb8622543a48351520012ff80144653efc08ed49e62e17050fa4fc1c98cdd8e40c68f9512e3c687b4d000a836a83d21ea810c683a30e79e5fc8626e78961f076aef2f89ab";
        xq1 = "18ab1ad30607288890b387858a";
        xq2 = "19975a38d9368fa99deda7e986";
        xq = "bd7cc6c56616fb5b41f35d8de2a5c61d1894895dfa46aa95c2de4ea5dfe370eb4543d6670898431d29a9efbbb034347cfaeb8a4c55bcb52dca553dd93ae81fa9ad2bc2b5e6a42c3d3b237648a3907d8a11e6db8b008016064f94168f50fddd791c3d72f729c21e811e68db7ae5400a0f02906462241a33e8faa1c20f48aa12253a80ce75f87a81b37a80079a9ecc42d378ee0e19e913769b738628a14b772673b0fcbf777c55be99f974e1eff5bd8c9d190abff776f246e6614b2f8d81ed812c";
        q = "bd7cc6c56616fb5b41f35d8de2a5c61d1894895dfa46aa95c2de4ea5dfe370eb4543d6670898431d29a9efbbb034347cfaeb8a4c55bcb52dca553dd93ae81fa9ad2bc2b5e6a42c3d3b237648a3907d8a11e6db8b008016064f94168f50fddd791c3d72f729c21e811e68db7ae5400a0f02906462241a33e8faa1c20f48aa12253a80ce75f87a81b37a80079a9ecc42d378ee0e19e913769b738628a14b772673b0fcbf777c640b3b2f869336b823710bb296f32aaba903f90af79239c3d97279";
        m = "a25e0fbcc06a40ac879bba988e78b9df8f88b800077d580b615e3f2f663c9ce631eb0229ee7a4d5166122378bd055f686dd382e63c1564c96127ec191c88d1ba02fcf90f1efcfe29bdfab0fd6413dcb4027512d15c2e337f7111e7acc7679cd1b96581461466ca63af5fbfc0579d322ca02413b75a6dce25c529d6475fafbc5d07504a29039c0f567cbb9dff2938687a6e6d4633f9ae46383536060dc7efb90ff99a6e97449e8f8ad24853f70726953b3f1dc82222f8407f98250f2060777cbd05d0b2ed6abb99d86ac30974df41da16bc1e3abd610df6bcff49a2be932baeedf163911eec026dcbd5937734b47ceb48db97c27bd2a35338f90332b75374ae4404913ae82caf14bba7410c638676a544046aed0b6605562186a4ba6b3695ab25f900899bd03a8f3e68d548b4eadbd9a348a142618954b1b9d73245926d6c57e26454db887c6272280c2d0efff1b856762da7c8be77a0006da3ea589b21ee5efec36574c041d8e506af55de52083225242642cafdcdadfa9663e4424a2bb937d3";
        d = "1b0fad4a2011b5721699f46ec269744fed417400013f8eac903a5fdd3bb4c4d10851d5b1a7bf0ce2e6585b3eca2b8fe6bcf895d10a0390cc3adbfcaeda16cd9f007f7ed7da7f7fb19fa9c82a3b58a4c8ab138322e4b25dea92d85147769144cd9ee6403658bbcc65f28ff54ab944ddb21ab0adf3e467a25ba0dc4e613a9d4a0f81380c5c2b44ad3914c9efaa86debc1467bce108a99d0bb408de5657a1529ed7feef126e8b6fc297230c0dfe813118df352fa15b05d40abfeeb0d7dababe94c9e77e9a8ecb3eebe9823aec87d9f8225aef4465f3dfc5db367a60cf517603a7596a1fbf9e8b08f115b73ecf81b684bfad73c093df30ebc07e434caa87c09d55ab0b674b3858afa1939ba249c7265fd747731f2384d75b5fe6b9e06bbd3110787618290fb73cd42aca08f3f2ee855e393a5e6e835aa77cafc7d329c1dde7655abeeb8d74a015f8d2d36a3bc8939864dfd60da40c63435f76ac1b411af42d5145e95d1b0798a8e8b2ee23edb188228061fa60760993399b16b0cb2246c63ec809f3";
        if(verbose) diag("Build FIPS key pair %d", i++);
        ok(RSAFIPS_Make_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d) == 0, "Successfully Built RSA KeyPair");

        e = 3;
        xp1 = "1a02a180a22a37d3ab4d5523fe";
        xp2 = "1179fc502dbe82ff9946c00392";
        xp = "d94a30017127e43b0005e99016c2f4efb8e0c91e61805b52478e35fddf3918e7a3a6e68013e5be75fa246981f222f5862ae79fdc67b3f7e849343ef1d0fb13301e314f267f862d33a66bae633a813b8b91518c95bb3dca18c2b6f02c30b0777cd253329cbcf4779d8d437fdff4c60f27738658f163081d08397e1353073f8df24675588ad215e4dc3615a59d2ad9b9815aeecb9a69fa37e036f36f115e909dbb02fd8a96cad3be182947e944e3a281c3cdf1ad35d4fd62c9417dcb0b3c8beffe8e558e6bab154b78ef43117c2808af1255f7c56dadf8e4ebe384f1eca918cae473e32caf7dc2d5250f6fe5ef00f68a997968dce7fbd2066da370a75aad1f7895";
        p = "d94a30017127e43b0005e99016c2f4efb8e0c91e61805b52478e35fddf3918e7a3a6e68013e5be75fa246981f222f5862ae79fdc67b3f7e849343ef1d0fb13301e314f267f862d33a66bae633a813b8b91518c95bb3dca18c2b6f02c30b0777cd253329cbcf4779d8d437fdff4c60f27738658f163081d08397e1353073f8df24675588ad215e4dc3615a59d2ad9b9815aeecb9a69fa37e036f36f115e909dbb02fd8a96cad3be182947e944e3a281c3cdf1ad35d4fd62c9417dcb0b3c8beffe8e558e6bab154b78ef43117c2808af1255f7c56dadf8e4ebe384f1eca918cae473e32caf7dd1126fd14c73ebcce310791625550d6582891713c38ac374993099";
        xq1 = "1fb621dce29cbb6a66cc3bf7d6";
        xq2 = "122325102c2e57c27d462e1e06";
        xq = "facc7f5f089ed9267363bc23c6c7b8f73208a36f61fa8ea8084ff777bc154107068061c4b9ead9788318eab4c3bf05729a4684f845ce9700aa70811530c50440d4ac19e47a47e5e78047e912996a79bbd9416fa10c3720174ccf8f65d32de16b0dd81187f1bee5b992792105f1d0fa191681cd305f3e113617f58b2d4a54c0cfd88db075c956c137e034fa5573fa71d67a8c076ee5e952a53369db3640438ab55e515e75a81861a99303dcc9c6efc7382cec83234742ccacc7b3e9485b002565c7af8351370aae57d26b2f2b93b7e2885429ab172c516593fb5c1b2b43957b273a2c87cf1d368e88c6f65b41815bac0d1cc9e6113d1d06a1f8ebdba6a1097343";
        q = "facc7f5f089ed9267363bc23c6c7b8f73208a36f61fa8ea8084ff777bc154107068061c4b9ead9788318eab4c3bf05729a4684f845ce9700aa70811530c50440d4ac19e47a47e5e78047e912996a79bbd9416fa10c3720174ccf8f65d32de16b0dd81187f1bee5b992792105f1d0fa191681cd305f3e113617f58b2d4a54c0cfd88db075c956c137e034fa5573fa71d67a8c076ee5e952a53369db3640438ab55e515e75a81861a99303dcc9c6efc7382cec83234742ccacc7b3e9485b002565c7af8351370aae57d26b2f2b93b7e2885429ab172c516593fb5c1b2b43957b273a2c87cf1d710fc707b5e6d58b6f3cb377b286466c4da41f592c749ebf97fca3";
        m = "d4e0061c2150cdf177232b89266af9153902cbd434a39cab549d997ed6dadcb4e84bbac6d49658428728a01bd7036bab4b0003f7e6ccf69df1effad985185c4ab0756237e4be92b2f42085d4388a29f461af98649c700d6dad5e0fe352513b578b3bff5f19b144e6304defe1b4fb43b37ecb4ed7c0e97377802d9e79c6d742837b3b71fd101fcf5ead4a114d9419af008a421d8a4c5efd4e6da8cc3c967502bd4cc1bda09e87bf7a1d0badaf0783a6dbef5c98359c59d6bda1cc9bacfaa962c841ddfa3670211e38a68998508ea1a2be519718a168d09cc0d2c1d0f8d56ca1d7199b0c4fc78ddb595f6681e5b1b96309251c0714bf134d46f58419a0273bfaab3328b59d75d8ada5e6e2745e816d17ded27b52f0b5632088ee6bf9675793adc52591abc3eacbf3ae4b59871ac9c94e98708801f534ad0a99791827e91cbacf7afbbd72e162698aeba0380f74462b8dd097fb576a99d70ad2117efee8f6ef51d6afd6fb8ce9b6c234ebf00d24d44ad505305e48af1a8037fed9a2a44235980d395bf69489309d37a04b66f236d223b1af759232ecf9d6556a71cd74c4936fc6d3efe6efb3311eea1574e0cebd657a9d36142f0719b95c98900bd32b9cdb6702ff92a7eefc5ec99c6f12709cb3a118cdaf56284dd195e0633dd689889924c42d3e6579e403bb3ecb08310128c673de301c3bea248f3bd0f63cab3f2545da9f8d6b";
        d = "237aabaf5ae2ccfd93db31ec3111d42e342b21f8b3709a1c8e1a443fce79cf737c0c9f21236e640b1686c559f92b3c9c8c8000a95122291a52fd5479962eba0c72be3b0950ca6dc87e056ba35ec1b1a8baf299661a12ace79ce502a5e30d89e3ec89ffe52ef2e0d1080cfd5048d48b489521e2794ad1933e955cefbef67935c09489e854d8054d3a723702e243599d2ac1b5af970cba7f8d1246ccb4c3be2b1f8ccaf4f01a6bf53f04d7479d2beb4679fd3a195e44b9a3ca45a219f229c6e5cc0afa545e680585097116eeb817c59b1fb843d9703c22c4cacdcaf82978e7704e8444820d4becf9e43a9115a648499081862f5683752de2367e40aef00689ff1c3a83010a2a02fd60bde977c71b5066fea69851107da6b3c26fc24ca84a0b8df91491bb3fda29e49ff7af5dd0adfbe3454739a4dac131bf48163de6a5af29c957017aac4e66c493f81440beaa685ff96c323c0f334dbb057055a96a8e7dd8297d229c9e915f2b3b7a4cb33cb5279df74b710e5b178eb456f56c07d64afb55f513df7dec96c388184208da0db6088d410e9aae8ffb46fdcc7b813d5c6a28c49a65ed1956711fb321b89ec38172747c0e09aee2ce756f84bc2f00703e8c35f9d2448a1b24dfea1c45c50d75ba01fb8eb4ae1cabcf8cc9ee5974fe9c14958958fbddc93c5d40daaa1c22e3ffcd00d9eca5d29d030c3491aacc2bb50d30fb4667bab3";
        if(verbose) diag("Build FIPS key pair %d", i++);
        ok(RSAFIPS_Make_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d) == 0, "Successfully Built RSA KeyPair");

        e = 0xd5db07;
        xp1 = "5bb112dd0eea8da7ab88a74b47c3105f2b69ea75e7bf99f8bfd17ba3";
        xp2 = "04d50b31ce0cf62d6162f9225b03eef44b99d297e048f20784c175";
        xp = "baa459bb19f837a82313f70e75a6215e61ec91248bc39016c813673c08958ebe3768b3e56cf9b6bb50fa07d29f9097dde6ef29b94b635ac5a2b2b473f479c969adefd26a4b64f19d744c63a132dd2ff4cbd31cc4ff7b187f6b0cbd6f86cb52f561bf291c4ed68403783bf0865d2165ef8fce3479644051b850e4c4530ae63865e5c2b3dc7511a10925dd1f0fa6c8fde6fc1ad0b40ff847015745fc9ca6192277c38a2d17908150c7366664cc917f77fe06b5e81dc058080ab232a722f2b7d34e";
        p = "baa459bb19f837a82313f70e75a6215e61ec91248bc39016c813673c08958ebe3768b3e56cf9b6bb50fa07d29f9097dde6ef29b94b635ac5a2b2b473f479c969adefd26a4b64f19d744c63a132dd2ff4cbd31cc4ff7b187f6b0cbd6f86cb52f561bf291c4ed68403783bf0865d2165ef8fce3479644051b850e4c4530ae63865e5c2b3dc7511a1093ba3ef165ce324498f57436ebf8adef98375648a33fe7f67291ab1fd7c11727269c0e10c1d1fc9578432863344b2b89ac601d53f62f4dc87";
        xq1 = "765dae3f7b4535196f62eec5ee495b1a67d1e593e7004baf4dddd91080739f36e84bc37d8c440662900005b1a85356253af6302e3b924927aea579bd03c83ab096a7cbfea48e43";
        xq2 = "0d13d2881d687676894e7ad625bc590ec6b512b11d27";
        xq = "ddbe54ed64de7d7a0379de757bd14b100c9c051b5248f8f88ee513e3069c7ba472b642855dedefc370f378e6c6175efcb4b597cbdc703c94e5c41dcd6eb5296057478e0c18256b5fb162315bc29f437155ad70bbf279df29057a2c9fa4ba96157305f883d6de427119e55054b8270354f154b5aa4e067eb9f99877722e9afec0a104f4646526377c8929721121d75be4bef6f12e6554e5858ea75723b1df13c1c6f430f73ad1b9d4bd3c8565c40f82573c81175020062f7e2cba0e39cb272f2d";
        q = "ddbe54ed64de7d7a0379de757bd14b100c9c051b5248f8f88ee513e3069c7ba472b642855dedefc370f378e6c6175efcb4b597cbdc703c94e5c41dcd6eb5296057478e0c18256b5fb162315bc29f437155ad70bbf279df29057a2c9fa4ba9615730621268bd01abae191dc256f7ccdc1ec024b9020e5232900b1b63064039cd60cb6f9c8ee815815e3b674becf31a212999b99c3de13cd7b14db092995d8fe7dece98c9eb79dff7fefa7184301b06efa66c9eea0cb4e6bfb6a0af1a9f1c6f463";
        m = "a1aaa55c1f6b6e100d3258062bc20a316e8ce02ff9cfa1c9df110ee7be9289309090d7f9858ccf78a32949ed41f2a7ff1784689f7ed20a01f978e8c064f311f6f3f65fa23380e1618a62d04712a34d3be3b433b67434f0dade2cf333dcbc72c764708496c0b96532977e7f5f60bf921aa46cf586fb771b18dbbda728d8e61c45fffa9fdddefa2850379ae5c457d22ecd84f9385ff4c40ae1255f4abde4f926d25a6b681b7b703645d8bb418624bdd9cbb4e69ffdd02038266baefb5d9a76b2a218eba8f7aab54974a74059791446dbe31e2c2a8af162dd68c309452c66319d6005a8410f9001331b16a6882b733a1a73e7507b9d54162295af7ba3631134e12e8870fa462b6e5d4ea0ab3c5d495c64c76df92a1e2ec6d468d6314e0e6924a88497a2b08b3dcbfdb4884b8f66d586c18f8e3e16fad71c5e9f0a9e0ad6f0398e369847db01e1952ff81e8d36f851498eff1fb06da8d5c1ad0259b0b5732fea792239b24e21708eab8b303c63572652efefcf5871a205fa20fe47ab9af14e4bf435";
        d = "25adc60ffedb7f08c53a5661b495a09e5ef6d2250195875923e620c3d80afdc59b2131ce9832db9021422af41b8f37201a9c1f939743dda1702f72baeecb4db26b505932791432b02adadbaf42648396dc4b49fe90750795ed8bb9e2d4963a31e262fdd83b572cd96ae305c54fab42411e7afbfbce7f0c2a52d2508594155992d11681ec66f02a9107a0bcfb0bc4bf886823d0b1f63293b0a31fc9437a24815ef9ccc8f85596195d2d722d9f72252d2ffb5d93612bac999514dda544c2b7ebfa32318276d88f3e027067ba0ca84e1d3eba6112d0f03673b7fbf2a871de4de93d52f8a78657d7267cb99f675f00fce87c62bdda8d1c39409c3465bac3445dbb0439c7707b09cf2d7e75789bfb78dba14a4eae9579f73c5df1afc307dddfa29b67ea7a5a5c932699c2c4be7f40ca9150932f50db9374d02769601c1222481f61c3353cc8059b407a479af01dffbfeeabd8ba97c0a679d874d4cee9a2249dbdf47bb532a7cabb7abadc7a6b85bc4f605a07bba5b42dd24ed149d6f87ce54110f5e7";
        if(verbose) diag("Build FIPS key pair %d", i++);
        ok(RSAFIPS_Make_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d) == 0, "Successfully Built RSA KeyPair");

        e = 0x78963b;
        xp1 = "2733f044e950d97eaea4463ebb68718f6d";
        //p1 = 2733f044e950d97eaea4463ebb68718fd3
        xp2 = "12179c6fb04940edeea0223623";
        //p2 = 12179c6fb04940edeea0223661
        xp = "e8637d8cd28dfe250959eb0aa45d402fadf862c9b48674d0a9d572cc8d57bcc520e063140d36dd73dc94a70b5b1e275ebcf1601af3633987994ec2e3d0125ba3";
        p = "e8637d8cd28dfe250959eb0aa45d402fadf862c9b48674d0a9d572cc8d57bcc520e45427ae56bc1f304447870f5f4af7b927d3e060c05ea78c8e412080ece86d";
        xq1 = "c808b18d339b6124594c06b9c94841cf17";
        //q1 = c808b18d339b6124594c06b9c94841cf4d
        xq2 = "15dd1a787b3e9470cf7fb5df2d";
        //q2 = 15dd1a787b3e9470cf7fb5df69
        xq = "e95707ab2c5b717284195ec005079e1c48bd5744b4cbb916e002b809df7f5c4455dbb47fa2decbc078eaea54e03080a64ba9888c6239215c9235bcfb8ee83e90";
        q = "e95707ab2c5b717284195ec005079e1c48bd5744b4cbb916e002b809df7f5c4455e72cb48debd7915bda684ebdbe601a6299eb23163a5a6e215b8a99cf32eaa3";
        m = "d3d18e0af1a69d514ec770bf207dd43c0406b5c4ceb0dbd8c21b7f6da8252e3250859442b0b3a8f55581a0117253fcf0e4669950dbaf9012cc23fa539a84bd621b25431fde3b798b70d6dd0a936f187b618ae5e20f6f9c444588a9fc47b61a3c47ed860771fc55ecfc716bec55a7eb93921d741f25e2e689f55496e52b959f67";
        d = "34742945247a5740550f0805f02c774b5db8730d7f44159973952761cadacf40a5615a79e1e00a78b2b287785d09152f14b87a2491ffba7f9121384f063066835e6515e871e96b6b3e89be2f68b4b7aa490fc3c0d142b1a9366b1aee4127488c5be1a90d64e6b3aadaf98dc824291dc961c7ec4bacbca238533d29f1fd45c7eb";
        if(verbose) diag("Build FIPS key pair %d", i++);
        ok(RSAFIPS_Make_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d) == 0, "Successfully Built RSA KeyPair");

        e = 0x3dadb7;
        xp1 = "36a675e92a9ced61319c98fa45ca6e141bab41a0225d7bbcc124d7b289783ac20bbcab363848d77a4f";
        //p1 = 36a675e92a9ced61319c98fa45ca6e141bab41a0225d7bbcc124d7b289783ac20bbcab363848d77b6d
        xp2 = "00aa64b0cb733c50d3666d41a302a956621bba634c3c19019f67ccd988ed528143b62799b1d548b919";
        //p2 = 00aa64b0cb733c50d3666d41a302a956621bba634c3c19019f67ccd988ed528143b62799b1d548b9ab
        xp = "ba5db7ce3d0dde423bec2ddbe4e1636425c30d0da51d3069ad8ce657157cded05f73713bb90ab3e48d80b9a8f5bc9a9f90683757498085bf9f7de8ce91a81c5a3351d0445257aac04bd4d2ef924c5780452fef01403a640edea40641e1531dced7cc3280305923281bb44a0f02e1e01b43884ccf97f6504499f2492376da0619301945269aadc7ad5007e948d1121430d36dc32e31a6837b6a7f5b0bbf28de709e885af5a3daf286abe0b2b26cb34caa99392f0e552450e41712526495f60c7d";
        p = "ba5db7ce3d0dde423bec2ddbe4e1636425c30d0da51d3069ad8ce657157cded05f73713bb90ab3e48d80b9a8f5bc9a9f90683757498085bf9f7de8ce91a81c5a3351d0445257aac04bd4d2ef924c5780452fef01403a640edea40641e1531dced7cc3280305923281bb44a0f02e29bc57a77a19bc173986d4f3991f4e78ff4f1b630c725fe1f6e3dd2318afbf9f111d8071305357f2bd10303166dad0334b98f40d53845793803f4788dc9ec568d1a3d08e0a227e4b740ee8d85b5dd06052d17";
        xq1 = "1d4f1147ca43912983c2c74caa928be0256b3b2b2570921b4dc0d7";
        //q1 = 1d4f1147ca43912983c2c74caa928be0256b3b2b2570921b4dc0e7
        xq2 = "07760dcd8ddc59657ac0794e1c6d598f94a2042292ebe7c7866bc24d1f";
        //q2 = 07760dcd8ddc59657ac0794e1c6d598f94a2042292ebe7c7866bc24d55
        xq = "ede277b3716d4ab749a068da372d316d510dbdbe33d4df4b6cf3b1d5aa9323c75e7c02a1dcaeb578d70324aef881cb39ba97a6d0aa648082aa88c1f3dbc30471c4256748c0dc46bd3b4f4704cf4137f360ab770d1c1168054169e3abbf4bf4c4edf48aba2a451ad69f579abef1b2d7798bd447e66d5c3d6a3a21f2113b2c45002cbf8206ae68fc799442b27ae4bf63e1892d0d08aa696e6b08aed00d9258c8756b08a862a84bad8d942ecf5e598a940b3824caad9114dec17860f185a7c777be";
        q = "ede277b3716d4ab749a068da372d316d510dbdbe33d4df4b6cf3b1d5aa9323c75e7c02a1dcaeb578d70324aef881cb39ba97a6d0aa648082aa88c1f3dbc30471c4256748c0dc46bd3b4f4704cf4137f360ab770d1c1168054169e3abbf4bf4c4edf48aba2a451ad69f579abef1b2d7798bd447e66d5c3d6a3a21f2113b2c45002cbf8206ae68fc7b7dbcc4f070cd5fa0bc0f66abb4dc968469acae8236c75e8184b4ccd18fc1d6157e057038d12be329917d476f0cbf23b67e70defdb827015f";
        m = "ad2da10a65230f057c725f87e33e3f0785f553370db587a35d274e5f5b7f0c88502e339149d491ae2ae812b47e7633fcb9d3b3a5271e94c00d1d28943b5a960d541122e55b1d7d322c22f9bc74edf87a49100d2b0ab2e270b31a8d98885d0eb540c879755d2e4a3fc614029ba4c1b9b73e7e2f17f70c0d1003af17efd9cdd70cb88847d7e141e4825916f77ea2a811892302a0ec58ccdc01fd491de1a463699c46128381f29020a4a436055e2f3f153841b1c57390a7fba65382d7e6f337fc672144326e59eef53b0f0155339eae5565a8e662fdad4bce3350decec593355a015a8416325e6f636c33427d317517d642fbee857300bb7664a83195d5f99e86abb7be0c499988d998e3f61c6e0cb44eb76a3bc25dc5a46b0443a71531a8a12b9d2c08bf2626522091c67f51063e7788ae8aa1fa14e63c49ff2efedd0794f5cc1e5fb0004bc4c2a201d03eb64cbd33b8b27578e51c7c215a6822b5dd8ae040b56d8d890440b54373c8096129554ffc2ad659fcd4aed0d679a0179b7ef8a799d289";
        d = "51ce416ca3cbd04124e26f739f8e7f0a74d879b2b99b31a06eb1e71627e13982542f9130942e3a6dcaba33321aaf4d5dd3d22b437c74182f54d4a6321131c1146043a591da8fa22b74da6ffbaa803993f3292910fe57236ca02b6dc14b531b894ded0dd814f6c5dc01e31a55319eef05610f0734a5a782135bfb60861e2f6f0fea663a89d681a9cab53382a27535c84563de40317b7155e8904195ca874f7be6e87e8fd16eee4264890e5b6236be09f01cdff1354751b94351bff7af5b07084295bd2381abe2e7b22d8514bfe959403d43fdb1593d2b04dbf983194f04f2e9faef9dfcc4815ae12f3b9a10c55aa985040ea42a657b8306cfac4cdb6199825bb8092c1149e9b002bb40948942e2b06e0ae478ce8202f99361fcaf78b0e01fc2006cf1c2e49f52d1715501abee47db1aeb32cf83b73ffd9f61b8a5d7bfb31bf6d71cc202e5bc5f835a92ed24946fdefe3089c6ceb68caac0f8c0bcca9589ef1cf9a4d8b8acbfc2235a1a81847546c9ce6af5b33ca66f5eb43f97155dff6c445933";

            if(verbose) diag("Build FIPS key pair %d\n", i++);
            ok(RSAFIPS_Make_Test(e, xp1, xp2, xp, xq1, xq2, xq, p, q, m, d) == 0, "Successfully Built RSA KeyPair");

    } /* fipsmake_kat */

    return 0;
}
#endif

