/* Copyright (c) (2017,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsha3.h>
#include <corecrypto/cchmac.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_hmac.h"
#include "cc_priv.h"

// Test HMAC
int fipspost_post_hmac(uint32_t fips_mode)
{
    int status = CCERR_OK;
    const struct ccdigest_info *sha1 = ccsha1_di();
    const struct ccdigest_info *sha256 = ccsha256_di();
    const struct ccdigest_info *sha512 = ccsha512_di();
    const struct ccdigest_info *sha512_256 = ccsha512_256_di();

#if !CC_KERNEL
    const struct ccdigest_info *sha3_224 = ccsha3_224_di();
    const struct ccdigest_info *sha3_256 = ccsha3_256_di();
    const struct ccdigest_info *sha3_384 = ccsha3_384_di();
    const struct ccdigest_info *sha3_512 = ccsha3_512_di();
#endif

    typedef struct {
        const struct ccdigest_info *digest_info;
        size_t key_size;
        unsigned char *key_buffer;
        size_t msg_size;
        unsigned char *msg_buffer;
        size_t digest_size;
        unsigned char *digest_buffer;
        unsigned char *digest_name;
    } hmac_test;

    // HMAC-SHA1 Test Data
    unsigned char *hmacSha1KeyBuffer;
    hmacSha1KeyBuffer = POST_FIPS_RESULT_STR(
        "\xee\xd8\x1b\x81\x31\x2a\x16\xfa\xc6\xa8\x1e\x98\x05\xe1\xd7\x84\x44\x5b\xff\x8c\xe6\x84\x99\xbe\x95\xeb\x4a\x36\xcb\xb0"
        "\x03\x34\x97\x3a\xe0\x72\x9e\x27\x50\xb4\x60\x89\x77\xa0\xbc\x4f\xd0\xd0\xb6\x01");

    const size_t hmacSha1KeyBufferLength = 50;
    unsigned char *sha1MsgBuffer =
        (unsigned char
             *)"\xf0\x6b\xb4\x5b\xd0\x60\x58\x27\x82\x4c\xd0\x4d\xa7\x5b\x68\x7a\x86\xc9\x39\xef\xaf\xf9\xf1\x32\xdd\xc1\xd7\x04"
               "\x21\x08\x09\x94\x3d\x94\x08\xf2\x4e\x1d\x77\xc6\xaf\xa6\x20\x42\x19\x0d\x38\x55\x0f\xe0\xe4\x22\x79\x72\xfc\xb0"
               "\x8f\x2e\x0e\xe3\xf8\x2c\xa6\xab\x33\x02\xcc\x7b\x37\xdd\xcf\xfd\x56\xd0\x41\x04\x67\x6b\x43\xc2\x24\x90\x03\x3b"
               "\xd1\x82\x82\xf9\x1f\x3f\x9b\x01\x4f\x10\x41\x07\x9a\x5e\x08\xde\xd1\xc7\xe6\x32\x41\x71\x3b\x79\xd9\x9e\x10\x27"
               "\x8f\x81\x9c\x21\xff\x51\x0d\x75\x55\x9b\x85\x48\x6e\xdc\x62\x10";
    const size_t sha1MsgBufferLength = 128;
    unsigned char *sha1DigestBuffer =
        (unsigned char *)"\x88\x6e\xae\x70\xf3\x6b\xd3\x80\x5e\xeb\x12\x74\xb3\x24\x8f\xcc\xf5\xe1\x5b\x80";
    const size_t sha1DigestBufferLength = CCSHA1_OUTPUT_SIZE;

    // HMAC-SHA256 Test Data
    unsigned char *hmacSha256KeyBuffer;
    hmacSha256KeyBuffer = POST_FIPS_RESULT_STR(
        "\xf3\xd9\x84\x1c\x78\x2e\x1d\xc8\x4d\x5f\xbd\x95\x23\x68\x3b\x8d\x29\xd1\xd5\x85\x2d\x3a\x74\x52\x04\x38\x32\x3a\x2d\x5f"
        "\x19\xa9\xb1\xa0\x2d\x25\x4d\xd6\xad\x84\xd3\x9b\x97\x5d\xce\x60\x6a\xbc\x65\xbd");
    const size_t hmacSha256KeyBufferLength = 50;
    unsigned char *sha256MsgBuffer =
        (unsigned char
             *)"\xce\xb6\xa4\x96\x7c\xc8\x60\xd3\xb8\x7a\x53\x1c\xb2\x4f\xc5\x31\x76\x35\xbf\x80\x11\x13\x5b\x50\xf6\xa1\x3d\x40"
               "\xa0\x7c\x62\xf0\x78\x7a\x19\xfe\xf8\x3a\x4e\x34\x11\x00\x0e\xff\xca\xc0\x48\x23\x2b\x79\xd1\xae\x59\xc5\xab\x2a"
               "\x02\xad\x87\x17\xfb\xc1\x88\x99\x28\x69\x4a\x6d\x9d\x76\x23\x21\x02\xfc\xa9\x85\x3c\x64\x74\x5d\x4a\xbd\x25\x58"
               "\x6c\x53\xa6\x46\x8b\x83\xb4\x85\xd5\xcd\x9b\xbc\xa8\x2b\x41\xcc\xb1\xa1\x66\x04\x55\x16\x2a\x95\x4f\x62\xd0\x45"
               "\x9b\xa8\xc1\x67\x93\xe6\xd4\x0a\x59\xca\xcc\x71\x74\xc8\x23\xc3";
    const size_t sha256MsgBufferLength = 128;
    unsigned char *sha256DigestBuffer = (unsigned char *)"\xc1\xcc\xf9\x1e\x8e\xa5\x8a\x16\x75\x6b\xe8\xe4\x08\xf3\x08\xc9\xe1"
                                                         "\x02\xea\xe3\x54\x4f\xb6\x36\xdb\x18\x29\x34\x80\xae\xd1\xe1";
    const size_t sha256DigestBufferLength = CCSHA256_OUTPUT_SIZE;

    // HMAC-SHA512 Test Data
    unsigned char *hmacSha512KeyBuffer;
    hmacSha512KeyBuffer = POST_FIPS_RESULT_STR(
        "\x14\x62\x37\xf2\xc2\x3c\x3c\x65\x22\x30\x60\x33\x44\x60\x4f\x29\x56\x92\xc7\xe0\x18\xd5\xa6\x88\x90\x66\x48\xe3\xfe\xd4"
        "\x0f\x94\x12\x63\x43\x9a\x5d\xae\x1d\x18\x06\x91\x1e\x57\xbe\x46\xa5\x0d\xf5\xce\xc1\xe0\x4e\x93\x44\x26\x51\x4b\x19\xef"
        "\x61\x1f\xd7\x45\xed\x0d\x95\xb2\xea\x8b\x01\x03\x80\x6d\xac\x4c\x03\x08\xa8\x2c\x26\x98\x55\x52\x6b\xdf\x78\x40\xde\x0f"
        "\x8d\x4f\x03\xea\x5f\xf4\x0d\x28\xd5\x41\x50\x19\x0f\xaf\xf9\x8b\xb1\x1a\xfd\xee");
    const size_t hmacSha512KeyBufferLength = 110;
    unsigned char *sha512MsgBuffer =
        (unsigned char
             *)"\x94\x14\x7a\x46\xd6\x7e\xef\x0b\x5e\x9f\x99\x24\x0a\xf4\xd3\x14\xa3\x30\x4d\x58\x02\xd6\x54\x9a\x77\x06\x54\x27"
               "\x6b\x97\x9b\xa3\x43\x67\x5f\xfc\x88\xef\x03\x9c\x45\x1b\x96\xe3\xb1\x58\x9d\xd4\x0e\xee\x12\x0e\xd1\x90\xac\xfe"
               "\x03\x31\x61\x54\xe7\x1a\x2a\xb3\xdd\x3a\x06\xad\x86\xbd\x41\xee\x29\xe0\xf6\xb7\x56\x03\xd3\x8f\xc9\xff\x1c\x35"
               "\x90\xbb\xf2\xd8\x71\xfa\xd6\x8a\x86\x77\x69\xf3\x2a\x34\x75\x42\x19\x0f\x31\x69\xd2\x96\xc1\x8a\x40\x1c\xfd\xac"
               "\x9a\x0d\x73\xb3\x88\x7e\xaf\x8f\x87\x08\xba\xb3\x8e\xd7\xe0\xc9";
    const size_t sha512MsgBufferLength = 128;
    unsigned char *sha512DigestBuffer =
        (unsigned char *)"\x57\x05\xbf\xd5\x85\x4b\x7c\xc3\xb7\xc8\xea\xca\x32\x41\x88\x40\xae\xde\x68\xe7\xcd\x62\x1e\x43\x8f"
                         "\x6d\x61\x58\x3b\x45\x61\xfc\xa5\x47\x19\x04\xbd\x79\x22\x89\x59\xa3\x90\x86\x4c\x8a\x70\xa5\x30\x69"
                         "\xda\x41\x72\xca\x34\xc0\xea\x49\x6e\x12\x8d\xcd\xb8\xc3";
    const size_t sha512DigestBufferLength = CCSHA512_OUTPUT_SIZE;

    // HMAC-SHA512/256 Test Data
    unsigned char *hmacSha512_256KeyBuffer;
    hmacSha512_256KeyBuffer = POST_FIPS_RESULT_STR("secret-key");
    const size_t hmacSha512_256KeyBufferLength = 10;
    unsigned char *sha512_256MsgBuffer =
        (unsigned char
             *)"value to digest";
    const size_t sha512_256MsgBufferLength = 15;
    unsigned char *sha512_256DigestBuffer =
        (unsigned char *)"\xaf\x80\xe3\x21\xcc\x60\x77\x64\xd3\x77\xe5\x77\xe2\xc7\x05\xf9\xfb\x33\x89\x93\xe8\x4a\xe4\x4e\x7d\x42\x55\x65\x81\x38\x52\x40";
    const size_t sha512_256DigestBufferLength = CCSHA512_256_OUTPUT_SIZE;

#if !CC_KERNEL
    /* HMAC-SHA3 Test Data
import hmac
import hashlib
printdigest = lambda s: print("\\x" + "\\x".join(s[i:i+2] for i in range(0, len(s), 2)))
printdigest(hmac.digest(key=b'secret-key', msg=b'value to digest', digest=hashlib.sha3_224).hex())
printdigest(hmac.digest(key=b'secret-key', msg=b'value to digest', digest=hashlib.sha3_256).hex())
printdigest(hmac.digest(key=b'secret-key', msg=b'value to digest', digest=hashlib.sha3_384).hex())
printdigest(hmac.digest(key=b'secret-key', msg=b'value to digest', digest=hashlib.sha3_512).hex())
     */
    unsigned char *hmac_sha3_key_buffer = POST_FIPS_RESULT_STR("secret-key");
    const size_t hmac_sha3_key_buffer_nbytes = 10;
    unsigned char *hmac_sha3_msg_buffer = POST_FIPS_RESULT_STR("value to digest");
    const size_t hmac_sha3_msg_buffer_nbytes = 15;
    
    unsigned char *hmac_sha3_224_digest_buffer =
        (unsigned char *)"\x19\xd4\x0e\xce\x01\x57\xaf\x5e\x6d\x66\xee\xd7\x60\xc3\x95\xe6\x4a\xe1\x95\x05\xa0\x6a\x45\x3c\x00\x60\xae\xa1";
    const size_t hmac_sha3_224_digest_buffer_nbytes = CCSHA3_224_OUTPUT_NBYTES;
    unsigned char *hmac_sha3_256_digest_buffer =
        (unsigned char *)"\xe6\x5b\x43\x9a\xd6\x9e\x2d\x0f\xe2\xc4\x15\x4b\x55\x4f\xe9\x96\x2a\x9a\x1e\xce\x26\x84\x65\x42\xb3\xed\x8f\xcb\x16\xf3\x67\xc8";
    const size_t hmac_sha3_256_digest_buffer_nbytes = CCSHA3_256_OUTPUT_NBYTES;
    unsigned char *hmac_sha3_384_digest_buffer =
        (unsigned char *)"\xde\x41\x78\xb5\xfa\xf0\x52\xab\x3e\x40\x9f\x71\x15\x45\x95\x0a\x44\x0c\x8b\xff\x76\x31\xfa\x0f\xe5\xd6\x1b\xc4\xca\x5f\xf9\xce\x14\xe4\x52\x6e\x5d\x7c\x1d\x5f\xd0\xaa\x9d\x63\x22\x12\x62\x7e";
    const size_t hmac_sha3_384_digest_buffer_nbytes = CCSHA3_384_OUTPUT_NBYTES;
    unsigned char *hmac_sha3_512_digest_buffer =
        (unsigned char *)"\xeb\x10\xd9\x65\x80\xbf\x8e\xee\xe5\x46\x0d\x5e\x58\x37\xf5\x55\x57\x09\x01\x13\x39\xb9\x36\xa6\x7b\x75\x37\x7f\x5d\x18\xae\xdb\xf7\x92\xb5\xa6\xf4\xa8\x53\x7b\x40\xd5\x5e\xc5\x0c\x8d\x7d\x5b\x49\x34\xc3\x04\xcc\xeb\xf6\x15\x26\x4b\x2b\x76\x16\xb9\xbf\x1a";
    const size_t hmac_sha3_512_digest_buffer_nbytes = CCSHA3_512_OUTPUT_NBYTES;
#endif
    
    uint8_t outputDigestBuffer[MAX_DIGEST_OUTPUT_SIZE];
    memset(outputDigestBuffer, 0, MAX_DIGEST_OUTPUT_SIZE);

    hmac_test testToRun[] = {
        { sha1,
          hmacSha1KeyBufferLength,
          hmacSha1KeyBuffer,
          sha1MsgBufferLength,
          sha1MsgBuffer,
          sha1DigestBufferLength,
          sha1DigestBuffer,
          (unsigned char *)"sha1" },
        { sha256,
          hmacSha256KeyBufferLength,
          hmacSha256KeyBuffer,
          sha256MsgBufferLength,
          sha256MsgBuffer,
          sha256DigestBufferLength,
          sha256DigestBuffer,
          (unsigned char *)"sha256" },
        { sha512,
          hmacSha512KeyBufferLength,
          hmacSha512KeyBuffer,
          sha512MsgBufferLength,
          sha512MsgBuffer,
          sha512DigestBufferLength,
          sha512DigestBuffer,
          (unsigned char *)"sha512" },
        { sha512_256,
          hmacSha512_256KeyBufferLength,
          hmacSha512_256KeyBuffer,
          sha512_256MsgBufferLength,
          sha512_256MsgBuffer,
          sha512_256DigestBufferLength,
          sha512_256DigestBuffer,
          (unsigned char *)"sha512/256" },
#if !CC_KERNEL
        { sha3_224,
          hmac_sha3_key_buffer_nbytes,
          hmac_sha3_key_buffer,
          hmac_sha3_msg_buffer_nbytes,
          hmac_sha3_msg_buffer,
          hmac_sha3_224_digest_buffer_nbytes,
          hmac_sha3_224_digest_buffer,
          (unsigned char *)"sha3_224" },
        { sha3_256,
          hmac_sha3_key_buffer_nbytes,
          hmac_sha3_key_buffer,
          hmac_sha3_msg_buffer_nbytes,
          hmac_sha3_msg_buffer,
          hmac_sha3_256_digest_buffer_nbytes,
          hmac_sha3_256_digest_buffer,
          (unsigned char *)"sha3_256" },
        { sha3_384,
          hmac_sha3_key_buffer_nbytes,
          hmac_sha3_key_buffer,
          hmac_sha3_msg_buffer_nbytes,
          hmac_sha3_msg_buffer,
          hmac_sha3_384_digest_buffer_nbytes,
          hmac_sha3_384_digest_buffer,
          (unsigned char *)"sha3_384" },
        { sha3_512,
          hmac_sha3_key_buffer_nbytes,
          hmac_sha3_key_buffer,
          hmac_sha3_msg_buffer_nbytes,
          hmac_sha3_msg_buffer,
          hmac_sha3_512_digest_buffer_nbytes,
          hmac_sha3_512_digest_buffer,
          (unsigned char *)"sha3_512" },
#endif
    };

    int numTestToRun = (int)CC_ARRAY_LEN(testToRun);
    for (int iCnt = 0; iCnt < numTestToRun; iCnt++) {
        hmac_test *currentTest = &(testToRun[iCnt]);
        const struct ccdigest_info *di_ptr = currentTest->digest_info;

        cchmac(di_ptr,
               currentTest->key_size,
               currentTest->key_buffer,
               currentTest->msg_size,
               currentTest->msg_buffer,
               outputDigestBuffer);

        if (cc_cmp_safe(currentTest->digest_size, outputDigestBuffer, currentTest->digest_buffer)) {
            failf("digest: %s", currentTest->digest_name);
            status = CCPOST_KAT_FAILURE;
        }
    }

    return status;
}
