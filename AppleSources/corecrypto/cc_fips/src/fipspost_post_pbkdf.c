/* Copyright (c) (2020-2022) Apple Inc. All rights reserved.
*
* corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
* is contained in the License.txt file distributed with corecrypto) and only to
* people who accept that license. IMPORTANT:  Any license rights granted to you by
* Apple Inc. (if any) are limited to internal use within your organization only on
* devices and computers you own or control, for the sole purpose of verifying the
* security characteristics and correct functioning of the Apple Software.  You may
* not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

#include "cc_error.h"
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsha3.h>
#include <corecrypto/ccpbkdf2.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_pbkdf.h"

int fipspost_post_pbkdf(uint32_t fips_mode)
{
    /*
    {
      "tcId" : 8,
      "hmacAlg" : "SHA-1",
      "keyLen" : 1144,
      "salt" : "0EDD6738CE8A1F7D973F23AC70431CBFD054503093",
      "password" : "roAhfqRBzTqHATLXmmLLiQIyBUchpmcqrXWMWoztGqWZrEbqIZFKWphBFbGkoJmnRaqDXZaYMreSUJhWTLypGstb",
      "iterationCount" : 881,
      "derivedKey":"25e718c0753dd18acf84530efe22bb30b3d865c533ed7ac4f930291330f503460d4669cea1c5b3b078fc305956730a5c347099ae658b3c2e0bc85d92ee265b8c488eaac0b13ed1b376a9511fb0855c9ad5295b63037c0af81505c0cf89c6ea4790edc39e80d6182f82f342509ad5a77acf76520f971cea634d8c23aae1eac240259fb4ce5f7c5e3af2881832a9435a"
    }
    */

    const size_t pbkdfSha1PasswordLength = 88;
    unsigned char* pbkdfSha1Password = (unsigned char*)
        "roAhfqRBzTqHATLXmmLLiQIyBUchpmcqrXWMWoztGqWZrEbqIZFKWphBFbGkoJmnRaqDXZaYMreSUJhWTLypGstb";

    const size_t pbkdfSha1SaltLength = 21;
    unsigned char* pbkdfSha1Salt = (unsigned char*)
        "\x0e\xdd\x67\x38\xce\x8a\x1f\x7d\x97\x3f\x23\xac\x70\x43\x1c\xbf"
        "\xd0\x54\x50\x30\x93";

    const size_t pbkdfSha1Iterations = 881;

    unsigned char* pbkdfSha1Key = POST_FIPS_RESULT_STR(
        "\x25\xe7\x18\xc0\x75\x3d\xd1\x8a\xcf\x84\x53\x0e\xfe\x22\xbb\x30"
        "\xb3\xd8\x65\xc5\x33\xed\x7a\xc4\xf9\x30\x29\x13\x30\xf5\x03\x46"
        "\x0d\x46\x69\xce\xa1\xc5\xb3\xb0\x78\xfc\x30\x59\x56\x73\x0a\x5c"
        "\x34\x70\x99\xae\x65\x8b\x3c\x2e\x0b\xc8\x5d\x92\xee\x26\x5b\x8c"
        "\x48\x8e\xaa\xc0\xb1\x3e\xd1\xb3\x76\xa9\x51\x1f\xb0\x85\x5c\x9a"
        "\xd5\x29\x5b\x63\x03\x7c\x0a\xf8\x15\x05\xc0\xcf\x89\xc6\xea\x47"
        "\x90\xed\xc3\x9e\x80\xd6\x18\x2f\x82\xf3\x42\x50\x9a\xd5\xa7\x7a"
        "\xcf\x76\x52\x0f\x97\x1c\xea\x63\x4d\x8c\x23\xaa\xe1\xea\xc2\x40"
        "\x25\x9f\xb4\xce\x5f\x7c\x5e\x3a\xf2\x88\x18\x32\xa9\x43\x5a");

    unsigned char dk1[1144 / 8 /* length of pbkdfSha1Key */];
    memset(dk1, 0, sizeof(dk1));

    int ret = ccpbkdf2_hmac(ccsha1_di(),
                            pbkdfSha1PasswordLength, pbkdfSha1Password,
                            pbkdfSha1SaltLength, pbkdfSha1Salt,
                            pbkdfSha1Iterations,
                            sizeof(dk1), dk1);

    if (ret != 0) {
        failf("failed ccpbkdf2_hmac (SHA-1): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(pbkdfSha1Key, dk1, sizeof(dk1))) {
        failf("failed PBKDF_SHA1 KAT");
        return CCPOST_KAT_FAILURE;
    }

    /*
    {
      "tcId" : 107,
      "hmacAlg" : "SHA2-256",
      "keyLen" : 520,
      "salt" : "8B81B846FC7BD0897D6976776F6F1B65BFB94D922B66492D5C4C8C82",
      "password" : "PpKpAmtfcDCPtAtwRMnHBueaQklIgpzLiH",
      "iterationCount" : 768,
      "derivedKey":"70cc738725a713671ce2a36332869c3914c521c3b82ab97493524d7e2ad52c034aa2fd07f1015b23458471a49eb732bba9b046b3f8f5907ccf969c5c76f722fbbb"
    }
    */

    const size_t pbkdfSha256PasswordLength = 34;
    unsigned char* pbkdfSha256Password = (unsigned char*)
        "PpKpAmtfcDCPtAtwRMnHBueaQklIgpzLiH";

    const size_t pbkdfSha256SaltLength = 28;
    unsigned char* pbkdfSha256Salt = (unsigned char*)
        "\x8b\x81\xb8\x46\xfc\x7b\xd0\x89\x7d\x69\x76\x77\x6f\x6f\x1b\x65"
        "\xbf\xb9\x4d\x92\x2b\x66\x49\x2d\x5c\x4c\x8c\x82";

    const size_t pbkdfSha256Iterations = 768;

    unsigned char* pbkdfSha256Key = POST_FIPS_RESULT_STR(
        "\x70\xcc\x73\x87\x25\xa7\x13\x67\x1c\xe2\xa3\x63\x32\x86\x9c\x39"
        "\x14\xc5\x21\xc3\xb8\x2a\xb9\x74\x93\x52\x4d\x7e\x2a\xd5\x2c\x03"
        "\x4a\xa2\xfd\x07\xf1\x01\x5b\x23\x45\x84\x71\xa4\x9e\xb7\x32\xbb"
        "\xa9\xb0\x46\xb3\xf8\xf5\x90\x7c\xcf\x96\x9c\x5c\x76\xf7\x22\xfb"
        "\xbb");

    unsigned char dk2[520 / 8 /* length of pbkdfSha256Key */];
    memset(dk2, 0, sizeof(dk2));

    ret = ccpbkdf2_hmac(ccsha256_di(),
                        pbkdfSha256PasswordLength, pbkdfSha256Password,
                        pbkdfSha256SaltLength, pbkdfSha256Salt,
                        pbkdfSha256Iterations,
                        sizeof(dk2), dk2);

    if (ret != 0) {
        failf("failed ccpbkdf2_hmac (SHA-256): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(pbkdfSha256Key, dk2, sizeof(dk2))) {
        failf("failed PBKDF_SHA2 KAT");
        return CCPOST_KAT_FAILURE;
    }

    /*
    {
      "tcId" : 217,
      "hmacAlg" : "SHA2-512",
      "keyLen" : 2552,
      "salt" : "1C1A2B496297DE6DEDAAE87EB27A0408049C13E8D237038107D3CCA8",
      "password" : "SeiPcvDyiAvRsPPKX",
      "iterationCount" : 580,
      "derivedKey":"2baca76f3bb374ae2e22154eafc30c9786c1d15bdd42ce65a5bd07a1fa4eaa4908681f7e19ca3f28a8958dd9cd7fde9fecdbf20d8d71f20a230c72158a45a1b0ec7f49f8d1a19bfed031272b497a747b083a5668699de01071ddb0dde42f072f0e5d2a349817ce871108852d30f9508b1931332154be5c9703110fe1fb4b7f6fc1b60cda25ebc2e5ec23ce2e4423c7fed6e2a5293da8af5d33ad2e20e59edd2f1eb7dde4811b09b27335e5fe3138ed5ec87ec354ad4fe70782109b7262bf141f0f0aae1472c799ffb66908435054e1f69ba16e658196f5be6d0f9491e54c11ca0faf78ce092ad01ce9661aada0c44bd26bfab775c4667cc8fecebbdec2f9d823cbb3c14bdc49e92608b4b4c320c5635766285789c77b2e13b9c8ea5d3563df20126c1ba15c9459197aa608b0f046dc44aa2f555d898ae64baade1adc9eb923"
    }
    */

    const size_t pbkdfSha512PasswordLength = 17;
    unsigned char* pbkdfSha512Password = (unsigned char*)
        "SeiPcvDyiAvRsPPKX";

    const size_t pbkdfSha512SaltLength = 28;
    unsigned char* pbkdfSha512Salt = (unsigned char*)
        "\x1c\x1a\x2b\x49\x62\x97\xde\x6d\xed\xaa\xe8\x7e\xb2\x7a\x04\x08"
        "\x04\x9c\x13\xe8\xd2\x37\x03\x81\x07\xd3\xcc\xa8";

    const size_t pbkdfSha512Iterations = 580;

    unsigned char* pbkdfSha512Key = POST_FIPS_RESULT_STR(
        "\x2b\xac\xa7\x6f\x3b\xb3\x74\xae\x2e\x22\x15\x4e\xaf\xc3\x0c\x97"
        "\x86\xc1\xd1\x5b\xdd\x42\xce\x65\xa5\xbd\x07\xa1\xfa\x4e\xaa\x49"
        "\x08\x68\x1f\x7e\x19\xca\x3f\x28\xa8\x95\x8d\xd9\xcd\x7f\xde\x9f"
        "\xec\xdb\xf2\x0d\x8d\x71\xf2\x0a\x23\x0c\x72\x15\x8a\x45\xa1\xb0"
        "\xec\x7f\x49\xf8\xd1\xa1\x9b\xfe\xd0\x31\x27\x2b\x49\x7a\x74\x7b"
        "\x08\x3a\x56\x68\x69\x9d\xe0\x10\x71\xdd\xb0\xdd\xe4\x2f\x07\x2f"
        "\x0e\x5d\x2a\x34\x98\x17\xce\x87\x11\x08\x85\x2d\x30\xf9\x50\x8b"
        "\x19\x31\x33\x21\x54\xbe\x5c\x97\x03\x11\x0f\xe1\xfb\x4b\x7f\x6f"
        "\xc1\xb6\x0c\xda\x25\xeb\xc2\xe5\xec\x23\xce\x2e\x44\x23\xc7\xfe"
        "\xd6\xe2\xa5\x29\x3d\xa8\xaf\x5d\x33\xad\x2e\x20\xe5\x9e\xdd\x2f"
        "\x1e\xb7\xdd\xe4\x81\x1b\x09\xb2\x73\x35\xe5\xfe\x31\x38\xed\x5e"
        "\xc8\x7e\xc3\x54\xad\x4f\xe7\x07\x82\x10\x9b\x72\x62\xbf\x14\x1f"
        "\x0f\x0a\xae\x14\x72\xc7\x99\xff\xb6\x69\x08\x43\x50\x54\xe1\xf6"
        "\x9b\xa1\x6e\x65\x81\x96\xf5\xbe\x6d\x0f\x94\x91\xe5\x4c\x11\xca"
        "\x0f\xaf\x78\xce\x09\x2a\xd0\x1c\xe9\x66\x1a\xad\xa0\xc4\x4b\xd2"
        "\x6b\xfa\xb7\x75\xc4\x66\x7c\xc8\xfe\xce\xbb\xde\xc2\xf9\xd8\x23"
        "\xcb\xb3\xc1\x4b\xdc\x49\xe9\x26\x08\xb4\xb4\xc3\x20\xc5\x63\x57"
        "\x66\x28\x57\x89\xc7\x7b\x2e\x13\xb9\xc8\xea\x5d\x35\x63\xdf\x20"
        "\x12\x6c\x1b\xa1\x5c\x94\x59\x19\x7a\xa6\x08\xb0\xf0\x46\xdc\x44"
        "\xaa\x2f\x55\x5d\x89\x8a\xe6\x4b\xaa\xde\x1a\xdc\x9e\xb9\x23");

    unsigned char dk3[2552 / 8 /* Length of pbkdfSha512Key */];
    memset(dk3, 0, sizeof(dk3));

    ret = ccpbkdf2_hmac(ccsha512_di(),
                        pbkdfSha512PasswordLength, pbkdfSha512Password,
                        pbkdfSha512SaltLength, pbkdfSha512Salt,
                        pbkdfSha512Iterations,
                        sizeof(dk3), dk3);

    if (ret != 0) {
        failf("failed ccpbkdf2_hmac (SHA-512): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(pbkdfSha512Key, dk3, sizeof(dk3))) {
        failf("failed PBKDF_SHA512 KAT");
        return CCPOST_KAT_FAILURE;
    }

#if !CC_KERNEL
    // SHA 3. We reuse the passphrase and salt from SHA1 KAT, set the iterations to 1000, and output 32 bytes.
    unsigned char dk_sha3[32];
    size_t iterations_sha3 = 1000;
/*
import pbkdf2
import hashlib
s224 = pbkdf2.PBKDF2(passphrase=bytes("roAhfqRBzTqHATLXmmLLiQIyBUchpmcqrXWMWoztGqWZrEbqIZFKWphBFbGkoJmnRaqDXZaYMreSUJhWTLypGstb", "utf8"), salt=bytes.fromhex("0EDD6738CE8A1F7D973F23AC70431CBFD054503093"), digestmodule=hashlib.sha3_224, iterations=1000).read(32).hex()
s256 = pbkdf2.PBKDF2(passphrase=bytes("roAhfqRBzTqHATLXmmLLiQIyBUchpmcqrXWMWoztGqWZrEbqIZFKWphBFbGkoJmnRaqDXZaYMreSUJhWTLypGstb", "utf8"), salt=bytes.fromhex("0EDD6738CE8A1F7D973F23AC70431CBFD054503093"), digestmodule=hashlib.sha3_256, iterations=1000).read(32).hex()
s384 = pbkdf2.PBKDF2(passphrase=bytes("roAhfqRBzTqHATLXmmLLiQIyBUchpmcqrXWMWoztGqWZrEbqIZFKWphBFbGkoJmnRaqDXZaYMreSUJhWTLypGstb", "utf8"), salt=bytes.fromhex("0EDD6738CE8A1F7D973F23AC70431CBFD054503093"), digestmodule=hashlib.sha3_384, iterations=1000).read(32).hex()
s512 = pbkdf2.PBKDF2(passphrase=bytes("roAhfqRBzTqHATLXmmLLiQIyBUchpmcqrXWMWoztGqWZrEbqIZFKWphBFbGkoJmnRaqDXZaYMreSUJhWTLypGstb", "utf8"), salt=bytes.fromhex("0EDD6738CE8A1F7D973F23AC70431CBFD054503093"), digestmodule=hashlib.sha3_512, iterations=1000).read(32).hex()
printdigest = lambda s: print("\\x" + "\\x".join(s[i:i+2] for i in range(0, len(s), 2)))
printdigest(s224)
printdigest(s256)
printdigest(s384)
printdigest(s512)
*/
    unsigned char* pbkdf2_sha3_224_key = POST_FIPS_RESULT_STR("\x16\xd1\x47\x43\x97\xe5\x2a\x54\x47\x44\xb6\xec\x78\xb3\x72\x9a\x73\xa0\x16\x3c\x1f\x29\x7d\x34\x5b\x6e\xd3\x51\xc5\x5c\xac\xd3");
    unsigned char* pbkdf2_sha3_256_key = POST_FIPS_RESULT_STR("\xe1\x6f\xdb\x97\xd0\xd9\xe8\x91\xc4\xe0\x1a\xe9\x35\xbf\x3d\x5a\x40\x83\x87\x2f\xd9\x06\x98\x3b\x84\x03\x6f\xae\x3e\x0f\xa0\x66");
    unsigned char* pbkdf2_sha3_384_key = POST_FIPS_RESULT_STR("\x5a\xbc\x17\x43\xa8\x4a\xe3\xda\xaa\xf0\x70\x4b\xa6\xff\xc9\x33\x7b\x1f\x99\x14\xf7\xfa\xfc\x3f\x3e\x6f\x7e\x09\xef\xd5\x31\x96");
    unsigned char* pbkdf2_sha3_512_key = POST_FIPS_RESULT_STR("\x96\xba\x8c\x13\x25\xbe\x7e\x7f\x6c\x62\x97\x2a\x5b\xb5\xce\xd4\xff\x8f\xc8\x90\x5b\xa8\xaa\x65\x7a\x29\xaa\xc5\x23\x7c\xde\x86");
    
    ret = ccpbkdf2_hmac(ccsha3_224_di(),
                        pbkdfSha1PasswordLength, pbkdfSha1Password,
                        pbkdfSha1SaltLength, pbkdfSha1Salt,
                        iterations_sha3,
                        sizeof(dk_sha3), dk_sha3);
    if (ret != 0) {
        failf("failed ccpbkdf2_hmac (SHA3-224): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }
    if (memcmp(pbkdf2_sha3_224_key, dk_sha3, sizeof(dk_sha3))) {
        failf("failed PBKDF_SHA3_224 KAT");
        return CCPOST_KAT_FAILURE;
    }
    
    ret = ccpbkdf2_hmac(ccsha3_256_di(),
                        pbkdfSha1PasswordLength, pbkdfSha1Password,
                        pbkdfSha1SaltLength, pbkdfSha1Salt,
                        iterations_sha3,
                        sizeof(dk_sha3), dk_sha3);
    if (ret != 0) {
        failf("failed ccpbkdf2_hmac (SHA3-256): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }
    if (memcmp(pbkdf2_sha3_256_key, dk_sha3, sizeof(dk_sha3))) {
        failf("failed PBKDF_SHA3_256 KAT");
        return CCPOST_KAT_FAILURE;
    }
    
    ret = ccpbkdf2_hmac(ccsha3_384_di(),
                        pbkdfSha1PasswordLength, pbkdfSha1Password,
                        pbkdfSha1SaltLength, pbkdfSha1Salt,
                        iterations_sha3,
                        sizeof(dk_sha3), dk_sha3);
    if (ret != 0) {
        failf("failed ccpbkdf2_hmac (SHA3-384): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }
    if (memcmp(pbkdf2_sha3_384_key, dk_sha3, sizeof(dk_sha3))) {
        failf("failed PBKDF_SHA3_384 KAT");
        return CCPOST_KAT_FAILURE;
    }
    
    ret = ccpbkdf2_hmac(ccsha3_512_di(),
                        pbkdfSha1PasswordLength, pbkdfSha1Password,
                        pbkdfSha1SaltLength, pbkdfSha1Salt,
                        iterations_sha3,
                        sizeof(dk_sha3), dk_sha3);
    if (ret != 0) {
        failf("failed ccpbkdf2_hmac (SHA3-512): %d", ret);
        return CCPOST_GENERIC_FAILURE;
    }
    if (memcmp(pbkdf2_sha3_512_key, dk_sha3, sizeof(dk_sha3))) {
        failf("failed PBKDF_SHA3_512 KAT");
        return CCPOST_KAT_FAILURE;
    }
#endif

    return CCERR_OK;
}
