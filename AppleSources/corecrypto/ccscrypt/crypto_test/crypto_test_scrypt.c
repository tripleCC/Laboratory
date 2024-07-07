/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
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

#if (CCSCRYPT == 0)
entryPoint(ccscrypt_tests, "ccscrypt test")
#else
#include <corecrypto/ccscrypt.h>
#include "ccscrypt_internal.h"
#include "cc_priv.h"

static void
test_ccscrypt_salsa20_8(void)
{
    char *input_hex = "7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1dee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e";
    char *output_hex = "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81";
    byteBuffer input_bytes = hexStringToBytes((char *) input_hex);
    byteBuffer output_bytes = hexStringToBytes((char *) output_hex);

    uint8_t output[64];
    ccscrypt_salsa20_8(input_bytes->bytes, output);

    is(cc_cmp_safe(sizeof(output), output, output_bytes->bytes), 0, "ccscrypt_salsa20_8 test vector from RFC7914 $8 failed");

    free(input_bytes);
    free(output_bytes);
}

static void
test_ccscrypt_blockmix_salsa8(void)
{
    char *input_hex = "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b067d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89";
    char *output_hex = "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f8120edc975323881a80540f64c162dcd3c21077cfe5f8d5fe2b1a4168f953678b77d3b3d803b60e4ab920996e59b4d53b65d2a225877d5edf5842cb9f14eefe425";

    byteBuffer input_bytes = hexStringToBytes((char *) input_hex);
    byteBuffer output_bytes = hexStringToBytes((char *) output_hex);

    uint8_t Y[128];
    ccscrypt_blockmix_salsa8(input_bytes->bytes, Y, 1);

    is(cc_cmp_safe(output_bytes->len, output_bytes->bytes, input_bytes->bytes), 0, "ccscrypt_blockmix_salsa8 test vector from RFC7914 $9 failed");

    free(input_bytes);
    free(output_bytes);
}

static void
test_ccscrypt_romix(void)
{
    char *input_hex = "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b067d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89";
    char *output_hex = "79ccc193629debca047f0b70604bf6b62ce3dd4a9626e355fafc6198e6ea2b46d58413673b99b029d665c357601fb426a0b2f4bba200ee9f0a43d19b571a9c71ef1142e65d5a266fddca832ce59faa7cac0b9cf1be2bffca300d01ee387619c4ae12fd4438f203a0e4e1c47ec314861f4e9087cb33396a6873e8f9d2539a4b8e";

    byteBuffer input_bytes = hexStringToBytes((char *) input_hex);
    byteBuffer output_bytes = hexStringToBytes((char *) output_hex);

    size_t r = 1;
    size_t N = 16;
    uint8_t V[128 * r * N];
    uint8_t X[128 * r];
    uint8_t Y[128 * r];
    ccscrypt_romix(r, input_bytes->bytes, N, V, X, Y);

    is(cc_cmp_safe(output_bytes->len, output_bytes->bytes, input_bytes->bytes), 0, "ccscrypt_romix test vector from RFC7914 $10 failed");

    free(input_bytes);
    free(output_bytes);
}

typedef struct {
    uint8_t *password;
    uint8_t *salt;
    uint64_t N;
    uint32_t r;
    uint32_t p;
    size_t dk_len;
    char *dk;
} test_ccscrypt_vector;

// Test vectors from https://tools.ietf.org/html/rfc7914. There is a
// fourth vector that allocates over 1GB of memory. This usage is
// unrealistic and impractical to test on many platforms, so it has
// been elided here.

static const test_ccscrypt_vector test_ccscrypt_vectors[] = {
    {
        .password = NULL,
        .salt = NULL,
        .N = 16,
        .r = 1,
        .p = 1,
        .dk_len = 64,
        .dk = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
    },
    {
        .password = (uint8_t *)"password",
        .salt = (uint8_t *)"NaCl",
        .N = 1024,
        .r = 8,
        .p = 16,
        .dk_len = 64,
        .dk = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    },
    {
        .password = (uint8_t *)"pleaseletmein",
        .salt = (uint8_t *)"SodiumChloride",
        .N = 16384,
        .r = 8,
        .p = 1,
        .dk_len = 64,
        .dk = "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
    },
};

static const size_t test_ccscrypt_vectors_len = CC_ARRAY_LEN(test_ccscrypt_vectors);

static void
test_ccscrypt(void)
{
    for (size_t i = 0; i < test_ccscrypt_vectors_len; i++) {
        test_ccscrypt_vector test = test_ccscrypt_vectors[i];

        byteBuffer expected = hexStringToBytes((char *)test.dk);
        uint8_t actual[test.dk_len];

        uint8_t *password = (uint8_t *)test.password;
        size_t password_len = password == NULL ? 0 : strlen((char *)test.password);
        uint8_t *salt = (uint8_t *)test.salt;
        size_t salt_len = salt == NULL ? 0 : strlen((char *)test.salt);

        int64_t buffer_size = ccscrypt_storage_size(test.N, test.r, test.p);
        uint8_t *buffer = (uint8_t *)malloc((size_t)buffer_size);
        if (buffer == NULL) {
            diag("warning: allocation failed");
            goto cleanup;
        }

        memset(buffer, 0, (size_t)buffer_size);

        ccscrypt(password_len, test.password, salt_len, test.salt, buffer, test.N, test.r, test.p, test.dk_len, actual);
        free(buffer);

        is(cc_cmp_safe(test.dk_len, actual, expected->bytes), 0, "test_ccscrypt test %zu failed", i);

    cleanup:
        free(expected);
    }
}

static void
test_ccscrypt_valid_parameters(void)
{
    uint64_t N = 0;
    uint32_t r = 0;
    uint32_t p = 0;

    is(ccscrypt_valid_parameters(N, r, p), CCERR_PARAMETER, "ccscrypt_valid_parameters(%llu, %u, %u) failed", N, r, p);

    N = 3; // not power of 2
    is(ccscrypt_valid_parameters(N, r, p), CCERR_PARAMETER, "ccscrypt_valid_parameters(%llu, %u, %u) failed", N, r, p);

    N = 2;
    r = 1;
    p = (UINT32_MAX - 1) * 32 / (128 * r); // p = ((2^32-1) * 32) / (128 * r)
    is(ccscrypt_valid_parameters(N, r, p), 0, "ccscrypt_valid_parameters(%llu, %u, %u) failed", N, r, p);

    p = p + 1; // p > ((2^32-1) * 32) / (128 * r)
    is(ccscrypt_valid_parameters(N, r, p), CCERR_PARAMETER, "ccscrypt_valid_parameters(%llu, %u, %u) failed", N, r, p);
}

int ccscrypt_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(7 + test_ccscrypt_vectors_len);

    test_ccscrypt_salsa20_8();
    test_ccscrypt_blockmix_salsa8();
    test_ccscrypt_romix();
    test_ccscrypt();
    test_ccscrypt_valid_parameters();

    return 0;
}
#endif // (CCSCRYPT != 0)

