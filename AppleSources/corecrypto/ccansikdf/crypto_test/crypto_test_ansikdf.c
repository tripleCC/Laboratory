/* Copyright (c) (2014-2016,2018,2019,2021,2022) Apple Inc. All rights reserved.
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
#include "cc_runtime_config.h"

#if (CCANSIKDF == 0)
entryPoint(ccansikdf_tests,"ccansikdf")
#else
#include "crypto_test_ansikdf.h"
static const int kTestTestCount = 413;

#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include "ccansikdf_internal.h"

#define di_SHA1   &ccsha1_eay_di
#define di_SHA224 &ccsha224_ltc_di
#define di_SHA256 &ccsha256_ltc_di
#define di_SHA384 &ccsha384_ltc_di
#define di_SHA512 &ccsha512_ltc_di

const struct ccansi_kdf_vector kdf_vectors_x963_sha1[]=
{
#include "../test_vectors/ansx963_cavs_sha1.inc"
};

const struct ccansi_kdf_vector kdf_vectors_x963_sha224[]=
{
#include "../test_vectors/ansx963_cavs_sha224.inc"
};

const struct ccansi_kdf_vector kdf_vectors_x963_sha256[]=
{
#include "../test_vectors/ansx963_cavs_sha256.inc"
};

const struct ccansi_kdf_vector kdf_vectors_x963_sha384[]=
{
#include "../test_vectors/ansx963_cavs_sha384.inc"
};

const struct ccansi_kdf_vector kdf_vectors_x963_sha512[]=
{
#include "../test_vectors/ansx963_cavs_sha512.inc"
};

const uint32_t magic=0xFACE;

// Process one vector
static int ccansikdf_x963_vector(const struct ccansi_kdf_vector *test)
{
    size_t output_len=(CC_BITLEN_TO_BYTELEN(test->key_data_length));
    uint8_t output[output_len+sizeof(magic)];
    cc_clear(sizeof(output),output);
    memcpy(&output[output_len],&magic,sizeof(magic));

    byteBuffer Z_data = hexStringToBytes(test->Z);
    byteBuffer SharedInfo_data = hexStringToBytes(test->SharedInfo);
    byteBuffer ExpectedKeyData_data = hexStringToBytes(test->key_data);

    assert(Z_data->len==CC_BITLEN_TO_BYTELEN(test->shared_secret_length));
    assert(SharedInfo_data->len==CC_BITLEN_TO_BYTELEN(test->SharedInfo_length));
    assert(ExpectedKeyData_data->len==output_len);

    ccansikdf_x963(test->di,
                   Z_data->len, Z_data->bytes,
                   SharedInfo_data->len,SharedInfo_data->bytes,
                   output_len,output);

    ok_memcmp_or_fail(output,ExpectedKeyData_data->bytes,ExpectedKeyData_data->len,
                      "Known answer test KDF x963");
    ok_memcmp_or_fail(&output[output_len],&magic,sizeof(magic),
                      "Output overflow KDF x963");
    
    cc_iovec_t shared_data[2] = {
        { .base = SharedInfo_data->bytes, .nbytes = SharedInfo_data->len,},
        { .base = NULL, .nbytes = 0,},
    };
    
    if (SharedInfo_data->len > 1) {
        shared_data[0].nbytes = SharedInfo_data->len - 1;
        shared_data[1].nbytes = 1;
        shared_data[1].base = SharedInfo_data->bytes + (SharedInfo_data->len - 1);
    }
    
    ccansikdf_x963_iovec(test->di,
                         Z_data->len,
                         Z_data->bytes,
                         CC_ARRAY_LEN(shared_data),
                         shared_data,
                         output_len,
                         output);

    ok_memcmp_or_fail(output,ExpectedKeyData_data->bytes,ExpectedKeyData_data->len,
                      "Known answer test KDF x963");
    ok_memcmp_or_fail(&output[output_len],&magic,sizeof(magic),
                      "Output overflow KDF x963");
    
    free(Z_data);
    free(SharedInfo_data);
    free(ExpectedKeyData_data);

    return 1; // Pass
}

// Loop through all vectors
static int ccansikdf_x963_test(const struct ccansi_kdf_vector *test)
{
    size_t test_counter=0;
    int test_status=1;
    const struct ccansi_kdf_vector * current_test=&test[test_counter++];
    while (current_test->di!=NULL && test_status)
    {
        test_status=ccansikdf_x963_vector(current_test);
        current_test=&test[test_counter++];
    }
    return test_status;
}


int ccansikdf_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(kTestTestCount);
    ok_status(ccansikdf_x963_test(kdf_vectors_x963_sha1)!=1,"x9.63 SHA1");
    ok_status(ccansikdf_x963_test(kdf_vectors_x963_sha224)!=1,"x9.63 SHA224");
    ok_status(ccansikdf_x963_test(kdf_vectors_x963_sha256)!=1,"x9.63 SHA256");
    ok_status(ccansikdf_x963_test(kdf_vectors_x963_sha384)!=1,"x9.63 SHA384");
    ok_status(ccansikdf_x963_test(kdf_vectors_x963_sha512)!=1,"x9.63 SHA512");
    return 0;
}

#endif
