/* Copyright (c) (2016,2019,2021) Apple Inc. All rights reserved.
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
#include "ccdrbg_test.h"
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include "cc_priv.h"

#if (CCDRBG == 0)
entryPoint(ccdrbg_tests,"ccdrbg")
#else

static struct ccdrbg_vector nisthmac_sha1_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-1.inc"
};

static struct ccdrbg_vector nisthmac_sha224_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-224.inc"
};

static struct ccdrbg_vector nisthmac_sha256_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-256.inc"
};

#if 0
static struct ccdrbg_vector nisthmac_sha512_224_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-512-224.inc"
};

static struct ccdrbg_vector nisthmac_sha512_256_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-512-256.inc"
};
#endif

static struct ccdrbg_vector nisthmac_sha384_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-384.inc"
};

static struct ccdrbg_vector nisthmac_sha512_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-512.inc"
};

/*
 [SHA-256]
 [PredictionResistance = False]
 [EntropyInputLen = 256]
 [NonceLen = 128]
 [PersonalizationStringLen = 256]
 [AdditionalInputLen = 0]
 [ReturnedBitsLen = 1024]

 COUNT = 0
 EntropyInput = fa0ee1fe39c7c390aa94159d0de97564342b591777f3e5f6a4ba2aea342ec840
 Nonce = dd0820655cb2ffdb0da9e9310a67c9e5
 PersonalizationString = f2e58fe60a3afc59dad37595415ffd318ccf69d67780f6fa0797dc9aa43e144c
 ** INSTANTIATE:
	V   = 8ef5e5870a97c084d1755e84fd741309679c35fa9c7d35daf22209ac26428773
	Key = 7f37fd4ce652ffbe367106d3b36e0111653e8cbe85004d92f18576c93586ca94
 EntropyInputReseed = e0629b6d7975ddfa96a399648740e60f1f9557dc58b3d7415f9ba9d4dbb501f6
 AdditionalInputReseed =
 ** RESEED:
	V   = ee34cedfaa282d1d55e0bb001aa5ae42c1f90b56c6b426ad47deccce83786f38
	Key = fd616afaa26dd2fc3c2e93cf84af86e6d948fa01c617758816d5ea689925b812
 AdditionalInput =
 ** GENERATE (FIRST CALL):
	V   = 12a5a939f3f229cb85a1d6fb72ca5e109959726dda4ff9d95c11d7129ad3c1f9
	Key = d4bbadb25daa6f76c18ad05c07e448f719f0af2f535e2f938e2dcc5dfa5525b7
 AdditionalInput =
 ReturnedBits = f92d4cf99a535b20222a52a68db04c5af6f5ffc7b66a473a37a256bd8d298f9b4aa4af7e8d181e02367903f93bdb744c6c2f3f3472626b40ce9bd6a70e7b8f93992a16a76fab6b5f162568e08ee6c3e804aefd952ddd3acb791c50f2ad69e9a04028a06a9c01d3a62aca2aaf6efe69ed97a016213a2dd642b4886764072d9cbe
 ** GENERATE (SECOND CALL):
	V   = 53bc9a0420b02b4f6a60aacd8e0320bc440a2385e27887e6ceba60571b27aa47
	Key = eab97b2cf76bd1817dc5d6826361b51c4dc8776ef643254dae01f83b23c2d5c2

*/
static int testNistHmacSHA256(void) {
    int rc=0;

    struct ccdrbg_info info;
    struct ccdrbg_nisthmac_custom custom_hmac = {
        .di = ccsha256_di(),
        .strictFIPS = 0,
    };

    ccdrbg_factory_nisthmac(&info, &custom_hmac);

    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("fa0ee1fe39c7c390aa94159d0de97564342b591777f3e5f6a4ba2aea342ec840");
    byteBuffer nonce=hexStringToBytes("dd0820655cb2ffdb0da9e9310a67c9e5");
    byteBuffer ps=hexStringToBytes("f2e58fe60a3afc59dad37595415ffd318ccf69d67780f6fa0797dc9aa43e144c");
    byteBuffer reseed=hexStringToBytes("e0629b6d7975ddfa96a399648740e60f1f9557dc58b3d7415f9ba9d4dbb501f6");
    byteBuffer result=hexStringToBytes("f92d4cf99a535b20222a52a68db04c5af6f5ffc7b66a473a37a256bd8d298f9b4aa4af7e8d181e02367903f93bdb744c6c2f3f3472626b40ce9bd6a70e7b8f93992a16a76fab6b5f162568e08ee6c3e804aefd952ddd3acb791c50f2ad69e9a04028a06a9c01d3a62aca2aaf6efe69ed97a016213a2dd642b4886764072d9cbe");
    byteBuffer result2=hexStringToBytes("97e05f7ed83f6ade911a09e0ce8fdd8bf6f5ffc7b66a473a37a256bd8d298f9b4aa4af7e8d181e02367903f93bdb744c6c2f3f3472626b40ce9bd6a70e7b8f93992a16a76fab6b5f162568e08ee6c3e804aefd952ddd3acb791c50f2ad69e9a04028a06a9c01d3a62aca2aaf6efe69ed97a016213a2dd642b4886764072d9cbe");
    unsigned char bytes[CC_MAX(result->len,result2->len)];

    /* FIPS test vector */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                        (uint32_t)nonce->len, nonce->bytes, ps->len, ps->bytes), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, result->len, bytes, 0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, result->len, bytes, 0, NULL), "Generate 2");
    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");

    ccdrbg_done(&info, rng);

    /* Additional test vector to cover the behavior of generate with 0 length (21208820) */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                        (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 0, bytes, 0, NULL), "Generate zero length");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");
    rc|=ok_memcmp(bytes, result2->bytes,result2->len, "returned bytes");

    ccdrbg_done(&info, rng);
    free(entropy);
    free(nonce);
    free(ps);
    free(reseed);
    free(result);
    free(result2);
    return rc;
}


#define commonTestNistHMAC_test(di,v) commonTestNistHMAC((di),#v,(v),CC_ARRAY_LEN(v))

static int commonTestNistHMAC(const struct ccdigest_info *di,
                              char * name,
                              struct ccdrbg_vector *v,
                              size_t n) {
    int rc=0;
    struct ccdrbg_info info;
    struct ccdrbg_nisthmac_custom custom = {
        .di = di,
        .strictFIPS = 0,
    };

    ccdrbg_factory_nisthmac(&info, &custom);

    for(size_t i=0; i<n; i++)
    {
        unsigned char temp[v[i].randomLen];
        ccdrbg_nist_14_3_test_vector(&info, &v[i], temp);
        rc|=ok_memcmp(temp, v[i].random, v[i].randomLen, "%s, vector %lu",name, i);
    }
    return rc;
}


int ccdrbg_tests_hmac(void)
{
    int status=0;

    status|=testNistHmacSHA256();

    status|=commonTestNistHMAC_test(ccsha1_di(),nisthmac_sha1_vectors);

    status|=commonTestNistHMAC_test(ccsha224_di(),nisthmac_sha224_vectors);

    status|=commonTestNistHMAC_test(ccsha256_di(),nisthmac_sha256_vectors);

    status|=commonTestNistHMAC_test(ccsha384_di(),nisthmac_sha384_vectors);

    status|=commonTestNistHMAC_test(ccsha512_di(),nisthmac_sha512_vectors);

    return status;
}

#endif // (CCDRBG == 0)
