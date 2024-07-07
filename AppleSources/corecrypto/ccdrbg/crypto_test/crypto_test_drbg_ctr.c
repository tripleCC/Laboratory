/* Copyright (c) (2016-2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccmode.h>
#include "cc_priv.h"

#if (CCDRBG == 0)
entryPoint(ccdrbg_tests,"ccdrbg")
#else

static struct ccdrbg_vector nistctr_aes128_df_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-128-df.inc"
};

static struct ccdrbg_vector nistctr_aes128_nodf_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-128-nodf.inc"
};

static struct ccdrbg_vector nistctr_aes192_df_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-192-df.inc"
};

static struct ccdrbg_vector nistctr_aes192_nodf_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-192-nodf.inc"
};

static struct ccdrbg_vector nistctr_aes256_df_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-256-df.inc"
};

static struct ccdrbg_vector nistctr_aes256_nodf_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-256-nodf.inc"
};

static struct ccdrbg_PR_vector nistctr_aes128_df_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-128-df-PR.inc"
};

static struct ccdrbg_PR_vector nistctr_aes128_nodf_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-128-nodf-PR.inc"
};

static struct ccdrbg_PR_vector nistctr_aes192_df_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-192-df-PR.inc"
};

static struct ccdrbg_PR_vector nistctr_aes192_nodf_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-192-nodf-PR.inc"
};

static struct ccdrbg_PR_vector nistctr_aes256_df_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-256-df-PR.inc"
};

static struct ccdrbg_PR_vector nistctr_aes256_nodf_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-256-nodf-PR.inc"
};

#define commonTestNistCtr_test(ecb,keylen,df,v) commonTestNistCtr((ecb),(keylen),(df),#v,(v),(CC_ARRAY_LEN(v)))

static int commonTestNistCtr(const struct ccmode_ctr *ctr,size_t keylen,
                             int df,
                             char * name,
                             struct ccdrbg_vector *v,
                             size_t n)
{
    int rc;
    struct ccdrbg_info info;
    ccdrbg_df_bc_ctx_t df_ctx;
    rc = ccdrbg_df_bc_init(&df_ctx,
                           ccaes_cbc_encrypt_mode(),
                           keylen);
    struct ccdrbg_nistctr_custom custom = {
        .ctr_info = ctr,
        .keylen = keylen,
        .strictFIPS = 0,
        .df_ctx = df ? &df_ctx.df_ctx : NULL,
    };

    ccdrbg_factory_nistctr(&info, &custom);

    for(size_t i=0; i<n; i++)
    {
        unsigned char temp[v[i].randomLen];
        ccdrbg_nist_test_vector(&info, &v[i], temp);
        rc|=ok_memcmp(temp, v[i].random, v[i].randomLen, "%s, vector %lu", name, i);
    }
    return rc;
}

#define commonTestNistCtrPR_test(ecb,keylen,df,v) commonTestNistCtrPR((ecb),(keylen),(df),#v,(v),(CC_ARRAY_LEN(v)))

static int commonTestNistCtrPR(
                                const struct ccmode_ctr *ctr,
                                size_t keylen,
                                int df,
                                char *name,
                                struct ccdrbg_PR_vector *v,
                                size_t n) {
    int rc=0;
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;
    size_t i;

    ccdrbg_df_bc_ctx_t df_ctx;
    rc = ccdrbg_df_bc_init(&df_ctx,
                           ccaes_cbc_encrypt_mode(),
                           keylen);

    custom.ctr_info=ctr;
    custom.keylen=keylen;
    custom.strictFIPS=0;
    custom.df_ctx = df ? &df_ctx.df_ctx : NULL;

    ccdrbg_factory_nistctr(&info, &custom);

    for(i=0; i<n; i++)
    {
        unsigned char temp[v[i].randomLen];
        ccdrbg_nist_PR_test_vector(&info, &v[i], temp);
        rc|=ok_memcmp(temp, v[i].random, v[i].randomLen, "%s, vector %lu", name, i);
    }
    return rc;
}

/*
 AES (encrypt)

 COUNT = 0
 EntropyInput = b9ad873294a58a0d6c2e9d072f8a270b
 Nonce = 0d5849ccaa7b8a95
 PersonalizationString =
 AdditionalInput =
 EntropyInputReseed = e47485dda9d246a07c0c39f0cf8cb76b
 AdditionalInputReseed =
 AdditionalInput =
 ReturnedBits = 24bd4f7cc6eb71987ab7b06bd066cc07
 */

static int testNistCtrAES128(void) {
    int rc=0;
    unsigned char bytes[16];
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    ccdrbg_df_bc_ctx_t df_ctx;
    rc = ccdrbg_df_bc_init(&df_ctx,
                           ccaes_cbc_encrypt_mode(),
                           16);

    custom.ctr_info=ccaes_ctr_crypt_mode();
    custom.keylen=16;
    custom.strictFIPS=0;
    custom.df_ctx = &df_ctx.df_ctx;

    ccdrbg_factory_nistctr(&info, &custom);

    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("b9ad873294a58a0d6c2e9d072f8a270b");
    byteBuffer nonce=hexStringToBytes("0d5849ccaa7b8a95");
    byteBuffer reseed=hexStringToBytes("e47485dda9d246a07c0c39f0cf8cb76b");
    byteBuffer result=hexStringToBytes("24bd4f7cc6eb71987ab7b06bd066cc07");
    byteBuffer result2=hexStringToBytes("53a374589113bea418166ce349fa739a");
    byteBuffer result3=hexStringToBytes("321f125cc30fe61e623927f85a19e8e0");

    /* FIPS test vector */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                              (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");

    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");

    ccdrbg_done(&info, rng);
    
    /* Additional test vector to cover the behavior of generate with 0 length (21208820) */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                        (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");
    
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 0, bytes, 0, NULL), "Generate zero length");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");
    rc|=ok_memcmp(bytes, result2->bytes,result2->len, "returned bytes");
    
    ccdrbg_done(&info, rng);
    
    /* Additional test vector to cover the behavior of generate with length not block-aligned */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                        (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");
    
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 13, bytes, 0, NULL), "Generate incomplete block");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate full block");
    rc|=ok_memcmp(bytes, result3->bytes,result3->len, "returned bytes");
    
    ccdrbg_done(&info, rng);
    free(entropy);
    free(nonce);
    free(reseed);
    free(result);
    free(result2);
    free(result3);
    return rc;
}

/* AES-128 no df
 COUNT = 0
 EntropyInput = 420edbaff787fdbd729e12c2f3cfc0ec6704de59bf28ed438bf0d86ddde7ebcc
 Nonce = be293b972894533b
 PersonalizationString =
 AdditionalInput =
 EntropyInputReseed = a821c34b7505291f80341e37f930451659091550bef04cb68a01b1be394b1037
 AdditionalInputReseed =
 AdditionalInput =
 ReturnedBits = 263c1cf3fd8c0bcb1ed754ce10cfc2fc
 */

static int testNistCtrAES128nodf(void) {
    int rc=0;
    unsigned char bytes[16];
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    custom.ctr_info=ccaes_ctr_crypt_mode();
    custom.keylen=16;
    custom.strictFIPS=0;
    custom.df_ctx = NULL;

    ccdrbg_factory_nistctr(&info, &custom);

    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("420edbaff787fdbd729e12c2f3cfc0ec6704de59bf28ed438bf0d86ddde7ebcc");
    byteBuffer nonce=hexStringToBytes("be293b972894533b");
    byteBuffer reseed=hexStringToBytes("a821c34b7505291f80341e37f930451659091550bef04cb68a01b1be394b1037");
    byteBuffer result=hexStringToBytes("263c1cf3fd8c0bcb1ed754ce10cfc2fc");

    /* typecast: size of entropy and nonce must be less than 4GB, and fit in uint32_t */
    rc|=is(CCDRBG_STATUS_OK,info.init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                              (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");

    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");
    free(entropy);
    free(nonce);
    free(reseed);
    free(result);
    return rc;
}

/* AES-256

 COUNT = 0
 EntropyInput = ec0197a55b0c9962d549b161e96e732a0ee3e177004fe95f5d6120bf82e2c0ea
 Nonce = 9b131c601efd6a7cc2a21cd0534de8d8
 PersonalizationString =
 AdditionalInput =
 EntropyInputReseed = 61810b74d2ed76365ae70ee6772bba4938ee38d819ec1a741fb3ff4c352f140c
 AdditionalInputReseed =
 AdditionalInput =
 ReturnedBits = 7ea89ce613e11b5de7f979e14eb0da4d

 */

static int testNistCtrAES256(void) {
    int rc=0;
    unsigned char bytes[16];
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    ccdrbg_df_bc_ctx_t df_ctx;
    rc = ccdrbg_df_bc_init(&df_ctx,
                           ccaes_cbc_encrypt_mode(),
                           32);

    custom.ctr_info=ccaes_ctr_crypt_mode();
    custom.keylen=32;
    custom.strictFIPS=0;
    custom.df_ctx = &df_ctx.df_ctx;

    ccdrbg_factory_nistctr(&info, &custom);

    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("ec0197a55b0c9962d549b161e96e732a0ee3e177004fe95f5d6120bf82e2c0ea");
    byteBuffer nonce=hexStringToBytes("9b131c601efd6a7cc2a21cd0534de8d8");
    byteBuffer reseed=hexStringToBytes("61810b74d2ed76365ae70ee6772bba4938ee38d819ec1a741fb3ff4c352f140c");
    byteBuffer result=hexStringToBytes("7ea89ce613e11b5de7f979e14eb0da4d");

    /* typecast: size of entropy and nonce must be less than 4GB, and fit in uint32_t */
    rc|=is(CCDRBG_STATUS_OK,info.init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                              (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");

    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");
    free(entropy);
    free(nonce);
    free(reseed);
    free(result);
    return rc;
}

/* AES-192

 COUNT = 0
 EntropyInput = 1e259e4e7f5b4c5b5b4d5119f2cde4853dc1dd131172f394
 Nonce = 40347af9fb51845a5d3712a2169065cb
 PersonalizationString =
 AdditionalInput =
 EntropyInputReseed = 82bd0a6027531a768163ff636d88a8e7513018117627da6d
 AdditionalInputReseed =
 AdditionalInput =
 ReturnedBits = 0b4de73186bde75f0d4d551ba55af931

 */

static int testNistCtrAES192(void) {
    int rc=0;
    unsigned char bytes[16];
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    ccdrbg_df_bc_ctx_t df_ctx;
    rc = ccdrbg_df_bc_init(&df_ctx,
                           ccaes_cbc_encrypt_mode(),
                           24);

    custom.ctr_info=ccaes_ctr_crypt_mode();
    custom.keylen=24;
    custom.strictFIPS=0;
    custom.df_ctx = &df_ctx.df_ctx;
    ccdrbg_factory_nistctr(&info, &custom);
    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("1e259e4e7f5b4c5b5b4d5119f2cde4853dc1dd131172f394");
    byteBuffer nonce=hexStringToBytes("40347af9fb51845a5d3712a2169065cb");
    byteBuffer reseed=hexStringToBytes("82bd0a6027531a768163ff636d88a8e7513018117627da6d");
    byteBuffer result=hexStringToBytes("0b4de73186bde75f0d4d551ba55af931");

    /* typecast: size of entropy and nonce must be less than 4GB, and fit in uint32_t */
    rc|=is(CCDRBG_STATUS_OK,info.init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                              (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");

    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");

    free(entropy);
    free(nonce);
    free(reseed);
    free(result);
    return rc;
}

int ccdrbg_tests_ctr(void)
{
    int status=0;

    status|=testNistCtrAES128();
    status|=testNistCtrAES128nodf();
    status|=testNistCtrAES192();
    status|=testNistCtrAES256();

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),16,1,
                           nistctr_aes128_df_vectors);

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),24,1,
                           nistctr_aes192_df_vectors);

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),32,1,
                           nistctr_aes256_df_vectors);

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),16,0,
                           nistctr_aes128_nodf_vectors);

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),24,0,
                           nistctr_aes192_nodf_vectors);

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),32,0,
                           nistctr_aes256_nodf_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),16,1,
                             nistctr_aes128_df_PR_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),24,1,
                             nistctr_aes192_df_PR_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),32,1,
                             nistctr_aes256_df_PR_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),16,0,
                             nistctr_aes128_nodf_PR_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),24,0,
                             nistctr_aes192_nodf_PR_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),32,0,
                             nistctr_aes256_nodf_PR_vectors);

    return status;
}

#endif // (CCDRBG == 0)
