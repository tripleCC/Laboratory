/* Copyright (c) (2017-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

//  Copyright (c) 2016 Apple Inc. All rights reserved.
//
//

#include <corecrypto/ccmode.h>

#include "testmore.h"
#include "testbyteBuffer.h"
#include "crypto_test_modes.h"


struct ccmode_ctr_vector {
    size_t keylen;
    const void *key;
    const uint8_t *iv;
    size_t nbytes;
    const uint8_t *pt;
    const uint8_t *ct;
};

/* CTR */
int ccmode_ctr_test_one_vector(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec);

int ccmode_ctr_test_one_vector_chained(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec);

int ccmode_ctr_test_one_vector_chained2(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec);



/* does one CTR encryption or decryption and compare result */
static int ccmode_ctr_test_one(const struct ccmode_ctr *ctr, size_t keylen, const void *keydata,
                        const void *iv, size_t nbytes, const void *in, const void *out)
{
    unsigned char temp[nbytes];
    unsigned char temp2[nbytes];
    ccctr_ctx_decl(ctr->size, key);
    ccctr_init(ctr, key, keylen, keydata, iv);
    ccctr_update(ctr, key, nbytes, in, temp);

    int rv;
    if ((rv = ccctr_one_shot(ctr, keylen, keydata, iv, nbytes, in, temp2))) {
        return rv;
    }

    return memcmp_print(out, temp, nbytes) || memcmp_print(out, temp2, nbytes);
}

/* Test one test vector - use dec=1 to reverse pt and ct */
int ccmode_ctr_test_one_vector(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec)
{
    if (dec)
        return ccmode_ctr_test_one(ctr, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    else
        return ccmode_ctr_test_one(ctr, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
}

/* Test one test vector, 1 byte at a time */
static int ccmode_ctr_test_one_chained(const struct ccmode_ctr *ctr, size_t keylen, const void *keydata,
                                const void *iv, size_t nbytes, const void *in, const void *out)
{
    size_t i;
    const unsigned char *input=in;
    unsigned char temp[nbytes];
    ccctr_ctx_decl(ctr->size, key);
    ccctr_init(ctr, key, keylen, keydata, iv);
    for (i=0; i<nbytes; i++) {
        ccctr_update(ctr,key, 1, &input[i], &temp[i]);
    }
    
    return memcmp_print(out, temp, nbytes);
}

int ccmode_ctr_test_one_vector_chained(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec)
{
    if (dec)
        return ccmode_ctr_test_one_chained(ctr, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    else
        return ccmode_ctr_test_one_chained(ctr, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
}

/* Test one test vector, 1 byte at a time */
static int ccmode_ctr_test_one_chained2(const struct ccmode_ctr *ctr, size_t keylen, const void *keydata,
                                 const void *iv, size_t nbytes, const void *in, const void *out)
{
    size_t i=0;
    const unsigned char *input=in;
    unsigned char temp[nbytes];
    ccctr_ctx_decl(ctr->size, key);
    ccctr_init(ctr, key, keylen, keydata, iv);
    if (nbytes>2*ctr->ecb_block_size+2) {
        ccctr_update(ctr,key, 1, &input[i], &temp[i]);
        i++;
        ccctr_update(ctr,key, 2*ctr->ecb_block_size, &input[i], &temp[i]);
        i+=2*ctr->ecb_block_size;
        ccctr_update(ctr,key, 1, &input[i], &temp[i]);
        i++;
    }
    for (; i<nbytes; i++) {
        ccctr_update(ctr,key, 1, &input[i], &temp[i]);
    }
    
    return memcmp_print(out, temp, nbytes);
}

int ccmode_ctr_test_one_vector_chained2(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec)
{
    if (dec)
        return ccmode_ctr_test_one_chained2(ctr, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    else
        return ccmode_ctr_test_one_chained2(ctr, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
}


static int ctr(const char *name, const struct ccmode_ctr* enc, const ccsymmetric_test_vector *sym_vectors)
{
    int rc=1;
    for(unsigned int i=0; (&sym_vectors[i])->keyStr!=NULL; i++)
    {
        const ccsymmetric_test_vector*v=&sym_vectors[i];
        // Convert from generic test vector format containing string
        // to CTR format with hexadecimal values
        struct ccmode_ctr_vector ctr_v;
        byteBuffer key = hexStringToBytes(v->keyStr);
        byteBuffer init_iv = hexStringToBytes(v->init_ivStr);
        byteBuffer pt = hexStringToBytes(v->ptStr);
        byteBuffer ct = hexStringToBytes(v->ctStr);
        ctr_v.keylen=key->len;
        ctr_v.key=key->bytes;
        ctr_v.iv=init_iv->bytes;
        ctr_v.nbytes=pt->len;
        ctr_v.pt=pt->bytes;
        ctr_v.ct=ct->bytes;
        
        rc &= is(ccctr_block_size(enc),(size_t)1,"Granularity size == 1 Vector %d %s", i, name);
        rc &= is(enc->ecb_block_size,init_iv->len,"ECB block size == IV len Vector %d %s", i, name);
        
        // Test the vector
        rc &= ok(ccmode_ctr_test_one_vector(enc, &ctr_v, 0)==0, "Encrypt Vector %d %s", i, name);
        rc &= ok(ccmode_ctr_test_one_vector(enc, &ctr_v, 1)==0, "Decrypt Vector %d %s", i, name);
        
        rc &= ok(ccmode_ctr_test_one_vector_chained(enc, &ctr_v, 0)==0, "Encrypt Chained Vector %d %s", i, name);
        rc &= ok(ccmode_ctr_test_one_vector_chained(enc, &ctr_v, 1)==0, "Decrypt Chained Vector %d %s", i, name);
        
        rc &= ok(ccmode_ctr_test_one_vector_chained2(enc, &ctr_v, 0)==0, "Encrypt Chained Vector %d %s", i, name);
        rc &= ok(ccmode_ctr_test_one_vector_chained2(enc, &ctr_v, 1)==0, "Decrypt Chained Vector %d %s", i, name);
        
        free(key);
        free(init_iv);
        free(pt);
        free(ct);
    }
    return rc;
}

int test_ctr(const char *name, const struct ccmode_ctr *encrypt_ciphermode, const struct ccmode_ctr *decrypt_ciphermode,
             const ccsymmetric_test_vector *sym_vectors)
{
    int rc=1;
    rc &= ctr(name,encrypt_ciphermode,sym_vectors);
    rc &= ctr(name,decrypt_ciphermode,sym_vectors);
    return rc;
}


