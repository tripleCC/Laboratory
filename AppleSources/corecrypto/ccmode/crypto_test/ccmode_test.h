/* Copyright (c) (2011-2013,2015-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CCMODE_TEST_H_
#define _CCMODE_TEST_H_

int ccmode_ecb_test_one(const struct ccmode_ecb *ecb, size_t keylen, const void *keydata,
                        size_t nblocks, const void *in, const void *out);

int ccmode_ecb_test_key_self(const struct ccmode_ecb *encrypt, const struct ccmode_ecb *decrypt, size_t nblocks,
                             size_t keylen, const void *keydata, size_t loops);

int ccmode_cbc_test_one(const struct ccmode_cbc *cbc, size_t keylen, const void *keydata,
                        const void *iv, size_t nblocks, const void *in, const void *out);

int ccmode_cbc_test_one_chained(const struct ccmode_cbc *cbc, size_t keylen, const void *keydata,
                                const void *iv, size_t nblocks, const void *in, const void *out);

int ccmode_cbc_test_key_self(const struct ccmode_cbc *encrypt, const struct ccmode_cbc *decrypt, size_t nblocks,
                             size_t keylen, const void *keydata, size_t loops);

int ccmode_cbc_test_chaining_self(const struct ccmode_cbc *encrypt, const struct ccmode_cbc *decrypt, size_t nblocks,
                                  size_t keylen, const void *keydata, size_t loops);

int ccmode_ofb_test_one(const struct ccmode_ofb *ofb, size_t keylen, const void *keydata,
                        const void *iv, size_t nbytes, const void *in, const void *out);

int ccmode_ofb_test_one_chained(const struct ccmode_ofb *ofb, size_t keylen, const void *keydata,
                                const void *iv, size_t nbytes, const void *in, const void *out);

int ccmode_cfb_test_one(const struct ccmode_cfb *cfb, size_t keylen, const void *keydata,
                        const void *iv, size_t nbytes, const void *in, const void *out);

int ccmode_cfb_test_one_chained(const struct ccmode_cfb *cfb, size_t keylen, const void *keydata,
                                const void *iv, size_t nbytes, const void *in, const void *out);

int ccmode_cfb8_test_one(const struct ccmode_cfb8 *cfb8, size_t keylen, const void *keydata,
                        const void *iv, size_t nbytes, const void *in, const void *out);

int ccmode_cfb8_test_one_chained(const struct ccmode_cfb8 *cfb8, size_t keylen, const void *keydata,
                                const void *iv, size_t nbytes, const void *in, const void *out);

int ccmode_ctr_test_one(const struct ccmode_ctr *ctr, size_t keylen, const void *keydata,
                        const void *iv, size_t nbytes, const void *in, const void *out);

int ccmode_ctr_test_one_chained(const struct ccmode_ctr *ctr, size_t keylen, const void *keydata,
                                const void *iv, size_t nbytes, const void *in, const void *out);

int ccmode_ctr_test_one_chained2(const struct ccmode_ctr *ctr, size_t keylen, const void *keydata,
                                const void *iv, size_t nbytes, const void *in, const void *out);

int ccmode_xts_test_one(const struct ccmode_xts *xts, size_t key_nbytes,
                        const void *dkey, const void *tkey, const void *tweak,
                        size_t nbytes, const void *in, void *out, int dec);

int ccmode_xts_test_one_chained(const struct ccmode_xts *xts,
                                size_t key_nbytes, const void *dkey,
                                const void *tkey, const void *tweak,
                                size_t nbytes, const void *in,
                                void *out, int dec);

int ccmode_gcm_test_one(const struct ccmode_gcm *gcm, size_t keylen, const void *keydata,
                        size_t ivlen, const void *iv, size_t adalen, const void *ada,
                        size_t nbytes, const void *in, const void *out,
                        size_t taglen, const void *tag);

int ccmode_gcm_test_one_chained(const struct ccmode_gcm *gcm, size_t keylen, const void *keydata,
                                size_t ivlen, const void *iv, size_t adalen, const void *ada,
                                size_t nbytes, const void *in, const void *out,
                                size_t taglen, const void *tag);


struct ccmode_ecb_vector {
    size_t keylen;
    const void *key;
    size_t nblocks;
    const void *pt;
    const void *ct;
};

int ccmode_ecb_test_one_vector(const struct ccmode_ecb *ecb, const struct ccmode_ecb_vector *v, int dec);


struct ccmode_cbc_vector {
    size_t keylen;
    const void *key;
    const char *iv;
    size_t nblocks;
    const char *pt;
    const char *ct;
};

struct ccmode_cbc_failure_vector {
    struct ccmode_cbc_vector cbc_vector;
    int expected_error;
};

int ccmode_cbc_test_one_vector(const struct ccmode_cbc *cbc, const struct ccmode_cbc_vector *v, int dec);
int ccmode_cbc_test_one_vector_unaligned(const struct ccmode_cbc *cbc, const struct ccmode_cbc_vector *v, int dec);
int ccmode_cbc_test_one_vector_chained(const struct ccmode_cbc *cbc, const struct ccmode_cbc_vector *v, int dec);

struct ccmode_ofb_vector {
    size_t keylen;
    const void *key;
    const char *iv;
    size_t nbytes;
    const char *pt;
    const char *ct;
};

int ccmode_ofb_test_one_vector(const struct ccmode_ofb *ofb, const struct ccmode_ofb_vector *v, int dec);

int ccmode_ofb_test_one_vector_chained(const struct ccmode_ofb *ofb, const struct ccmode_ofb_vector *v, int dec);

struct ccmode_cfb_vector {
    size_t keylen;
    const void *key;
    const char *iv;
    size_t nbytes;
    const char *pt;
    const char *ct;
};

int ccmode_cfb_test_one_vector(const struct ccmode_cfb *cfb, const struct ccmode_cfb_vector *v, int dec);

int ccmode_cfb_test_one_vector_chained(const struct ccmode_cfb *cfb, const struct ccmode_cfb_vector *v, int dec);

struct ccmode_cfb8_vector {
    size_t keylen;
    const void *key;
    const char *iv;
    size_t nbytes;
    const char *pt;
    const char *ct;
};

int ccmode_cfb8_test_one_vector(const struct ccmode_cfb8 *cfb8, const struct ccmode_cfb8_vector *v, int dec);

int ccmode_cfb8_test_one_vector_chained(const struct ccmode_cfb8 *cfb8, const struct ccmode_cfb8_vector *v, int dec);

struct ccmode_xts_vector {
    size_t keylen;
    const void *dkey; /* keylen sized */
    const void *tkey; /* keylen sized */
    const char *tweak; /* 16 bytes */
    size_t nbytes;
    const char *pt;    /* nbytes sized */
    const char *ct;    /* nbytes sized */
};

int ccmode_xts_test_one_vector(const struct ccmode_xts *xts,
                               const struct ccmode_xts_vector *v, void *out,
                               int dec);

int ccmode_xts_test_one_vector_chained(const struct ccmode_xts *xts,
                                       const struct ccmode_xts_vector *v,
                                       void *out, int dec);

struct ccmode_gcm_vector {
    size_t keylen;
    const void *key;
    size_t ivlen;
    const char *iv;
    size_t ptlen;
    const char *pt;
    size_t adalen;
    const char *ada;
    size_t ctlen;
    const char *ct;
    size_t taglen;
    const char *tag;
};

int ccmode_gcm_test_one_vector(const struct ccmode_gcm *gcm, const struct ccmode_gcm_vector *v, int dec);

int ccmode_gcm_test_one_vector_chained(const struct ccmode_gcm *gcm, const struct ccmode_gcm_vector *v, int dec);

struct ccmode_ccm_vector {
    size_t keylen;
    const void *key;
    size_t noncelen;
    const char *nonce;
    size_t ptlen;
    const char *pt;
    size_t adalen;
    const char *ada;
    size_t ctlen;
    const char *ct;
};

struct iterated_adata_ccm_test_vector
{
    size_t key_n;
    char *key;
    size_t nonce_n;
    char *nonce;
    size_t aData_iterated_string_n;
    char *iterated_string;
    size_t aData_num_of_iterations;
    size_t pdata_n;
    char *pdata;
    size_t full_ciphertext_n;
    char *full_ciphertext;
    size_t enc_data_n;
    char *enc_data;
    size_t tag_n;
    char *tag;
};


int ccmode_ccm_test_one(const struct ccmode_ccm *ccm, size_t keylen, const void *keydata,
                        size_t nonce_len, const void *nonce, size_t adalen, const void *ada,
                        size_t nbytes, const void *in, const void *out,
                        size_t mac_size, const void *mac, int chained);
int ccmode_ccm_test_one_vector(const struct ccmode_ccm *ccm,
                                const struct ccmode_ccm_vector *v, int dec, int chained);


#endif /* _CCMODE_TEST_H_ */
