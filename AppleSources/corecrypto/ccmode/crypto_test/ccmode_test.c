/* Copyright (c) (2010-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccmode.h>
#include <corecrypto/ccpad.h>
#include "cctest.h"
#include <corecrypto/cc_priv.h>
#include "ccmode_test.h"
#include "cc_macros.h"

//#define _INTERNAL_DEBUG_  1
//#define USE_COMMONCRYPTO_GCM  1

#ifdef _INTERNAL_DEBUG_
#include <stdio.h>
#endif

/* does one encryption or decryption in ECB mode and compare result */
int ccmode_ecb_test_one(const struct ccmode_ecb *ecb, size_t keylen, const void *keydata,
                        size_t nblocks, const void *in, const void *out)
{
    unsigned char temp[nblocks*ecb->block_size];
    ccecb_ctx_decl(ecb->size, key);

    if (ecb->init(ecb, key, keylen, keydata)) {
        return -1;
    }
    if (ecb->ecb(key, nblocks, in, temp)) {
        return -1;
    }

#ifdef _INTERNAL_DEBUG_
    {
        char k[keylen*2+1];
        char i[ecb->block_size*nblocks*2+1];
        char o[ecb->block_size*nblocks*2+1];
        char t[ecb->block_size*nblocks*2+1];

        cc_bin2hex(keylen, k, keydata);
        cc_bin2hex(ecb->block_size*nblocks, i, in);
        cc_bin2hex(ecb->block_size*nblocks, o, out);
        cc_bin2hex(ecb->block_size*nblocks, t, temp);

        fprintf(stderr, "k: %s, i: %s, o:%s, t:%s\n", k, i, o, t);
    }
#endif

    return memcmp(out, temp, ecb->block_size*nblocks);
}

/* Test one test vector - use dec=1 to reverse pt and ct */
int ccmode_ecb_test_one_vector(const struct ccmode_ecb *ecb, const struct ccmode_ecb_vector *v, int dec)
{
    if (dec) {
        return ccmode_ecb_test_one(ecb, v->keylen, v->key, v->nblocks, v->ct, v->pt);
    } else {
        return ccmode_ecb_test_one(ecb, v->keylen, v->key, v->nblocks, v->pt, v->ct);
    }
}

/* Initialize a block of 'nblocks' of zeroes,
 Does 'loops' consecutive encryption (ECB) in place,
 then 'loops' decryption (ECB) in place,
 result should be zeroes. */
int ccmode_ecb_test_key_self(const struct ccmode_ecb *encrypt, const struct ccmode_ecb *decrypt, size_t nblocks,
                             size_t keylen, const void *keydata, size_t loops)
{
    unsigned char temp[nblocks*encrypt->block_size];
    unsigned char zeroes[nblocks*encrypt->block_size];
    ccecb_ctx_decl(decrypt->size, dkey);
    ccecb_ctx_decl(encrypt->size, ekey);

    cc_clear(nblocks*encrypt->block_size,temp);
    cc_clear(nblocks*encrypt->block_size,zeroes);

    if (encrypt->init(encrypt, ekey, keylen, keydata)) {
        return -1;
    }
    if (decrypt->init(decrypt, dkey, keylen, keydata)) {
        return -1;
    }

    for (size_t i=0; i<loops; i++) {
        if (encrypt->ecb(ekey, nblocks, temp, temp)) {
            return -1;
        }
    }

    for (size_t i=0; i<loops; i++) {
        if (decrypt->ecb(dkey, nblocks, temp, temp)) {
            return -1;
        }
    }

    return memcmp(zeroes, temp, encrypt->block_size*nblocks);
}

/* does one CBC encryption or decryption and compare result */
int ccmode_cbc_test_one(const struct ccmode_cbc *cbc, size_t keylen, const void *keydata,
                        const void *iv, size_t nblocks, const void *in, const void *out)
{
    unsigned char temp[nblocks*cbc->block_size];
    int rc = cccbc_one_shot(cbc, keylen, keydata, iv, nblocks, in, temp);
    if (rc != CCERR_OK) {
        return rc;
    }

    return memcmp(out, temp, sizeof(temp));
}

/* Test one test vector - use dec=1 to reverse pt and ct */
int ccmode_cbc_test_one_vector(const struct ccmode_cbc *cbc, const struct ccmode_cbc_vector *v, int dec)
{
    if (dec) {
        return ccmode_cbc_test_one(cbc, v->keylen, v->key, v->iv, v->nblocks, v->ct, v->pt);
    } else {
        return ccmode_cbc_test_one(cbc, v->keylen, v->key, v->iv, v->nblocks, v->pt, v->ct);
    }
}

/* Test one test vector, with unaligned data */
int ccmode_cbc_test_one_vector_unaligned(const struct ccmode_cbc *cbc, const struct ccmode_cbc_vector *v, int dec)
{
    uint8_t pt[v->nblocks*cbc->block_size+1];
    uint8_t ct[v->nblocks*cbc->block_size+1];

    memcpy(pt+1, v->pt, v->nblocks*cbc->block_size);
    memcpy(ct+1, v->ct, v->nblocks*cbc->block_size);

    if (dec) {
        return ccmode_cbc_test_one(cbc, v->keylen, v->key, v->iv, v->nblocks, ct+1, v->pt);
    } else {
        return ccmode_cbc_test_one(cbc, v->keylen, v->key, v->iv, v->nblocks, pt+1, v->ct);
    }
}

/* Test one test vector, 1 block at a time */
int ccmode_cbc_test_one_chained(const struct ccmode_cbc *cbc, size_t keylen, const void *keydata,
                                const void *iv, size_t nblocks, const void *in, const void *out)
{
    size_t i;
    const unsigned char *input=in;
    unsigned char temp[nblocks*cbc->block_size];
    cccbc_ctx_decl(cbc->size, key);
    cccbc_iv_decl(cbc->block_size, iv_ctx);
    int rc = cccbc_init(cbc, key, keylen, keydata);
    cc_require_or_return(rc == CCERR_OK, rc);
    rc = cccbc_set_iv(cbc, iv_ctx, iv);
    cc_require_or_return(rc == CCERR_OK, rc);

    for (i=0; i<nblocks; i++) {
        rc = cccbc_update(cbc, key, iv_ctx, 1, &input[i*cbc->block_size], &temp[i*cbc->block_size]);
        cc_require_or_return(CCERR_OK, rc);
    }

    return memcmp(out, temp, cbc->block_size*nblocks);
}

int ccmode_cbc_test_one_vector_chained(const struct ccmode_cbc *cbc, const struct ccmode_cbc_vector *v, int dec)
{
    if (dec) {
        return ccmode_cbc_test_one_chained(cbc, v->keylen, v->key, v->iv, v->nblocks, v->ct, v->pt);
    } else {
        return ccmode_cbc_test_one_chained(cbc, v->keylen, v->key, v->iv, v->nblocks, v->pt, v->ct);
    }
}


/* Initialize a block of 'nblocks' of zeroes,
 Does 'loops' consecutive encryption (CBC) in place,
 then 'loops' decryption (CBC) in place,
 using 0 for iv in each loop, result should be zeroes. */
int ccmode_cbc_test_key_self(const struct ccmode_cbc *encrypt,
                             const struct ccmode_cbc *decrypt,
                             size_t nblocks, size_t keylen,
                             const void *keydata, size_t loops)
{
    unsigned char temp[nblocks*encrypt->block_size];
    unsigned char zeroes[nblocks*encrypt->block_size];
    cccbc_iv_decl(encrypt->block_size, iv); // we can use the same iv context for encrypt and decrypt
                                            // as long as we are not chaining concurrently for both.
    cccbc_ctx_decl(encrypt->size, ekey);
    cccbc_ctx_decl(decrypt->size, dkey);

    cc_clear(nblocks*encrypt->block_size,temp);
    cc_clear(nblocks*encrypt->block_size,zeroes);

    int rc = cccbc_init(encrypt, ekey, keylen, keydata);
    cc_require_or_return(rc == CCERR_OK, rc);
    
    for (size_t i=0; i<loops; i++) {
        if (cccbc_set_iv(encrypt, iv, NULL)) {
            return -1;
        }
        if (cccbc_update(encrypt, ekey, iv, nblocks, temp, temp)) {
            return -1;
        }
    }

    if (cccbc_init(decrypt, dkey, keylen, keydata)) {
        return -1;
    }

    for (size_t i=0; i<loops; i++) {
        if (cccbc_set_iv(decrypt, iv, NULL)) {
            return -1;
        }
        if (cccbc_update(decrypt, dkey, iv, nblocks, temp, temp)) {
            return -1;
        }
    }

    return memcmp(zeroes, temp, encrypt->block_size*nblocks);
}

/*
 Encrypt and decrypt 'nblocks*loop' blocks of zeroes,
 'nblocks' at a time.
 */
int ccmode_cbc_test_chaining_self(const struct ccmode_cbc *encrypt,
                                  const struct ccmode_cbc *decrypt,
                                  size_t nblocks, size_t keylen,
                                  const void *keydata, size_t loops)
{
    unsigned char temp[nblocks*encrypt->block_size];
    unsigned char zeroes[nblocks*encrypt->block_size];
    cccbc_ctx_decl(encrypt->size, ekey);
    cccbc_ctx_decl(decrypt->size, dkey);

    /* here we have to use two iv contexts */
    cccbc_iv_decl(encrypt->block_size, eiv);
    cccbc_iv_decl(decrypt->block_size, div);

    cc_clear(nblocks*encrypt->block_size,temp);
    cc_clear(nblocks*encrypt->block_size,zeroes);

    int rc = cccbc_init(encrypt, ekey, keylen, keydata);
    cc_require_or_return(rc == CCERR_OK, rc);
    
    rc = cccbc_init(decrypt, dkey, keylen, keydata);
    cc_require_or_return(rc == CCERR_OK, rc);

    
    if (cccbc_set_iv(encrypt, eiv, NULL)) {
        return -1;
    }
    if (cccbc_set_iv(decrypt, div, NULL)) {
        return -1;
    }

    for (size_t i=0; i<loops; i++) {
        if (cccbc_update(encrypt, ekey, eiv, nblocks, temp, temp)) {
            return -1;
        }
        if (cccbc_update(decrypt, dkey, div, nblocks, temp, temp)) {
            return -1;
        }
    }

    return memcmp(zeroes, temp, sizeof(temp));
}


/* OFB */

/* does one OFB encryption or decryption and compare result */
int ccmode_ofb_test_one(const struct ccmode_ofb *ofb, size_t keylen, const void *keydata,
                        const void *iv, size_t nbytes, const void *in, const void *out)
{
    unsigned char temp[nbytes];
    ccofb_ctx_decl(ofb->size, key);

    if (ofb->init(ofb, key, keylen, keydata, iv)) {
        return -1;
    }
    if (ofb->ofb(key, nbytes, in, temp)) {
        return -1;
    }

    return memcmp(out, temp, nbytes);
}

/* Test one test vector - use dec=1 to reverse pt and ct */
int ccmode_ofb_test_one_vector(const struct ccmode_ofb *ofb, const struct ccmode_ofb_vector *v, int dec)
{
    if (dec) {
        return ccmode_ofb_test_one(ofb, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    } else {
        return ccmode_ofb_test_one(ofb, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
    }
}

/* Test one test vector, 1 byte at a time */
int ccmode_ofb_test_one_chained(const struct ccmode_ofb *ofb, size_t keylen, const void *keydata,
                                const void *iv, size_t nbytes, const void *in, const void *out)
{
    size_t i;
    const unsigned char *input=in;
    unsigned char temp[nbytes];
    ccofb_ctx_decl(ofb->size, key);

    if (ofb->init(ofb, key, keylen, keydata, iv)) {
        return -1;
    }

    for (i=0; i<nbytes; i++) {
        if (ofb->ofb(key, 1, &input[i], &temp[i])) {
            return -1;
        }
    }

    return memcmp(out, temp, nbytes);
}

int ccmode_ofb_test_one_vector_chained(const struct ccmode_ofb *ofb, const struct ccmode_ofb_vector *v, int dec)
{
    if (dec) {
        return ccmode_ofb_test_one_chained(ofb, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    } else {
        return ccmode_ofb_test_one_chained(ofb, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
    }
}

/* does one CFB encryption or decryption and compare result */
int ccmode_cfb_test_one(const struct ccmode_cfb *cfb, size_t keylen, const void *keydata,
                        const void *iv, size_t nbytes, const void *in, const void *out)
{
    unsigned char temp[nbytes];
    cccfb_ctx_decl(cfb->size, key);

    if (cfb->init(cfb, key, keylen, keydata, iv)) {
        return -1;
    }
    if (cfb->cfb(key, nbytes, in, temp)) {
        return -1;
    }

    return memcmp(out, temp, nbytes);
}

/* Test one test vector - use dec=1 to reverse pt and ct */
int ccmode_cfb_test_one_vector(const struct ccmode_cfb *cfb, const struct ccmode_cfb_vector *v, int dec)
{
    if (dec) {
        return ccmode_cfb_test_one(cfb, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    } else {
        return ccmode_cfb_test_one(cfb, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
    }
}

/* Test one test vector, 1 block at a time */
int ccmode_cfb_test_one_chained(const struct ccmode_cfb *cfb, size_t keylen, const void *keydata,
                                const void *iv, size_t nbytes, const void *in, const void *out)
{
    size_t i;
    const unsigned char *input=in;
    unsigned char temp[nbytes];
    cccfb_ctx_decl(cfb->size, key);

    if (cfb->init(cfb, key, keylen, keydata, iv)) {
        return -1;
    }

    for (i=0; i<nbytes; i++) {
        if (cfb->cfb(key, 1, &input[i], &temp[i])) {
            return -1;
        }
    }

    return memcmp(out, temp, nbytes);
}

int ccmode_cfb_test_one_vector_chained(const struct ccmode_cfb *cfb, const struct ccmode_cfb_vector *v, int dec)
{
    if (dec) {
        return ccmode_cfb_test_one_chained(cfb, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    } else {
        return ccmode_cfb_test_one_chained(cfb, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
    }
}


/* CFB8 */

/* does one CFB8 encryption or decryption and compare result */
int ccmode_cfb8_test_one(const struct ccmode_cfb8 *cfb8, size_t keylen, const void *keydata,
                         const void *iv, size_t nbytes, const void *in, const void *out)
{
    unsigned char temp[nbytes];
    cccfb8_ctx_decl(cfb8->size, key);

    if (cfb8->init(cfb8, key, keylen, keydata, iv)) {
        return -1;
    }
    if (cfb8->cfb8(key, nbytes, in, temp)) {
        return -1;
    }

    return memcmp(out, temp, nbytes);
}

/* Test one test vector - use dec=1 to reverse pt and ct */
int ccmode_cfb8_test_one_vector(const struct ccmode_cfb8 *cfb8, const struct ccmode_cfb8_vector *v, int dec)
{
    if (dec) {
        return ccmode_cfb8_test_one(cfb8, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    } else {
        return ccmode_cfb8_test_one(cfb8, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
    }
}

/* Test one test vector, 1 byte at a time */
int ccmode_cfb8_test_one_chained(const struct ccmode_cfb8 *cfb8, size_t keylen, const void *keydata,
                                 const void *iv, size_t nbytes, const void *in, const void *out)
{
    size_t i;
    const unsigned char *input=in;
    unsigned char temp[nbytes];
    cccfb8_ctx_decl(cfb8->size, key);

    if (cfb8->init(cfb8, key, keylen, keydata, iv)) {
        return -1;
    }

    for (i=0; i<nbytes; i++) {
        if (cfb8->cfb8(key, 1, &input[i], &temp[i])) {
            return -1;
        }
    }

    return memcmp(out, temp, nbytes);
}

int ccmode_cfb8_test_one_vector_chained(const struct ccmode_cfb8 *cfb8, const struct ccmode_cfb8_vector *v, int dec)
{
    if (dec) {
        return ccmode_cfb8_test_one_chained(cfb8, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    } else {
        return ccmode_cfb8_test_one_chained(cfb8, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
    }
}

/* GCM */

int ccmode_gcm_test_one_chained(const struct ccmode_gcm *gcm,
                                size_t keylen, const void *keydata,
                                size_t ivlen,  const void *iv,
                                size_t adalen, const void *ada,
                                size_t nbytes, const void *in, const void *out,
                                size_t taglen, const void *tag)
{
    /* mac and crypt one byte at a time */
    size_t i;
    unsigned char temp[nbytes];
    unsigned char temptag[taglen];
    ccgcm_ctx_decl(gcm->size, key);

    if (gcm->init(gcm, key, keylen, keydata)) {
        return -1;
    }
    if (gcm->set_iv(key, ivlen, iv)) {
        return -1;
    }

    const unsigned char *p = ada;
    if (adalen) {
        for (i = 0; i < adalen; i++) {
            if (gcm->gmac(key, 1, &p[i])) {
                return -1;
            }
        }
    } else {
        if (gcm->gmac(key, 0, NULL)) {
            return -1;
        }
    }

    p = in;
    if (nbytes) {
        for (i = 0; i < nbytes; i++) {
            if (gcm->gcm(key, 1, &p[i], &temp[i])) {
                return -1;
            }
        }
    } else {
        if (gcm->gcm(key, 0, NULL, NULL)) {
            return -1;
        }
    }
    memcpy(temptag, tag, taglen);
    int rc=gcm->finalize(key, taglen, temptag); //for decryption should return zero because we passed the correct tag


#ifdef _INTERNAL_DEBUG_
    int r1, r2;
    r1 = memcmp(out, temp, nbytes);
    r2 = memcmp(tag, temptag, taglen);
    if (r1 || r2)
        cc_printf("ivlen: %lu adalen: %lu nbytes: %lu taglen: %lu crypt: %d tag: %d\n",
               ivlen, adalen, nbytes, taglen, r1, r2);

    return r1 != 0 ? r1 : r2;
#else
    return rc || memcmp(out, temp, nbytes) || memcmp(tag, temptag, taglen);
#endif
}


int ccmode_gcm_test_one_vector(const struct ccmode_gcm *gcm, const struct ccmode_gcm_vector *v, int dec)
{
    if (v->ptlen != v->ctlen) {
        return -1;
    }

    char expected_tag[v->taglen];

    int rc = 0;
    if (dec) {
        char pt_out[v->ptlen];

        memcpy(expected_tag, v->tag, v->taglen);
        rc = ccgcm_one_shot(gcm, v->keylen, v->key, v->ivlen, v->iv, v->adalen, v->ada, v->ctlen, v->ct, pt_out, v->taglen, expected_tag);
         //this is not needed in practice, we do it because this is a test fucntion
        rc = rc | memcmp(pt_out, v->pt, v->ptlen) | memcmp(expected_tag, v->tag, v->taglen);
     }else{
        char ct_out[v->ptlen];
        rc = ccgcm_one_shot(gcm, v->keylen, v->key, v->ivlen, v->iv, v->adalen, v->ada, v->ptlen, v->pt, ct_out, v->taglen, expected_tag);
        rc = rc | memcmp(ct_out, v->ct, v->ctlen) | memcmp(expected_tag, v->tag, v->taglen);

    }
    return rc;
}

int ccmode_gcm_test_one_vector_chained(const struct ccmode_gcm *gcm, const struct ccmode_gcm_vector *v, int dec)
{
    if (v->ptlen != v->ctlen) {
        return -1;
    }

    if (dec) {
        return ccmode_gcm_test_one_chained(gcm, v->keylen, v->key, v->ivlen, v->iv, v->adalen, v->ada, v->ptlen, v->ct, v->pt, v->taglen, v->tag);
    } else {
        return ccmode_gcm_test_one_chained(gcm, v->keylen, v->key, v->ivlen, v->iv, v->adalen, v->ada, v->ptlen, v->pt, v->ct, v->taglen, v->tag);
    }
}



/* does one XTS encryption or decryption and compare result */
int ccmode_xts_test_one(const struct ccmode_xts *xts, size_t keylen,
                        const void *dkey, const void *tkey, const void *iv,
                        size_t nbytes, const void *in, void *out,
                        int dec)
{
    ccxts_ctx_decl(xts->size, key);
    ccxts_tweak_decl(xts->tweak_size, tweak);
    if (xts->init(xts, key, keylen, dkey, tkey)) {
        return -1;
    }

    if (xts->set_tweak(key, tweak, iv)) {
        return -1;
    }

    /* Use raw xex mode when nbytes is a multiple of the blocksize. */
    if ((nbytes & 15) == 0) {
        if (xts->xts(key, tweak, nbytes >> 4, in, out) == NULL) {
            return -1;
        }
    } else {
        if (dec) {
            if (ccpad_xts_decrypt(xts, key, tweak, nbytes, in, out) != nbytes) {
                return -1;
            }
        } else {
            ccpad_xts_encrypt(xts, key, tweak, nbytes, in, out);
        }
    }

    return 0;
}

/* Test one test vector - use dec=1 to reverse pt and ct */
int ccmode_xts_test_one_vector(const struct ccmode_xts *xts,
                               const struct ccmode_xts_vector *v, void *out,
                               int dec)
{
    if (dec) {
        return ccmode_xts_test_one(xts, v->keylen, v->dkey, v->tkey, v->tweak,
                                   v->nbytes, v->ct, out, dec);
    } else {
        return ccmode_xts_test_one(xts, v->keylen, v->dkey, v->tkey, v->tweak,
                                   v->nbytes, v->pt, out, dec);
    }
}

/* Test one test vector, 1 block at a time */
int ccmode_xts_test_one_chained(const struct ccmode_xts *xts,
                                size_t keylen, const void *dkey,
                                const void *tkey, const void *iv,
                                size_t nbytes, const void *in,
                                void *out, int dec)
{
    size_t i;
    const unsigned char *input=in;
    unsigned char *output=out;
    ccxts_ctx_decl(xts->size, key);
    ccxts_tweak_decl(xts->tweak_size, tweak);

    if (xts->init(xts, key, keylen, dkey, tkey) != 0) {
        return -1;
    }
    if (xts->set_tweak(key, tweak, iv)) {
        return -1;
    }

    size_t nblocks = nbytes >> 4;
    if (nbytes & 15) {
        nblocks -= 1;
    }

    for (i=0; i < nblocks; i++) {
        if (xts->xts(key, tweak, 1, &input[i*xts->block_size], &output[i*xts->block_size]) == NULL) {
            return -1;
        }
    }

    if (nbytes & 15) {
        nbytes -= nblocks * xts->block_size;

        if (dec) {
            if (ccpad_xts_decrypt(xts, key, tweak, nbytes, &input[nblocks*xts->block_size],
                                  &output[nblocks*xts->block_size]) != nbytes) {
                return -1;
            }
        } else {
            ccpad_xts_encrypt(xts, key, tweak, nbytes, &input[nblocks*xts->block_size],
                              &output[nblocks*xts->block_size]);
        }
    }

    return 0;
}

int ccmode_xts_test_one_vector_chained(const struct ccmode_xts *xts,
                                       const struct ccmode_xts_vector *v,
                                       void *out, int dec)
{
    if (dec) {
        return ccmode_xts_test_one_chained(xts, v->keylen, v->dkey, v->tkey, v->tweak,
                                           v->nbytes, v->ct, out, dec);
    } else {
        return ccmode_xts_test_one_chained(xts, v->keylen, v->dkey, v->tkey, v->tweak,
                                           v->nbytes, v->pt, out, dec);
    }
}


/* CCM */

int ccmode_ccm_test_one(const struct ccmode_ccm *ccm, size_t keylen, const void *keydata,
                        size_t noncelen, const void *noncedata, size_t adalen, const void *ada,
                        size_t nbytes, const void *in, const void *out,
                        size_t mac_size, const void *mac, int chained)
{
    unsigned char temp[nbytes];
    unsigned char tempmac[mac_size];
    ccccm_ctx_decl(ccm->size, key);
    ccccm_nonce_decl(ccm->nonce_size, nonce);

    /* mac and crypt one byte at a time */
    if (chained) {
        if (ccm->init(ccm, key, keylen, keydata)) {
            return -1;
        }
        if (ccm->set_iv(key, nonce, noncelen, noncedata, mac_size, adalen, nbytes)) {
            return -1;
        }

        const unsigned char *p = ada;
        if (adalen) {
            for (unsigned i = 0; i < adalen; i++) {
                if (ccm->cbcmac(key, nonce, 1, &p[i])) {
                    return -1;
                }
            }
        } else {
            if (ccm->cbcmac(key, nonce, 0, NULL)) {
                return -1;
            }
        }

        p = in;
        if (nbytes) {
            for (unsigned i = 0; i < nbytes; i++) {
                if (ccm->ccm(key, nonce, 1, &p[i], &temp[i])) {
                    return -1;
                }
            }
        } else {
            if (ccm->ccm(key, nonce, 0, NULL, NULL)) {
                return -1;
            }
        }

        if (ccm->finalize(key, nonce, tempmac)) {
            return -1;
        }
    } else {
        if (ccccm_one_shot(ccm, keylen, keydata, noncelen, noncedata, nbytes, in, temp, adalen, ada, mac_size, tempmac)) {
            return -1;
        }
    }

#ifdef _INTERNAL_DEBUG_
    int r1, r2;
    r1 = memcmp(out, temp, nbytes);
    r2 = memcmp(mac, tempmac, mac_size);
    if (r1 || r2)
        printf("nonce_len: %u adalen: %lu nbytes: %lu taglen: %u crypt: %d tag: %d\n",
               nonce_len, adalen, nbytes, mac_size, r1, r2);

    return r1 != 0 ? r1 : r2;
#else
    return memcmp(out, temp, nbytes) || memcmp(mac, tempmac, mac_size);
#endif
}

/* Test one test vector - use dec=1 to reverse pt and ct */
int ccmode_ccm_test_one_vector(const struct ccmode_ccm *ccm,
                                const struct ccmode_ccm_vector *v,
                                int dec, int chained)
{
    if (dec) {
        return ccmode_ccm_test_one(ccm, v->keylen, v->key, v->noncelen, v->nonce, v->adalen, v->ada, v->ptlen, v->ct, v->pt, (unsigned)(v->ctlen - v->ptlen), v->ct + v->ptlen, chained);
    } else {
        return ccmode_ccm_test_one(ccm, v->keylen, v->key, v->noncelen, v->nonce, v->adalen, v->ada, v->ptlen, v->pt, v->ct, (unsigned)(v->ctlen - v->ptlen), v->ct + v->ptlen, chained);
    }
}
