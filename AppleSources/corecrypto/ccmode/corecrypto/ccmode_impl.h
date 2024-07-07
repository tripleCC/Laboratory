/* Copyright (c) (2010-2012,2015-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCMODE_IMPL_H_
#define _CORECRYPTO_CCMODE_IMPL_H_
#include <corecrypto/cc.h>

#define CCMODE_MAX_BLOCK_SIZE 16

/* ECB mode. */
cc_aligned_struct(16) ccecb_ctx;

/* Actual symmetric algorithm implementation should provide you one of these. */
struct ccmode_ecb {
    size_t size; /* first argument to ccecb_ctx_decl(). */
    size_t block_size;
    int (*CC_SPTR(ccmode_ecb, init))(const struct ccmode_ecb *ecb, ccecb_ctx *ctx, size_t key_nbytes, const void *key);
    int (*CC_SPTR(ccmode_ecb, ecb))(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out);
    void (*CC_SPTR(ccmode_ecb, roundkey))(const ccecb_ctx *ctx, unsigned r, void *key);
    cc_impl_t impl;
};

/*!
 * @brief corecrypto symmetrical encryption and decryption modes
 *
 * corecrypto supports 6 stateless en(de)cryption modes and 2 stateful authenticated en(de)cryption modes
 * stateless modes CBC, CFB, CFB8, CTR, OFB, XTS: They provide 3 interface functions that do not return errors codes
 *   1- ccmod_xxx_init()
 *   2- ccmod_xxx_decrypt()
 *   3- ccmod_xxx_encrypt()
 *
 * stateful modes CCM and GCM: They provide 7 interface functions that return error codes if a function is called out of state
 *   1- ccmod_xxx_init()
 *   2- ccmod_xxx_setiv()
 *   3- ccmod_xxx_aad()
 *   4- ccmod_xxx_decrypt()
 *   5- ccmod_xxx_encrypt()
 *   6- ccmod_xxx_finalize()
 *   7- ccmod_xxx_reset()
 *
 *  the correct call sequences are:
 *
 *  calls to 1, 2 and 6 arerequired
 *  2 and 3 can be called as mant times as needed
 *  calls to 3, 4, 5 can be skipped
 *
 *  1, 2*n, 3*n, 4|5, 6
 *  1, 2*n,    , 4|5, 6
 *  1, 2*n,    ,    , 6
 *  1, 2*n, 3*n,    , 6
 */

// 1- CBC mode, stateless
cc_aligned_struct(16) cccbc_ctx;
cc_aligned_struct(16) cccbc_iv;

// This value was derived empirically. It may need to be updated to
// match changes in implementation.
#define CCCBC_MAX_CTX_SIZE 512

struct ccmode_cbc {
    size_t size; /* first argument to cccbc_ctx_decl(). */
    size_t block_size;
    int (*CC_SPTR(ccmode_cbc, init))(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, size_t key_len, const void *key);
    /* cbc encrypt or decrypt nblocks from in to out, iv will be used and updated. */
    int (*CC_SPTR(ccmode_cbc, cbc))(const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out);
    const void *custom;
};

// 2- CFB mode, stateless
cc_aligned_struct(16) cccfb_ctx;

struct ccmode_cfb {
    size_t size; /* first argument to cccfb_ctx_decl(). */
    size_t block_size;
    int (*CC_SPTR(ccmode_cfb,
                  init))(const struct ccmode_cfb *cfb, cccfb_ctx *ctx, size_t key_len, const void *key, const void *iv);
    int (*CC_SPTR(ccmode_cfb, cfb))(cccfb_ctx *ctx, size_t nbytes, const void *in, void *out);
    const void *custom;
};

// 3- CFB8 mode, stateless
cc_aligned_struct(16) cccfb8_ctx;

struct ccmode_cfb8 {
    size_t size; /* first argument to cccfb8_ctx_decl(). */
    size_t block_size;
    int (*CC_SPTR(ccmode_cfb8,
                  init))(const struct ccmode_cfb8 *cfb8, cccfb8_ctx *ctx, size_t key_len, const void *key, const void *iv);
    int (*CC_SPTR(ccmode_cfb8, cfb8))(cccfb8_ctx *ctx, size_t nbytes, const void *in, void *out);
    const void *custom;
};

// 4- CTR mode, stateless
cc_aligned_struct(16) ccctr_ctx;

struct ccmode_ctr {
    size_t size;           /* first argument to ccctr_ctx_decl(). */
    size_t block_size;     /* for historical reasons, this is set to 1 */
    size_t ecb_block_size; /* the actual block size of the underlying cipher */
    int (*CC_SPTR(ccmode_ctr,
                  init))(const struct ccmode_ctr *mode, ccctr_ctx *ctx, size_t key_len, const void *key, const void *iv);
    int (*CC_SPTR(ccmode_ctr, setctr))(const struct ccmode_ctr *mode, ccctr_ctx *ctx, const void *ctr);
    int (*CC_SPTR(ccmode_ctr, ctr))(ccctr_ctx *ctx, size_t nbytes, const void *in, void *out);
    const void *custom;
};

// 5- OFB mode, stateless
cc_aligned_struct(16) ccofb_ctx;

struct ccmode_ofb {
    size_t size; /* first argument to ccofb_ctx_decl(). */
    size_t block_size;
    int (*CC_SPTR(ccmode_ofb,
                  init))(const struct ccmode_ofb *ofb, ccofb_ctx *ctx, size_t key_len, const void *key, const void *iv);
    int (*CC_SPTR(ccmode_ofb, ofb))(ccofb_ctx *ctx, size_t nbytes, const void *in, void *out);
    const void *custom;
};

// 6- XTS mode, stateless
cc_aligned_struct(16) ccxts_ctx;
cc_aligned_struct(16) ccxts_tweak;

struct ccmode_xts {
    size_t size;       /* first argument to ccxts_ctx_decl(). Size of the ctx data structure */
    size_t tweak_size; /* first argument to ccxts_tweak_decl(). Size of the tweak structure, not the expected tweak size */
    size_t block_size;

    /* Create a xts key from a xts mode object.
     key must point to at least 'size' bytes of free storage.
     tweak_key must point to at least 'tweak_size' bytes of free storage.
     key and tweak_key must differ.
     Returns nonzero on failure.
     */
    int (*CC_SPTR(ccmode_xts, init))(const struct ccmode_xts *xts,
                                     ccxts_ctx *ctx,
                                     size_t key_nbytes,
                                     const void *data_key,
                                     const void *tweak_key);

    void (*CC_SPTR(ccmode_xts, key_sched))(const struct ccmode_xts *xts,
                                           ccxts_ctx *ctx,
                                           size_t key_nbytes,
                                           const void *data_key,
                                           const void *tweak_key);

    /* Set the tweak (sector number), the block within the sector zero. */
    int (*CC_SPTR(ccmode_xts, set_tweak))(const ccxts_ctx *ctx, ccxts_tweak *tweak, const void *iv);

    /* Encrypt blocks for a sector, clients must call set_tweak before calling
       this function. Return a pointer to the tweak buffer */
    void *(*CC_SPTR(ccmode_xts, xts))(const ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nblocks, const void *in, void *out);

    const void *custom;
    const void *custom1;
    cc_impl_t impl;
};

// 7- GCM mode, statful
cc_aligned_struct(16) ccgcm_ctx;
#define CCMODE_GCM_DECRYPTOR 78647
#define CCMODE_GCM_ENCRYPTOR 4073947

struct ccmode_gcm {
    size_t size; /* first argument to ccgcm_ctx_decl(). */
    int encdec;  // is it encrypt or decrypt object
    size_t block_size;
    int (*CC_SPTR(ccmode_gcm, init))(const struct ccmode_gcm *gcm, ccgcm_ctx *ctx, size_t key_nbytes, const void *key);
    int (*CC_SPTR(ccmode_gcm, set_iv))(ccgcm_ctx *ctx, size_t iv_nbytes, const void *iv);
    int (*CC_SPTR(ccmode_gcm, gmac))(ccgcm_ctx *ctx, size_t nbytes, const void *in); // could just be gcm with NULL out
    int (*CC_SPTR(ccmode_gcm, gcm))(ccgcm_ctx *ctx, size_t nbytes, const void *in, void *out);
    int (*CC_SPTR(ccmode_gcm, finalize))(ccgcm_ctx *key, size_t tag_nbytes, void *tag);
    int (*CC_SPTR(ccmode_gcm, reset))(ccgcm_ctx *ctx);
    const void *custom;
};

// 8- CCM mode, stateful
cc_aligned_struct(16) ccccm_ctx;
cc_aligned_struct(16) ccccm_nonce;

struct ccmode_ccm {
    size_t size;       /* first argument to ccccm_ctx_decl(). */
    size_t nonce_size; /* first argument to ccccm_nonce_decl(). */
    size_t block_size;
    int (*CC_SPTR(ccmode_ccm, init))(const struct ccmode_ccm *ccm, ccccm_ctx *ctx, size_t key_len, const void *key);
    int (*CC_SPTR(ccmode_ccm, set_iv))(ccccm_ctx *ctx,
                                       ccccm_nonce *nonce_ctx,
                                       size_t nonce_len,
                                       const void *nonce,
                                       size_t mac_size,
                                       size_t auth_len,
                                       size_t data_len);
    int (*CC_SPTR(ccmode_ccm, cbcmac))(ccccm_ctx *ctx,
                                       ccccm_nonce *nonce_ctx,
                                       size_t nbytes,
                                       const void *in); // could just be ccm with NULL out
    int (*CC_SPTR(ccmode_ccm, ccm))(ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const void *in, void *out);
    int (*CC_SPTR(ccmode_ccm, finalize))(ccccm_ctx *key, ccccm_nonce *nonce_ctx, void *mac);
    int (*CC_SPTR(ccmode_ccm, reset))(ccccm_ctx *key, ccccm_nonce *nonce_ctx);
    const void *custom;
    bool enc_mode;
};

/* We need to expose this (currently)to keep CommonCrypto happy. */
struct _ccmode_ccm_nonce {
    unsigned char A_i[16]; /* crypto block iv */
    unsigned char B_i[16]; /* mac block iv */
    unsigned char MAC[16]; /* crypted mac */
    unsigned char buf[16]; /* crypt buffer */

    uint32_t mode;    /* mode: IV -> AD -> DATA */
    uint32_t buflen;  /* length of data in buf */
    uint32_t b_i_len; /* length of cbcmac data in B_i */

    size_t nonce_size;
    size_t mac_size;
};

/* OMAC mode. */
cc_aligned_struct(16) ccomac_ctx;

struct ccmode_omac {
    size_t size; /* first argument to ccomac_ctx_decl(). */
    size_t block_size;
    int (*CC_SPTR(ccmode_omac,
                  init))(const struct ccmode_omac *omac, ccomac_ctx *ctx, size_t tweak_len, size_t key_len, const void *key);
    int (*CC_SPTR(ccmode_omac, omac))(ccomac_ctx *ctx, size_t nblocks, const void *tweak, const void *in, void *out);
    const void *custom;
};

/* This provide an implementation of SIV
 as specified in https://tools.ietf.org/html/rfc5297
 also in http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/siv/siv.pdf
 Counter Mode where IV is based on CMAC
 */

cc_aligned_struct(16) ccsiv_ctx;

struct ccmode_siv {
    size_t size;        /* first argument to ccsiv_ctx_decl(). */
    size_t block_size;
    int (*CC_SPTR(ccmode_siv, init))(const struct ccmode_siv *siv, ccsiv_ctx *ctx,
                 size_t key_len, const uint8_t *key);
    int (*CC_SPTR(ccmode_siv, set_nonce))(ccsiv_ctx *ctx,  size_t nbytes, const uint8_t *in);  // could just be ccm with NULL out
    int (*CC_SPTR(ccmode_siv, auth))(ccsiv_ctx *ctx,  size_t nbytes, const uint8_t *in);  // could just be ccm with NULL out
    int (*CC_SPTR(ccmode_siv, crypt))(ccsiv_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *out);
    int (*CC_SPTR(ccmode_siv, reset))(ccsiv_ctx *ctx);
    const struct ccmode_cbc *cbc;
    const struct ccmode_ctr *ctr;
};

/* This provides an implementation of SIV using AES CTR mode with HMAC as the MAC,
 allowing for a tagging mechanism with collision resistant tags. This is a modification of the
 standard specified in https://tools.ietf.org/html/rfc5297
 also in http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/siv/siv.pdf
 Counter Mode where IV is based on HMAC.
 */

cc_aligned_struct(16) ccsiv_hmac_ctx;

struct ccmode_siv_hmac {
    size_t size; /* first argument to ccsiv_hmac_ctx_decl(). */
    size_t block_size;
    
    int (*CC_SPTR(ccmode_siv_hmac, init))(const struct ccmode_siv_hmac *sivhmac,
                ccsiv_hmac_ctx *ctx,
                size_t key_len,
                const uint8_t *key,
                const size_t tag_size);
    int (*CC_SPTR(ccmode_siv_hmac, set_nonce))(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in);
    int (*CC_SPTR(ccmode_siv_hmac, auth))(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in);
    int (*CC_SPTR(ccmode_siv_hmac, crypt))(ccsiv_hmac_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *out);
    int (*CC_SPTR(ccmode_siv_hmac, reset))(ccsiv_hmac_ctx *ctx);
    const struct ccdigest_info *hmac_digest; // Digest to be used in HMAC;
    const struct ccmode_ctr *ctr;
};

#endif /* _CORECRYPTO_CCMODE_IMPL_H_ */
