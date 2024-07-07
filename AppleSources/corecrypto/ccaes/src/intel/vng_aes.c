/* Copyright (c) (2012,2013,2015,2016,2019,2020,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/*
 * Parts of this code adapted from LibTomCrypt vng_aes.c
 *
 * LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include <corecrypto/cc_config.h>
#include <corecrypto/cc_priv.h>

#if  CCAES_INTEL_ASM && (defined (__i386__) || defined (__x86_64__))

#include <string.h>
#include "vng_aesPriv.h"

/*! XTS Encryption
 @param pt     [in]  Plaintext
 @param ptlen  Length of plaintext (and ciphertext)
 @param ct     [out] Ciphertext
 @param T  [in] The 128--bit encryption tweak (e.g. sector number)
 @param ctx    The XTS structure
 Returns CRYPT_OK upon success
 */

int 
vng_aes_xts_encrypt_opt(
                   const uint8_t *pt, size_t ptlen,
                   uint8_t *ct,
                   const uint8_t *T,
                   const void *ctx)
{
    const vng_aes_encrypt_ctx *xts = ctx;
    uint8_t PP[16], CC[16];
    uint64_t i, m, mo, lim;
    int err = CRYPT_ERROR;
    
    /* get number of blocks */
    m  = ptlen >> 4;
    mo = ptlen & 15;
    
    /* must have at least one full block */
    if (m == 0) {
        return CRYPT_INVALID_ARG;
    }
    
    /* for i = 0 to m-2 do */
    if (mo == 0) {
        lim = m;
    } else {
        lim = m - 1;
    }
    
    
    if (lim>0) {
        if ((err = aesxts_tweak_crypt_group_opt(pt, ct, T, xts, (uint32_t)lim)) != CRYPT_OK) {
            return err;
        }
        ct += (lim<<4);
        pt += (lim<<4);
    }
    
    /* if ptlen not divide 16 then */
    if (mo > 0) {
        /* CC = tweak encrypt block m-1 */
        if ((err = aesxts_tweak_crypt_opt(pt, CC, T, xts)) != CRYPT_OK) {
            return err;
        }
        
        /* Cm = first ptlen % 16 bytes of CC */
        for (i = 0; i < mo; i++) {
            PP[i] = pt[16+i];
            ct[16+i] = CC[i];
        }
        
        for (; i < 16; i++) {
            PP[i] = CC[i];
        }
        
        /* Cm-1 = Tweak encrypt PP */
        if ((err = aesxts_tweak_crypt_opt(PP, ct, T, xts)) != CRYPT_OK) {
            return err;
        }
    }
    
    return err;
}

int 
vng_aes_xts_encrypt_aesni(
                   const uint8_t *pt, size_t ptlen,
                   uint8_t *ct,
                   const uint8_t *T,
                   const void *ctx)
{
    const vng_aes_encrypt_ctx *xts = ctx;
    uint8_t PP[16], CC[16];
    uint64_t i, m, mo, lim;
    int err = CRYPT_ERROR;
    
    /* get number of blocks */
    m  = ptlen >> 4;
    mo = ptlen & 15;
    
    /* must have at least one full block */
    if (m == 0) {
        return CRYPT_INVALID_ARG;
    }
    
    /* for i = 0 to m-2 do */
    if (mo == 0) {
        lim = m;
    } else {
        lim = m - 1;
    }
    
    if (lim>0) {
        if ((err = aesxts_tweak_crypt_group_aesni(pt, ct, T, xts, (uint32_t)lim)) != CRYPT_OK) {
            return err;
        }
        ct += (lim<<4);
        pt += (lim<<4);
    }
    
    /* if ptlen not divide 16 then */
    if (mo > 0) {
        /* CC = tweak encrypt block m-1 */
        if ((err = aesxts_tweak_crypt_aesni(pt, CC, T, xts)) != CRYPT_OK) {
            return err;
        }
        
        /* Cm = first ptlen % 16 bytes of CC */
        for (i = 0; i < mo; i++) {
            PP[i] = pt[16+i];
            ct[16+i] = CC[i];
        }
        
        for (; i < 16; i++) {
            PP[i] = CC[i];
        }
        
        /* Cm-1 = Tweak encrypt PP */
        if ((err = aesxts_tweak_crypt_aesni(PP, ct, T, xts)) != CRYPT_OK) {
            return err;
        }
    }
    
    return err;
}


/*! XTS Decryption
 @param ct     [in] Ciphertext
 @param ptlen  Length of plaintext (and ciphertext)
 @param pt     [out]  Plaintext
 @param T  [in] The 128--bit encryption tweak (e.g. sector number)
 @param ctx    The XTS structure
 Returns CRYPT_OK upon success
 */

int 
vng_aes_xts_decrypt_opt(
                   const uint8_t *ct, size_t ptlen,
                   uint8_t *pt,
                   const uint8_t *T,
                   const void *ctx)
{

    const vng_aes_decrypt_ctx *decrypt_ctx = ctx;
    uint8_t PP[16], CC[16];
    uint64_t i, m, mo, lim;
    int err;
    
    /* check inputs */
    if((pt == NULL) || (ct == NULL)|| (decrypt_ctx == NULL)) return 1;
    
    /* get number of blocks */
    m  = ptlen >> 4;
    mo = ptlen & 15;
    
    /* must have at least one full block */
    if (m == 0) {
        return CRYPT_INVALID_ARG;
    }

    
    /* for i = 0 to m-2 do */
    if (mo == 0) {
        lim = m;
    } else {
        lim = m - 1;
    }
    
    if (lim>0) {
        if ((err = aesxts_tweak_uncrypt_group_opt(ct, pt, T, decrypt_ctx,(uint32_t)lim)) != CRYPT_OK) {
            return err;
        }
        ct += (lim<<4);
        pt += (lim<<4);
    }

    /* if ptlen not divide 16 then */
    if (mo > 0) {
        cc_memcpy(CC, T, 16);
        aesxts_mult_x(CC);
        
        /* PP = tweak decrypt block m-1 */
        if ((err = aesxts_tweak_uncrypt_opt(ct, PP, CC, decrypt_ctx)) != CRYPT_OK) {
            return err;
        }
        
        /* Pm = first ptlen % 16 bytes of PP */
        for (i = 0; i < mo; i++) {
            CC[i]    = ct[16+i];
            pt[16+i] = PP[i];
        }
        for (; i < 16; i++) {
            CC[i] = PP[i];
        }
        
        /* Pm-1 = Tweak uncrypt CC */
        if ((err = aesxts_tweak_uncrypt_opt(CC, pt, T, decrypt_ctx)) != CRYPT_OK) {
            return err;
        }
    }
    
    return CRYPT_OK;
}


int 
vng_aes_xts_decrypt_aesni(
                   const uint8_t *ct, size_t ptlen,
                   uint8_t *pt,
                   const uint8_t *T,
                   const void *ctx)
{

    const vng_aes_decrypt_ctx *decrypt_ctx = ctx;
    uint8_t PP[16], CC[16];
    uint64_t i, m, mo, lim;
    int err;
    
    /* check inputs */
    if((pt == NULL) || (ct == NULL)|| (decrypt_ctx == NULL)) return 1;
    
    /* get number of blocks */
    m  = ptlen >> 4;
    mo = ptlen & 15;
    
    /* must have at least one full block */
    if (m == 0) {
        return CRYPT_INVALID_ARG;
    }

    
    /* for i = 0 to m-2 do */
    if (mo == 0) {
        lim = m;
    } else {
        lim = m - 1;
    }
    
    if (lim>0) {
        if ((err = aesxts_tweak_uncrypt_group_aesni(ct, pt, T, decrypt_ctx,(uint32_t)lim)) != CRYPT_OK) {
            return err;
        }
        ct += (lim<<4);
        pt += (lim<<4);
    }
    
    /* if ptlen not divide 16 then */
    if (mo > 0) {
        cc_memcpy(CC, T, 16);
        aesxts_mult_x(CC);
        
        /* PP = tweak decrypt block m-1 */
        if ((err = aesxts_tweak_uncrypt_aesni(ct, PP, CC, decrypt_ctx)) != CRYPT_OK) {
            return err;
        }
        
        /* Pm = first ptlen % 16 bytes of PP */
        for (i = 0; i < mo; i++) {
            CC[i]    = ct[16+i];
            pt[16+i] = PP[i];
        }
        for (; i < 16; i++) {
            CC[i] = PP[i];
        }
        
        /* Pm-1 = Tweak uncrypt CC */
        if ((err = aesxts_tweak_uncrypt_aesni(CC, pt, T, decrypt_ctx)) != CRYPT_OK) {
            return err;
        }
    }
    
    return CRYPT_OK;
}

#endif /* X86 */


