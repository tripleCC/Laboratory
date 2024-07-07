/* Copyright (c) (2012,2015,2016,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>

#if  CCAES_INTEL_ASM

#ifndef VNG_AES_PRIV_H_
#define VNG_AES_PRIV_H_
#if defined(__cplusplus)
extern "C"
{
#endif
    
#include "vng_aes.h"
// Assembly level interfaces for basic AES.

#define kUseAESNI 1
#define kUseOPT 0


struct ccaes_intel_xts_tweak_ctx
{
    uint8_t T[16];
};

//int 
//vng_aes_encrypt_key(const unsigned char *key, int key_len, vng_aes_encrypt_ctx cx[1]);

int
vng_aes_encrypt_opt_key(const unsigned char *key, int key_len, vng_aes_encrypt_ctx cx[1]) __asm__("_vng_aes_encrypt_opt_key");

int
vng_aes_encrypt_aesni_key(const unsigned char *key, int key_len, vng_aes_encrypt_ctx cx[1]) __asm__("_vng_aes_encrypt_aesni_key");



//int 
//vng_aes_decrypt_key(const unsigned char *key, int key_len, vng_aes_decrypt_ctx cx[1]);

int
vng_aes_decrypt_opt_key(const unsigned char *key, int key_len, vng_aes_decrypt_ctx cx[1]) __asm__("_vng_aes_decrypt_opt_key");

int
vng_aes_decrypt_aesni_key(const unsigned char *key, int key_len, vng_aes_decrypt_ctx cx[1]) __asm__("_vng_aes_decrypt_aesni_key");



//extern int vng_aes_encrypt_cbc(const unsigned char *ibuf, const unsigned char *in_iv, unsigned int num_blk, unsigned char *obuf, vng_aes_encrypt_ctx *encrypt);
extern int vng_aes_encrypt_opt_cbc(const unsigned char *ibuf, const unsigned char *in_iv, unsigned int num_blk, unsigned char *obuf, const vng_aes_encrypt_ctx *encrypt) __asm__("_vng_aes_encrypt_opt_cbc");
extern int vng_aes_encrypt_aesni_cbc(const unsigned char *ibuf, const unsigned char *in_iv, unsigned int num_blk, unsigned char *obuf, const vng_aes_encrypt_ctx *encrypt) __asm__("_vng_aes_encrypt_aesni_cbc");

//extern int vng_aes_decrypt_cbc(const unsigned char *ibuf, const unsigned char *in_iv, unsigned int num_blk, unsigned char *obuf, vng_aes_decrypt_ctx *decript);
extern int vng_aes_decrypt_opt_cbc(const unsigned char *ibuf, const unsigned char *in_iv, unsigned int num_blk, unsigned char *obuf, const vng_aes_decrypt_ctx *decript) __asm__("_vng_aes_decrypt_opt_cbc");
extern int vng_aes_decrypt_aesni_cbc(const unsigned char *ibuf, const unsigned char *in_iv, unsigned int num_blk, unsigned char *obuf, const vng_aes_decrypt_ctx *decript) __asm__("_vng_aes_decrypt_aesni_cbc");

// Prototypes for assembly functions used in optimized AES-XTS for x86.

extern void aesxts_mult_x(uint8_t *I) __asm__("_aesxts_mult_x");
extern int aesxts_tweak_crypt_opt(const uint8_t *P, uint8_t *C, const uint8_t *T, const vng_aes_encrypt_ctx *ctx) __asm__("_aesxts_tweak_crypt_opt");
extern int aesxts_tweak_crypt_aesni(const uint8_t *P, uint8_t *C, const uint8_t *T, const vng_aes_encrypt_ctx *ctx) __asm__("_aesxts_tweak_crypt_aesni");

extern int aesxts_tweak_crypt_group_aesni(const uint8_t *P, uint8_t *C, const uint8_t *T, const vng_aes_encrypt_ctx *ctx, uint32_t lim) __asm__("_aesxts_tweak_crypt_group_aesni");
extern int aesxts_tweak_crypt_group_opt(const uint8_t *P, uint8_t *C, const uint8_t *T, const vng_aes_encrypt_ctx *ctx, uint32_t lim) __asm__("_aesxts_tweak_crypt_group_opt");

extern int aesxts_tweak_uncrypt_opt(const uint8_t *C, uint8_t *P, const uint8_t *T, const vng_aes_decrypt_ctx *ctx) __asm__("_aesxts_tweak_uncrypt_opt");;
extern int aesxts_tweak_uncrypt_aesni(const uint8_t *C, uint8_t *P, const uint8_t *T, const vng_aes_decrypt_ctx *ctx) __asm__("_aesxts_tweak_uncrypt_aesni");


extern int aesxts_tweak_uncrypt_group_aesni(const uint8_t *C, uint8_t *P, const uint8_t *T, const vng_aes_decrypt_ctx *ctx, uint32_t lim) __asm__("_aesxts_tweak_uncrypt_group_aesni");
extern int aesxts_tweak_uncrypt_group_opt(const uint8_t *C, uint8_t *P, const uint8_t *T, const vng_aes_decrypt_ctx *ctx, uint32_t lim) __asm__("_aesxts_tweak_uncrypt_group_opt");


#if defined(__cplusplus)
}
#endif

#endif /* VNG_AES_PRIV_H_ */
#endif // CCAES_INTEL_ASM
