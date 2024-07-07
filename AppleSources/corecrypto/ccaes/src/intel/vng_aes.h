/* Copyright (c) (2012,2015,2016,2018,2019) Apple Inc. All rights reserved.
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
 * Parts of this code adapted from LibTomCrypt vng_aes.h
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

#if  CCAES_INTEL_ASM

#ifndef VNG_AES_H_
#define VNG_AES_H_

#include <stdint.h>


/* error codes [will be expanded in future releases] */
enum {
    CRYPT_OK=0,             /* Result OK */
    CRYPT_ERROR,            /* Generic Error */
    CRYPT_NOP,              /* Not a failure but no operation was performed */
    
    CRYPT_INVALID_KEYSIZE,  /* Invalid key size given */
    CRYPT_INVALID_ROUNDS,   /* Invalid number of rounds */
    CRYPT_FAIL_TESTVECTOR,  /* Algorithm failed test vectors */
    
    CRYPT_BUFFER_OVERFLOW,  /* Not enough space for output */
    CRYPT_INVALID_PACKET,   /* Invalid input packet given */
    
    CRYPT_INVALID_PRNGSIZE, /* Invalid number of bits for a PRNG */
    CRYPT_ERROR_READPRNG,   /* Could not read enough from PRNG */
    
    CRYPT_INVALID_CIPHER,   /* Invalid cipher specified */
    CRYPT_INVALID_HASH,     /* Invalid hash specified */
    CRYPT_INVALID_PRNG,     /* Invalid PRNG specified */
    
    CRYPT_MEM,              /* Out of memory */
    
    CRYPT_PK_TYPE_MISMATCH, /* Not equivalent types of PK keys */
    CRYPT_PK_NOT_PRIVATE,   /* Requires a private PK key */
    
    CRYPT_INVALID_ARG,      /* Generic invalid argument */
    CRYPT_FILE_NOTFOUND,    /* File Not Found */
    
    CRYPT_PK_INVALID_TYPE,  /* Invalid type of PK key */
    CRYPT_PK_INVALID_SYSTEM,/* Invalid PK system specified */
    CRYPT_PK_DUP,           /* Duplicate key already in key ring */
    CRYPT_PK_NOT_FOUND,     /* Key not found in keyring */
    CRYPT_PK_INVALID_SIZE,  /* Invalid size input for PK parameters */
    
    CRYPT_INVALID_PRIME_SIZE,/* Invalid size of prime requested */
    CRYPT_PK_INVALID_PADDING,/* Invalid padding on input */
    
    CRYPT_HASH_OVERFLOW,     /* Hash applied to too many bits */
    CRYPT_UNIMPLEMENTED,     /* called an unimplemented routine through a function table */
    CRYPT_PARAM,                /* Parameter Error */
    
    CRYPT_FALLBACK           /* Accelerator was called, but the input didn't meet minimum criteria - fallback to software */
};

#if defined(__cplusplus)
extern "C"
{
#endif
    
#define KS_LENGTH       60

typedef struct {   
	uint32_t ks[KS_LENGTH];
    uint32_t rn;
} vng_aes_encrypt_ctx;

typedef struct {   
	uint32_t ks[KS_LENGTH];
	uint32_t rn;
} vng_aes_decrypt_ctx;

typedef struct {   
	vng_aes_encrypt_ctx encrypt;
	vng_aes_decrypt_ctx decrypt;
} vng_aes_ctx, vng_aes_keysched;
    
int vng_aes_xts_encrypt_opt(
                   const uint8_t *pt, size_t ptlen,
                   uint8_t *ct,
                   const uint8_t *tweak,
                   const void *xts);

int vng_aes_xts_encrypt_aesni(
                   const uint8_t *pt, size_t ptlen,
                   uint8_t *ct,
                   const uint8_t *tweak,
                   const void *xts);

int vng_aes_xts_decrypt_opt(
                   const uint8_t *ct, size_t ptlen,
                   uint8_t *pt,
                   const uint8_t *tweak,
                   const void *xts);
				
int vng_aes_xts_decrypt_aesni(
                   const uint8_t *ct, size_t ptlen,
                   uint8_t *pt,
                   const uint8_t *tweak,
                   const void *xts);


#if defined(__cplusplus)
}
#endif
#endif /* VNG_AES_H_ */
#endif  //CCAES_INTEL_ASM
