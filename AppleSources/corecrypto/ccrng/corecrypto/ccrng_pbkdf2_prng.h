/* Copyright (c) (2013,2014,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_ccrng_pbkdf2_prng_h
#define corecrypto_ccrng_pbkdf2_prng_h

#include <corecrypto/ccrng.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccec.h>


#define CCRNG_PBKDF2_BUFFER 4096

// This RNG is limited to provide min("CCRNG_PBKDF2_BUFFER",maxbytes) of cumulated pseudo random bytes.
// Pseudo random bytes can be obtained with one or several "generate"
// When out of random, the generate function will persistently fail until a new initialization of the context is performed.

struct ccrng_pbkdf2_prng_state {
    CCRNG_STATE_COMMON
    size_t random_buffer_size;
    uint8_t random_buffer[CCRNG_PBKDF2_BUFFER];
};


int ccrng_pbkdf2_prng_init(struct ccrng_pbkdf2_prng_state *rng, size_t maxbytes,
                           size_t passwordLen, const void *password,
                           size_t saltLen, const void *salt,
                           size_t iterations);

#endif
