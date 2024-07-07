/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCKPRNG_INTERNAL_H_
#define _CORECRYPTO_CCKPRNG_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/cckprng.h>

#if CC_BUILT_FOR_TESTING
extern uint64_t (*cckprng_reseed_get_nonce_mock)(void);
#endif

/*
 Internal Fortuna
 */

void cckprng_rekeygens(struct cckprng_ctx *ctx);

#define CCKPRNG_LABEL(op) { 0x78, 0x6e, 0x75, 0x70, 0x72, 0x6e, 0x67, op }

enum CCKPRNG_OP {
    CCKPRNG_OP_INIT = 0,
    CCKPRNG_OP_USERRESEED = 1,
    CCKPRNG_OP_SCHEDRESEED = 2,
    CCKPRNG_OP_ADDENTROPY = 3,
    CCKPRNG_OP_INIT_RNG = 4,
};

#define CCKPRNG_REFRESH_MIN_NSAMPLES 32

#define CCKPRNG_SEEDSIZE 32
#define CCKPRNG_SEEDFILE "/var/db/prng.seed"
#define CCKPRNG_RANDOMDEV "/dev/random"

// Read the full seed file and provide its contents to the kernel PRNG
// via the random device.
int cckprng_loadseed(void);

// Request a seed from the kernel PRNG (via getentropy(2)) and persist
// it to the seed file for future boots. Ensure the seed file is
// readable and writable only by root.
int cckprng_storeseed(void);

#endif /* _CORECRYPTO_CCKPRNG_INTERNAL_H_ */
