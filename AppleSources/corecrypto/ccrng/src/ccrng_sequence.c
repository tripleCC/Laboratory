/* Copyright (c) (2013-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* This is a RNG that is deterministic -  useful for testing */

/* 
    RNG that reads byte from an array set a init time.
    It starts from the beginning of the buffer on every generate.
    When exceeding the length, it rolls over silently.
    If the lenght of the sequence is 0, it returns an error
 */

#include "cc_internal.h"
#include <corecrypto/ccrng_sequence.h>
#include "ccrng_sequence_non_repeat.h"

static int sequence_repeat_generate(struct ccrng_state *rng, size_t entropy_size, void *entropy)
{
    struct ccrng_sequence_state *thisrng = (struct ccrng_sequence_state *)rng;
    uint8_t *e_bytes = (uint8_t *) entropy;
    if (thisrng->len == 0) {
        return CCERR_CRYPTO_CONFIG;
    }
    for (size_t i = 0; i < entropy_size; i++) {
        e_bytes[i] = thisrng->state[i%thisrng->len];
    }
    return 0;
}

int ccrng_sequence_init(struct ccrng_sequence_state *rng, size_t len, const uint8_t *sequence)
{
    CC_ENSURE_DIT_ENABLED

    rng->generate=sequence_repeat_generate;
    rng->state=sequence;
    rng->len=len;
    return 0;
}

static int non_repeat_sequence_generate(struct ccrng_state *rng, size_t entropy_size, void *entropy)
{
    struct ccrng_sequence_state *thisrng = (struct ccrng_sequence_state *)rng;
    uint8_t *e_bytes = (uint8_t *) entropy;
    if (thisrng->len<entropy_size) return CCERR_OUT_OF_ENTROPY;
    for(size_t i=0; i<entropy_size; i++) {
        e_bytes[i] = thisrng->state[i];
    }
    thisrng->state+=entropy_size;
    thisrng->len-=entropy_size;
    return 0;
}

int ccrng_sequence_non_repeat_init(struct ccrng_sequence_state *rng, size_t len, const uint8_t *sequence)
{
    rng->generate=non_repeat_sequence_generate;
    rng->state=sequence;
    rng->len=len;
    return 0;
}

