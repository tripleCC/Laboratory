/* Copyright (c) (2014,2015,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include <corecrypto/ccpad.h>
#include <corecrypto/cc_priv.h>

#define DECODE_MINIMAL                  1
#define DECODE_NOT_CONSTANT_TIME        2
#define FULL_DECODE_CONSTANT_TIME       3
#define LAST_BYTE_DECODE_CONSTANT_TIME  4

#define DECODE_SELECT LAST_BYTE_DECODE_CONSTANT_TIME

/* Constant time pkcs7 padding check. */
size_t ccpad_pkcs7_decode(const size_t block_size, const uint8_t* last_block) {
    CC_ENSURE_DIT_ENABLED

    size_t pad = last_block[block_size - 1];
#if (DECODE_SELECT == LAST_BYTE_DECODE_CONSTANT_TIME)
    /* RECOMMENDED: This processes the last byte only so that leaks are harmless.
     It provides the correct info if the decryption was correct.
     Although this may seem incomplete, it provides good protection against timing attacks since behavior
     based on incorrect length at the application level only leaks info about the last byte.

     A partial check is ok because a padding check (or associate length) is NOT a good way to verify 
     that decryption is correct.
     
    */
    size_t default_size=0; // Value returned in case of incorrect padding
    size_t failed=0;
    failed=(0xff& (~block_size))+pad;  // MSByte>0 iff pad>block_size
    failed|=(0x100-pad);  // MSByte>0 iff pad>block_size
    failed=(0x100-(failed>>8));          // => 0xff iff failed==1
    return ((~failed) & pad) + ((failed) & default_size);
#elif (DECODE_SELECT==FULL_DECODE_CONSTANT_TIME)
#warning "Not recommended: behavior of applicaton can still leak padding info"
    /* Actual time constant version 
    Behaves the same as the legacy version below */
    unsigned char default_size=block_size; // Value returned in case of incorrect padding
    uint16_t mask;
    uint16_t counting=0x100;
    uint16_t failed=0;
    size_t pad_counter=0x100;

    for(size_t i=block_size-1; i>0;i--)
    {
        uint16_t flag=(pad^last_block[i - 1]); // 0 if ok
        flag=(0x100^(flag+0xFF)); // flag 1 iff pad==0;
        counting&=flag;
        pad_counter+= (flag & counting);
    }
    failed|=(0xFF+(pad^(pad_counter>>8))); // Failed flag is the MSB
    mask=(0xff*(failed>>8));        // => 0xff iff failed==1
    return ((~mask) & pad) + ((mask) & default_size);
#elif (DECODE_SELECT==DECODE_NOT_CONSTANT_TIME)
#warning "Not recommended: not constant time"
    /* Not constant time pkcs7 padding check. 
     Kept here to play with the ccpad constant time detection algorithm
     */
    bool failed = pad > block_size;
    failed |= pad == 0;
    for (size_t ix = 2; ix <= block_size; ++ix) {
        failed |= ((ix > pad)
                   ? false
                   : last_block[block_size - ix] != pad);
    }
    /* To be safe we remove the entire offending block if the pkcs7 padding
     checks failed.  However we purposely don't report the failure to decode
     the padding since any use of this error leads to potential security
     exploits. */
    return failed ? block_size : pad;
#elif (DECODE_SELECT==DECODE_MINIMAL)
#warning "Not recommended: just a stub to have the correct behavior, not to be used"
    /* Time constant implementation
     If padding is not correct, it returns an arbitrary length in [1..block_size]
     Kept here as a reference for time constant algorithm */
    return ((pad-1) & (block_size-1))+1;
#else
#error "Invalid value of DECODE_SELECT"
#endif

}
