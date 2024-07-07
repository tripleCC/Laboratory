# Copyright (c) (2015,2016,2018,2019,2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if CCAES_ARM_ASM
#if !defined(__arm64__)

    /*
            armv7 implementation of ccm-encrypt functions

            void ccm_encrypt(void *in, void *out, void *tag, int nblocks, void *key, void *ctr, int ctr_len);

            ctr_len : 2-7, meaning the number of bytes that will increment inside ctr
    */


#define pin     r4
#define pout    r5
#define ptag    r6
#define nblocks r8
#define pctr    r10


/*
    ccaes_arm_encrypt(const unsigned char *in, unsigned char *out, const ccaes_arm_encrypt_ctx cx[1]);
*/
    .extern _AccelerateCrypto_AES_encrypt

    .syntax unified
    .align  2
    .code   16
    .thumb_func _ccm_encrypt 

    .globl _ccm_encrypt
_ccm_encrypt:

/* set up often used constants in registers */
    push    {r4-r7,lr}
    add     r7, sp, #12     // setup frame pointer
    push    {r8-r11}
    sub     sp, sp, #32

    mov     pin, r0
    mov     pout, r1
    mov     ptag, r2
    mov     nblocks, r3
    ldr     pctr, [r7, #12]
    ldr     r12, [r7, #16]      // ctr_len 2:7

    /*
        precompute mask for ctr_len 
            2 : 0000 0000 0000 FFFF
            7 : 00FF FFFF FFFF FFFF
    */
    cmp     r12, 4
    bgt     1f
    rsb     r12, #4
    mov     r0, #-1
    mov     r1, #0
    lsl     r12, #3
    lsr     r0, r12
    b       2f
1:
    mov     r1, #-1
    mov     r0, #-1
    rsb     r12, #8
    lsl     r12, #3
    lsr     r1, r12
2:
    strd    r0, r1, [sp, #24]

    /*
        read ctr higher half, byte swap, save in stack
    */
    ldrd    r2, r3, [pctr, #8]
    rev     r2, r2
    rev     r3, r3
    strd    r2, r3, [sp, #16]

0:

    /* ++ctr */
    ldrd    r2, r3, [sp, #16]       // ctr high half
    adds    r0, r3, #1              //  
    ldr     r12, [sp, #24]
    adc     r1, r2, #0              // r1:r0 = ctr+1 in 8bytes 
    and     r0, r0, r12
    bic     r3, r3, r12
    ldr     r12, [sp, #28]
    and     r1, r1, r12
    bic     r2, r2, r12
    orr     r3, r3, r0
    orr     r2, r2, r1
    strd    r2, r3, [sp, #16]       // ctr high half
    rev     r2, r2
    rev     r3, r3
    strd    r2, r3, [pctr, #8]

    /* tmp = aes_encrypt(++ctr) */
    mov     r0, pctr
    mov     r1, sp
    ldr     r2, [r7, #8]            // key
    bl      _AccelerateCrypto_AES_encrypt

    /* ct = pt ^ tmp */
    ldmia   sp, {r0-r3} // tmp
    ldr     r9, [pin] , #4
    ldr     r11, [pin], #4
    ldr     r12, [pin], #4 
    ldr     lr, [pin], #4 
    eor     r0, r0, r9
    eor     r1, r1, r11
    eor     r2, r2, r12
    eor     r3, r3, lr
    str     r0, [pout], #4
    str     r1, [pout], #4
    str     r2, [pout], #4
    str     r3, [pout], #4

    /* tag ^= pt */
    ldr     r0, [ptag]
    ldr     r1, [ptag, #4]
    ldr     r2, [ptag, #8]
    ldr     r3, [ptag, #12]
    eor     r0, r0, r9
    eor     r1, r1, r11
    eor     r2, r2, r12
    eor     r3, r3, lr
    stmia   sp, {r0-r3}

    /* tag = aes_encrypt(tag) */
    mov     r0, sp
    mov     r1, ptag
    ldr     r2, [r7, #8]            // key
    bl      _AccelerateCrypto_AES_encrypt

    subs    nblocks, #1
    bgt     0b
    
    add     sp, sp, #32

    pop     {r8-r11}
    pop     {r4-r7,pc}

#endif  // __armv7__ w __ARM_NEON__
#endif  // CCAES_ARM_ASM

