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

#if CCAES_ARM_ASM && !defined(__arm64__)

/*
    aes_ctr_crypt((const void*) pt, (void*) ct, j, (void *) ctr, (void *) ecb_key);
    {

        while (j>0) {
              aes_encrypt(ctr, tmp, ctx);
              *ct++ = *pt++ ^ tmp;
                ctr++;
                j+=16;
        }
    }
*/

    #define	t		r12
    #define pt      r4
    #define ct      r5
    #define nb      r8
    #define ctr     r6
    #define ctx     r10 

	.text
    .syntax unified
    .align  2
    .code   16
    .thumb_func     _aes_ctr_crypt

	.globl _aes_ctr_crypt
_aes_ctr_crypt:

	ldr		t, [sp, #0]			// load the 5th calling argument (ctx) before we move the stack pointer
    push    {r4-r7,lr}
    add     r7, sp, #12 
    push    {r8-r11}
    sub     sp, sp, #16         // tmp for aes_encrypt output

    /* transfer registers */
    mov     pt, r0
    mov     ct, r1
    mov     nb , r2, lsr #4
    mov     ctr, r3
    mov     ctx, t

0:

    // aes_cfb_encrypt(ctr,tmp,ctx);
    mov     r0, ctr
    mov     r1, sp
    mov     r2, ctx
    bl      _AccelerateCrypto_AES_encrypt

    ldmia   sp, {r0-r3}
    ldr     r9, [pt], #4
    ldr     r11, [pt], #4
    ldr     r12, [pt], #4
    ldr     lr, [pt], #4
    
    eor     r0, r9, r0
    eor     r1, r11, r1
    eor     r2, r12, r2
    eor     r3, lr, r3

    str     r0, [ct], #4
    str     r1, [ct], #4
    str     r2, [ct], #4
    str     r3, [ct], #4

    ldr     r0, [ctr, #12]
    ldr     r1, [ctr, #8]
    rev     r0, r0 
    rev     r1, r1 
    adds    r0, r0, #1
    adc     r1, r1, #0
    rev     r0, r0 
    rev     r1, r1 
    str     r0, [ctr, #12]
    str     r1, [ctr, #8]

    subs    nb, nb, #1
    bgt     0b

    add     sp, sp, #16         // tmp for aes_encrypt output
    pop     {r8-r11}
    pop     {r4-r7,pc}

#endif /* CCAES_ARM_ASM */

