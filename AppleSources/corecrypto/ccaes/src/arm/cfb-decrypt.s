# Copyright (c) (2015,2016,2019,2021) Apple Inc. All rights reserved.
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

    aes_cfb_decrypt(const aes_encrypt_ctx *ctx, __m128 *iv, int num_blk, const __m128 *ibuf, __m128 *obuf)
    {

        while (num_blk--) {
              aes_encrypt(iv, tmp, ctx);
              *iv = *ibuf++;
              *obuf++ = *iv ^ tmp;
        }
    }
*/

    #define	t		r12
    #define ibuf    r4
    #define iv      r5
    #define nb      r8
    #define obuf    r6
    #define ctx     r10 

	.text
    .syntax unified
    .align  2
    .code   16
    .thumb_func _ccaes_cfb_decrypt_vng_vector 

	.globl _ccaes_cfb_decrypt_vng_vector
_ccaes_cfb_decrypt_vng_vector:

	ldr		t, [sp, #0]			// load the 5th calling argument (ctx) before we move the stack pointer
    push    {r4-r6,r8-r11,lr}

    /* transfer registers */
    mov     ctx, r0
    mov     iv, r1
    mov     nb , r2
    mov     ibuf, r3
    mov     obuf, t

0:
    mov     r0, iv
    mov     r1, obuf
    mov     r2, ctx
    bl      _AccelerateCrypto_AES_encrypt


    ldr     r9, [ibuf], #4
    ldr     r11, [ibuf], #4
    ldr     r12, [ibuf], #4
    ldr     lr, [ibuf], #4
    ldr     r0, [obuf]
    ldr     r1, [obuf, #4]
    ldr     r2, [obuf, #8]
    ldr     r3, [obuf, #12]

    eor     r0, r9, r0
    str     r9, [iv]
    eor     r1, r11, r1
    str     r11, [iv, #4]
    eor     r2, r12, r2
    str     r12, [iv, #8]
    eor     r3, lr, r3
    str     lr, [iv, #12]

    str     r0 , [obuf], #4
    str     r1 , [obuf], #4
    str     r2 , [obuf], #4
    str     r3 , [obuf], #4


    subs    nb, nb, #1
    bgt     0b

    pop    {r4-r6,r8-r11,pc}

#endif /* CCAES_ARM_ASM */

