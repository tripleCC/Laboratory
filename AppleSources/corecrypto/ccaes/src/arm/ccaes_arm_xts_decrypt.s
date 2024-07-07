# Copyright (c) (2014-2017,2019-2021) Apple Inc. All rights reserved.
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
#if CC_ARM_ARCH_7 || defined(__arm64__)

    /* 
        armv7/arm64 implementation of vectorized function

        ccaes_xts_decrypt_vng_vector(output, input, t, nblocks, CCMODE_XTS_KEY_DATA_KEY(key)) {
            ccn_xor(ccn_nof_size(16), output, input, t);
            aes_decrypt(CCMODE_XTS_KEY_DATA_KEY(key), 1, output, output);
            ccn_xor(ccn_nof_size(16), output, output, t);
            ccmode_xts_mult_alpha(t);
    }
    */


    .text


#if defined(__arm64__)

#include "ccarm_pac_bti_macros.h"

    .align  4
    .globl  _ccaes_xts_decrypt_vng_vector
_ccaes_xts_decrypt_vng_vector:
	BRANCH_TARGET_CALL

    #define out  x0
    #define in   x1
    #define t       x2
    #define nblocks x3
    #define aeskey  x4
    #define NR      w5
    #define ctr     x10
    #define wctr    w10
    #define key     v16
    #define qkey     q16
    #define finalkey     v17
    #define qfinalkey    q17

    #define tweak   v18
    #define tweak0  v24
    #define tweak1  v25
    #define tweak2  v26
    #define tweak3  v27
    #define tweak4  v28
    #define tweak5  v29
    #define tweak6  v30
    #define tweak7  v31

    /*
        tweak = (tweak<<1) modulo 0x1,000...00087
        use v20-v21 as temp registers
        v19 = 0x000...00086 since the carry is rolled into LSB
     */
    .macro  mult_alpha
    ushr.2d v20, tweak, #63
    sshr.2d v21, tweak, #63
    shl.2d  tweak, tweak, #1
    ext.16b v20, v20, v20, #8
    ext.16b v21, v21, v21, #15
    orr.16b v20, v20, tweak
    and.16b v21, v21, v19
    eor.16b tweak, v20, v21
    .endm

    /* fused aes decryption round */
    .macro  aesenc
    aesd.16b    $0, $1
    aesimc.16b   $0, $0
    .endm

    /* fused last aes decryption round */
    .macro  aeslast
    aesd.16b    $0, key
    eor.16b     $0, $0, finalkey
    .endm

    /* aes decryption round on 8 vectors and read the next aes key */
    .macro  round
    aesenc  v0, key
    aesenc  v1, key
    aesenc  v2, key
    aesenc  v3, key
    aesenc  v4, key
    aesenc  v5, key
    aesenc  v6, key
    aesenc  v7, key
    ldr     qkey, [aeskey, ctr]
    .endm

    /* aes decryption round on 8 vectors and store tweak into stack and multi_alpha in paralell */
    .macro  round_compute_alpha
    subs    ctr, ctr, #16
                                    ushr.2d v20, tweak, #63
                                    sshr.2d v21, tweak, #63
                                    st1.4s  {tweak}, [x9], #16
    aesenc  v0, key
                                    shl.2d  tweak, tweak, #1
    aesenc  v1, key
    aesenc  v2, key
                                    ext.16b v20, v20, v20, #8
                                    ext.16b v21, v21, v21, #15
    aesenc  v3, key
    aesenc  v4, key
    aesenc  v5, key
                                    orr.16b v20, v20, tweak
    aesenc  v6, key
                                    and.16b v21, v21, v19
    aesenc  v7, key
                                    eor.16b tweak, v20, v21
    ldr     qkey, [aeskey, ctr]
    .endm

#if CC_KERNEL
    sub     sp, sp, #22*16
    mov     x8, sp
    st1.4s  {v0,v1,v2,v3}, [x8], #4*16
    st1.4s  {v4,v5,v6,v7}, [x8], #4*16
    st1.4s  {v16,v17,v18,v19}, [x8], #4*16
    st1.4s  {v20,v21}, [x8], #2*16
    st1.4s  {v24,v25,v26,v27}, [x8], #4*16
    st1.4s  {v28,v29,v30,v31}, [x8], #4*16
#endif

    // reserve stack space for 8 tweaks 
    sub     sp, sp, #(8*16)    

    // read AES round number 10/12/14 and convert to 160/192/224 (byte address offset) 
    ldr     NR, [aeskey, #240]

    // set up v19 to update and store 8 tweaks in parallel to 8 encryptions 
    eor.16b  v19, v19, v19
    mov     w8, #0x86
    mov     v19.d[0], x8

    ldr     qfinalkey, [aeskey]

    // compute next 8 tweaks and store in stack space 
    mov     x9, sp
    ld1.4s  {tweak}, [t]
    st1.4s  {tweak}, [x9], #16
    mult_alpha
    st1.4s  {tweak}, [x9], #16
    mult_alpha
    st1.4s  {tweak}, [x9], #16
    mult_alpha
    st1.4s  {tweak}, [x9], #16
    mult_alpha
    st1.4s  {tweak}, [x9], #16
    mult_alpha
    st1.4s  {tweak}, [x9], #16
    mult_alpha
    st1.4s  {tweak}, [x9], #16
    mult_alpha
    st1.4s  {tweak}, [x9], #16
    mult_alpha

    subs    nblocks, nblocks, #8
    b.lt    L_lessthan8


    /* 
        main loop : do 8 vectors decryption and 8 tweak updates in paralell
    */

L_loop_8:

    // read 8 tweaks that will used in main loop from previous computation
    mov     x9, sp
    ld1.4s  {tweak0,tweak1,tweak2,tweak3}, [x9], #64
    ld1.4s  {tweak4,tweak5,tweak6,tweak7}, [x9], #64

    mov     wctr, NR

    // read 8 input vectors
    ld1.4s  {v0,v1,v2,v3}, [in], #64
    ld1.4s  {v4,v5,v6,v7}, [in], #64

    ldr     qkey, [aeskey, ctr]
    mov     x9, sp


    /* 
        D = C xor T                  T = multi_alpha(T) 
    */
    eor.16b v0, v0, tweak0
                                    st1.4s  {tweak}, [x9], #16
    eor.16b v1, v1, tweak1
                                    ushr.2d v20, tweak, #63
                                    sshr.2d v21, tweak, #63
    eor.16b v2, v2, tweak2
                                    shl.2d  tweak, tweak, #1
    eor.16b v3, v3, tweak3
                                    ext.16b v20, v20, v20, #8
                                    ext.16b v21, v21, v21, #15
    eor.16b v4, v4, tweak4
    eor.16b v5, v5, tweak5
    eor.16b v6, v6, tweak6
                                    orr.16b v20, v20, tweak
                                    and.16b v21, v21, v19
    eor.16b v7, v7, tweak7
                                    eor.16b tweak, v20, v21

    /*
        7 more rounds of parelelled 
        D = aes_decrypt(D)           T = multi_alpha(T)
    */
    round_compute_alpha
    round_compute_alpha
    round_compute_alpha
    round_compute_alpha
    round_compute_alpha
    round_compute_alpha
    round_compute_alpha
    subs    ctr, ctr, #16

    /* remaining aes_decrypt on 8 vectors */
0:
    round 
    subs    ctr, ctr, #16
    b.gt    0b

    aeslast v0
    aeslast v1
    aeslast v2
    aeslast v3
    aeslast v4
    aeslast v5
    aeslast v6
    aeslast v7

    // D = D xor T
    eor.16b v0, v0, tweak0
    eor.16b v1, v1, tweak1
    eor.16b v2, v2, tweak2
    eor.16b v3, v3, tweak3
    eor.16b v4, v4, tweak4
    eor.16b v5, v5, tweak5
    eor.16b v6, v6, tweak6
    eor.16b v7, v7, tweak7

    // write 8 output vectors
    st1.4s  {v0,v1,v2,v3}, [out], #64
    st1.4s  {v4,v5,v6,v7}, [out], #64

    subs    nblocks, nblocks, #8
    b.ge    L_loop_8

L_lessthan8:
    mov     x9, sp
    adds    nblocks, nblocks, #7
    b.lt    L_done

L_loop_1:

    // copy and generate next tweak
    ld1.4s  {tweak0},[x9], #16

    mov     wctr, NR

    // read the next input vector
    ld1.4s  {v0}, [in], #16

    // read initial aeskey
    ldr     qkey, [aeskey, ctr]
    sub     ctr, ctr, #16

    // xor input vectors w tweak
    eor.16b v0, v0, tweak0

0:
    aesenc  v0, key
    ldr     qkey, [aeskey, ctr]
    subs    ctr, ctr, #16
    b.gt    0b

    aeslast v0

    // xor output vectors w tweak
    eor.16b v0, v0, tweak0

    // write 1 output vector
    st1.4s  {v0}, [out], #16


    subs    nblocks, nblocks, #1
    b.ge    L_loop_1

L_done:
    ld1.4s  {tweak0}, [x9]
    st1.4s  {tweak0}, [t]

    add     sp, sp, #8*16
#if CC_KERNEL
    ld1.4s  {v0,v1,v2,v3}, [sp], #4*16
    ld1.4s  {v4,v5,v6,v7}, [sp], #4*16
    ld1.4s  {v16,v17,v18,v19}, [sp], #4*16
    ld1.4s  {v20,v21}, [sp], #2*16
    ld1.4s  {v24,v25,v26,v27}, [sp], #4*16
    ld1.4s  {v28,v29,v30,v31}, [sp], #4*16
#endif    
    ret

#else   /* armv7 */

    .syntax unified
    .align  2
    .code   16
    .thumb_func _ccaes_xts_decrypt_vng_vector

    .globl  _ccaes_xts_decrypt_vng_vector
_ccaes_xts_decrypt_vng_vector:

    #define out       r0
    #define in        r1
    #define t         r2
    #define nblocks   r3
    #define key       lr

    push    {r4-r11,lr}
    ldr     lr, [sp, #36]           // key
    ldmia   t, {r9,r10,r11,r12}     // r9-r12 used as tweak

0:
    ldr     r4, [in], #4
    ldr     r5, [in], #4
    ldr     r6, [in], #4
    ldr     r8, [in], #4

    // out = in xor tweak
    eor     r4, r4, r9
    eor     r5, r5, r10
    eor     r6, r6, r11
    eor     r8, r8, r12

    str     r4, [out, #0]
    str     r5, [out, #4]
    str     r6, [out, #8]
    str     r8, [out, #12]

    push    {r0-r3,r8-r9,r12,lr}
    mov     r1, out 
    mov     r2, key
    bl      _AccelerateCrypto_AES_decrypt
    pop     {r0-r3,r8-r9,r12, lr}

    ldr     r4, [out]
    ldr     r5, [out, #4]
    ldr     r6, [out, #8]
    ldr     r8, [out, #12]

    // out = out xor tweak and update tweak
    eor     r4, r4, r9
    adds    r9, r9, r9
    eor     r5, r5, r10
    adcs    r10, r10, r10
    eor     r6, r6, r11
    adcs    r11, r11, r11
    eor     r8, r8, r12
    adcs    r12, r12, r12
    str     r4, [out], #4
    str     r5, [out], #4
    str     r6, [out], #4
    str     r8, [out], #4
    it      cs
    eorcs   r9, r9, #0x87

    subs    nblocks, nblocks, #1
    bgt     0b
    stmia   t, {r9,r10,r11,r12}
    pop     {r4-r11,pc}


// __ARM_NEON__
#endif

#endif
#endif /* CCAES_ARM_ASM */
