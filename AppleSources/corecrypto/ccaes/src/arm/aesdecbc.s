# Copyright (c) (2011-2016,2019,2020,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if CCAES_ARM_ASM && defined(__arm64__)
#include "ccarm_intrinsic_compatability.h"
#include "ccarm_pac_bti_macros.h"
	// decrypt C code
/*
	aes_rqal aes_decrypt_cbc(const __m128 *ibuf, __m128 *iq, int num_blk, __m128 *obuf, const aes_decrypt_ctx *ctx)
    {
        while(num_blk--) {
            aes_decrypt(ibuf, obuf, ctx);
            *obuf++ ^= *iq;
            *iq = *ibuf++;
        }
        return 0;
    }
*/

	#define	ctx		x0
	#define	iq		x1
	#define	num_blk	x2
	#define	ibuf	x3
	#define	obuf	x4
	#define	keylen	x5
	#define	keylenw	w5
	#define	t		x6

    .macro  decrypt blk, key
	AESD		\blk, \key					// xor/SubByte/ShiftRows
	AESIMC      \blk, \blk  				// MixColumns
    .endm

    .macro  decrypt_final blk, key, last_key
	AESD		\blk, \key					// xor/SubByte/ShiftRows
	eor.16b		v\blk, v\blk, v\last_key    // out = state ^ key[0];
    .endm

	.text
	.align	4
	.globl	_ccaes_arm_decrypt_cbc

_ccaes_arm_decrypt_cbc:
	BRANCH_TARGET_CALL
	// early exit if input number of blocks is zero
	cbnz		num_blk, 1f
	ret			lr
1:


	ldr			keylenw, [ctx, #240]

	cmp     	keylen, #160
    b.eq   		2f
    cmp     	keylen, #192
    b.eq   		2f
    cmp     	keylen, #224
    b.eq     	2f

	mov     	x0, #-1     // Return error.
	ret			lr

2:
#if CC_KERNEL
    // save used vector registers
	sub		x6, sp, #32*16
    sub     sp, sp, #32*16
    st1.4s      {v0,v1,v2,v3}, [x6], #4*16
    st1.4s      {v4,v5,v6,v7}, [x6], #4*16
    st1.4s      {v16,v17,v18,v19}, [x6], #4*16
    st1.4s      {v20,v21,v22,v23}, [x6], #4*16
    st1.4s      {v24,v25,v26,v27}, [x6], #4*16
    st1.4s      {v28,v29,v30,v31}, [x6], #4*16
#else
	sub		x6, sp, #8*16
    sub     sp, sp, #8*16
#endif
    st1.4s      {v8,v9,v10,v11}, [x6], #4*16
    st1.4s      {v12,v13,v14,v15}, [x6], #4*16


	ldr			q31, [iq]				// a copy of *iq

#if (CC_IBOOT==0)   // if not for iBOOT of which limited code space is available

	subs		num_blk, num_blk, #16
	b.lt		L_lessthan_16

L16_loop:    // per 16 blocks
    
    ldr         q0, [ibuf]
    add         ibuf, ibuf, #16*16
    ldr         q1, [ibuf, #-15*16]
    ldr         q2, [ibuf, #-14*16]
    ldr         q3, [ibuf, #-13*16]
    ldr         q4, [ibuf, #-12*16]
    ldr         q5, [ibuf, #-11*16]
    orr.16b     v18, v0, v0
    ldr         q6, [ibuf, #-10*16]
    orr.16b     v19, v1, v1
    ldr         q7, [ibuf, #-9*16]
    orr.16b     v20, v2, v2
    ldr         q8, [ibuf, #-8*16]
    orr.16b     v21, v3, v3
    ldr         q9, [ibuf, #-7*16]
    orr.16b     v22, v4, v4
    ldr         q10, [ibuf, #-6*16]
    orr.16b     v23, v5, v5
    ldr         q11, [ibuf, #-5*16]
    orr.16b     v24, v6, v6
    ldr         q12, [ibuf, #-4*16]
    orr.16b     v25, v7, v7
    ldr         q13, [ibuf, #-3*16]
    orr.16b     v26, v8, v8
    ldr         q14, [ibuf, #-2*16]
    orr.16b     v27, v9, v9
    ldr         q15, [ibuf, #-1*16]
    orr.16b     v28, v10, v10
	ldr			q16, [ctx, keylen]		// expanded key[10]
    orr.16b     v29, v11, v11
	ldr			q17, [ctx]				// expanded key[0]
    orr.16b     v30, v12, v12
	sub			t, keylen, #16

0:
    decrypt     0, 16
    decrypt     1, 16
    decrypt     2, 16
    decrypt     3, 16
    decrypt     4, 16
    decrypt     5, 16
    decrypt     6, 16
    decrypt     7, 16
    decrypt     8, 16
    decrypt     9, 16
    decrypt     10, 16
    decrypt     11, 16
    decrypt     12, 16
    decrypt     13, 16
    decrypt     14, 16
    decrypt     15, 16
	ldr			q16, [ctx, t]			// expanded key[t]
	subs		t, t, #16
	b.gt		0b

    add         obuf, obuf, #16*16
	decrypt_final 0, 16, 17
	decrypt_final 1, 16, 17
	eor.16b		v0, v0, v31
    ldr         q31, [ibuf, #-1*16]
	decrypt_final 2, 16, 17
	eor.16b		v1, v1, v18
    ldr         q18, [ibuf, #-3*16]
	decrypt_final 3, 16, 17
	eor.16b		v2, v2, v19
    ldr         q19, [ibuf, #-2*16]
	decrypt_final 4, 16, 17
	eor.16b		v3, v3, v20
    str         q0, [obuf, #-16*16]
	decrypt_final 5, 16, 17
	eor.16b		v4, v4, v21
    str         q1, [obuf, #-15*16]
	decrypt_final 6, 16, 17
	eor.16b		v5, v5, v22
    str         q2, [obuf, #-14*16]
	decrypt_final 7, 16, 17
	eor.16b		v6, v6, v23
    str         q3, [obuf, #-13*16]
	decrypt_final 8, 16, 17
	eor.16b		v7, v7, v24
    str         q4, [obuf, #-12*16]
	decrypt_final 9, 16, 17
	eor.16b		v8, v8, v25
    str         q5, [obuf, #-11*16]
	decrypt_final 10, 16, 17
	eor.16b		v9, v9, v26
    str         q6, [obuf, #-10*16]
	decrypt_final 11, 16, 17
	eor.16b		v10, v10, v27
    str         q7, [obuf, #-9*16]
	decrypt_final 12, 16, 17
	eor.16b		v11, v11, v28
    str         q8, [obuf, #-8*16]
	decrypt_final 13, 16, 17
	eor.16b		v12, v12, v29
    str         q9, [obuf, #-7*16]
	decrypt_final 14, 16, 17
	eor.16b		v13, v13, v30
    str         q10, [obuf, #-6*16]
	decrypt_final 15, 16, 17
	eor.16b		v14, v14, v18
    str         q11, [obuf, #-5*16]
	eor.16b		v15, v15, v19
    str         q12, [obuf, #-4*16]
    str         q13, [obuf, #-3*16]
    str         q14, [obuf, #-2*16]
    str         q15, [obuf, #-1*16]

	subs		num_blk, num_blk, #16
	b.ge		L16_loop


L_lessthan_16:

	adds		num_blk, num_blk, #8
	b.lt		L_lessthan_8

L8_loop:    // per 8 blocks

    ldr         q0, [ibuf], #8*16
    ldr         q1, [ibuf, #-7*16]
    ldr         q2, [ibuf, #-6*16]
    ldr         q3, [ibuf, #-5*16]
    orr.16b     v18, v0, v0
    ldr         q4, [ibuf, #-4*16]
    orr.16b     v19, v1, v1
    ldr         q5, [ibuf, #-3*16]
    orr.16b     v20, v2, v2
    ldr         q6, [ibuf, #-2*16]
    orr.16b     v21, v3, v3
    ldr         q7, [ibuf, #-1*16]
    orr.16b     v22, v4, v4
	ldr			q16, [ctx, keylen]		// expanded key[10]
    orr.16b     v23, v5, v5
	ldr			q17, [ctx]				// expanded key[0]
    orr.16b     v24, v6, v6
	sub			t, keylen, #16

0:
    decrypt     0, 16
    decrypt     1, 16
    decrypt     2, 16
    decrypt     3, 16
    decrypt     4, 16
    decrypt     5, 16
    decrypt     6, 16
    decrypt     7, 16
	ldr			q16, [ctx, t]			// expanded key[t]
	subs		t, t, #16
	b.gt		0b

    add         obuf, obuf, #8*16
	decrypt_final 0, 16, 17
	decrypt_final 1, 16, 17
	eor.16b		v0, v0, v31
    ldr         q31, [ibuf, #-1*16]
	decrypt_final 2, 16, 17
	eor.16b		v1, v1, v18
    str         q0, [obuf, #-8*16]
	decrypt_final 3, 16, 17
	eor.16b		v2, v2, v19
    str         q1, [obuf, #-7*16]
	decrypt_final 4, 16, 17
	eor.16b		v3, v3, v20
    str         q2, [obuf, #-6*16]
	decrypt_final 5, 16, 17
	eor.16b		v4, v4, v21
    str         q3, [obuf, #-5*16]
	decrypt_final 6, 16, 17
	eor.16b		v5, v5, v22
    str         q4, [obuf, #-4*16]
	decrypt_final 7, 16, 17

	eor.16b		v6, v6, v23
    str         q5, [obuf, #-3*16]
	eor.16b		v7, v7, v24

    str         q6, [obuf, #-2*16]
    str         q7, [obuf, #-1*16]

	subs		num_blk, num_blk, #8
	b.ge		L8_loop

L_lessthan_8:

	adds		num_blk, num_blk, #4
	b.lt		L_lessthan_4

#else   // CC_IBOOT

	subs		num_blk, num_blk, #4
	b.lt		L_lessthan_4

#endif  // CC_IBOOT

L4_loop:    // per 4 blocks

    ldr         q0, [ibuf], #4*16
    ldr         q1, [ibuf, #-3*16]
    ldr         q2, [ibuf, #-2*16]
    orr.16b     v5, v0, v0
    ldr         q3, [ibuf, #-1*16]
    orr.16b     v6, v1, v1
	ldr			q16, [ctx, keylen]		// expanded key[10]
    orr.16b     v7, v2, v2
	ldr			q17, [ctx]				// expanded key[0]
	sub			t, keylen, #16

0:
    decrypt     0, 16
    decrypt     1, 16
    decrypt     2, 16
    decrypt     3, 16
	ldr			q16, [ctx, t]			// expanded key[t]
	subs		t, t, #16
	b.gt		0b

    add         obuf, obuf, #4*16
	decrypt_final 0, 16, 17
	decrypt_final 1, 16, 17
	eor.16b		v0, v0, v31
    ldr         q31, [ibuf, #-1*16]
	decrypt_final 2, 16, 17
	eor.16b		v1, v1, v5
    str         q0, [obuf, #-4*16]
	decrypt_final 3, 16, 17

	eor.16b		v2, v2, v6
    str         q1, [obuf, #-3*16]
	eor.16b		v3, v3, v7
    str         q2, [obuf, #-2*16]
    str         q3, [obuf, #-1*16]

	subs		num_blk, num_blk, #4
	b.ge		L4_loop

L_lessthan_4:

	adds		num_blk, num_blk, #4
	b.le		L_done

L_scalar:

	ldr			q16, [ctx, keylen]		// expanded key[10]
	sub			t, keylen, #16

	ldr			q0, [ibuf], #16			// state = in
	ldr			q17, [ctx]				// expanded key[0]

0:
    decrypt     0, 16
	ldr			q16, [ctx, t]			// expanded key[t]
	subs		t, t, #16
	b.gt		0b

   
    decrypt_final   0, 16, 17 

	eor.16b		v0, v0, v31
	ldr			q31, [ibuf, #-16]

	str			q0, [obuf], #16
	subs		num_blk, num_blk, #1
	b.gt		L_scalar

L_done:
	mov			x0, #0
	str			q31, [iq]

#if CC_KERNEL
    // restore used vector registers
    ld1.4s      {v0,v1,v2,v3}, [sp], #4*16
    ld1.4s      {v4,v5,v6,v7}, [sp], #4*16
    ld1.4s      {v16,v17,v18,v19}, [sp], #4*16
    ld1.4s      {v20,v21,v22,v23}, [sp], #4*16
    ld1.4s      {v24,v25,v26,v27}, [sp], #4*16
    ld1.4s      {v28,v29,v30,v31}, [sp], #4*16
#endif
    ld1.4s      {v8,v9,v10,v11}, [sp], #4*16
    ld1.4s      {v12,v13,v14,v15}, [sp], #4*16
	ret			lr

#else
	#define	Select	1		// Select=1 to define aes_decrypt_cbc from aes_cbc.s
	#include "aes_cbc.s"
	#undef	Select
#endif


