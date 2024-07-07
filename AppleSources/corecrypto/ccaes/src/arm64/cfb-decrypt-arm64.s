# Copyright (c) (2011-2016,2019,2020) Apple Inc. All rights reserved.
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

	#define	ctx		x0
	#define	iv		x1
	#define	num_blk	x2
	#define	ibuf	x3
	#define	obuf	x4
	#define	keylen	x5
	#define	keylenw	w5
	#define	t		x6

	.text
	.align	4
	.globl	_ccaes_cfb_decrypt_vng_vector

_ccaes_cfb_decrypt_vng_vector:
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
	sub		x6, sp, #11*16
    sub     sp, sp, #11*16
    st1.4s      {v0,v1,v2,v3}, [x6], #4*16
    st1.4s      {v4,v5,v6,v7}, [x6], #4*16
    st1.4s      {v16,v17,v18}, [x6], #3*16
#endif


	ldr			q0, [iv]				// a copy of *iv
	subs		num_blk, num_blk, #4
	b.lt		L_lessthan_4


L_loop:			// per 4 blocks


	ld1.4s      {v16}, [ctx], #16
    sub         t, keylen, #16

	ld1.4s		{v1,v2,v3,v4}, [ibuf], #4*16

	orr.16b 	v5, v1, v1
	orr.16b 	v6, v2, v2
	orr.16b 	v7, v3, v3
	orr.16b 	v18, v4, v4

0:
	AESE		0, 16					// 	xor/SubByte/ShiftRows
	AESMC       0, 0					// MixColumns
	AESE		1, 16					// 	xor/SubByte/ShiftRows
	AESMC       1, 1					// MixColumns
	AESE		2, 16					// 	xor/SubByte/ShiftRows
	AESMC       2, 2					// MixColumns
	AESE		3, 16					// 	xor/SubByte/ShiftRows
	AESMC       3, 3					// MixColumns
	ld1.4s      {v16}, [ctx], #16
	subs		t, t, #16
	b.gt		0b

	mov			t, keylen

	ld1.4s      {v17}, [ctx]
    sub         ctx, ctx, keylen

	AESE		0, 16					// 	xor/SubByte/ShiftRows
	eor.16b		v0, v0, v17				// out = state ^ key[0];
	AESE		1, 16					// 	xor/SubByte/ShiftRows
	eor.16b		v1, v1, v17				// out = state ^ key[0];
	AESE		2, 16					// 	xor/SubByte/ShiftRows
	eor.16b		v2, v2, v17				// out = state ^ key[0];
	AESE		3, 16					// 	xor/SubByte/ShiftRows
	eor.16b		v3, v3, v17				// out = state ^ key[0];

	eor.16b		v0, v0, v5
	eor.16b		v1, v1, v6
	eor.16b		v2, v2, v7
	eor.16b		v3, v3, v18

	st1.4s		{v0,v1,v2,v3}, [obuf], #4*16
	orr.16b		v0, v4, v4
	subs		num_blk, num_blk, #4
	b.ge		L_loop

L_lessthan_4:

	adds		num_blk, num_blk, #4
	b.le		L_done

L_scalar:

	ld1.4s      {v16}, [ctx], #16
    sub         t, keylen, #16

	ldr			q4, [ibuf], #16			// state = in

0:
	AESE		0, 16					// 	xor/SubByte/ShiftRows
	AESMC 		0, 0					// MixColumns
	ld1.4s      {v16}, [ctx], #16
	subs		t, t, #16
	b.gt		0b

	ldr			q17, [ctx]				// expanded key[0]
    sub         ctx, ctx, keylen
	AESE		0, 16					// 	xor/SubByte/ShiftRows
	eor.16b		v0, v0, v17				// out = state ^ key[0];

	eor.16b		v0, v0, v4
	str			q0, [obuf], #16

	orr.16b		v0, v4, v4
	subs		num_blk, num_blk, #1
	b.gt		L_scalar

L_done:
	mov			x0, #0
	str			q0, [iv]
#if CC_KERNEL
    // restore used vector registers
    ld1.4s      {v0,v1,v2,v3}, [sp], #4*16
    ld1.4s      {v4,v5,v6,v7}, [sp], #4*16
    ld1.4s      {v16,v17,v18}, [sp], #3*16
#endif
	ret			lr


#endif


