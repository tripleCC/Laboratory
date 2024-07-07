# Copyright (c) (2011-2013,2015,2016,2018-2020,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

/*

    This is for Chinook AOP (arm64) that does not support crypto instructions.

	This file provides arm64 neon hand implementation of the following function

	void SHA256_Transform(SHA256_ctx *ctx, char *data, unsigned int num_blocks);

	which is a C function in sha2.c (from xnu).

	sha256 algorithm per block description:

		1. W(0:15) = big-endian (per 4 bytes) loading of input data (64 byte) 
		2. load 8 digests a-h from ctx->state
		3. for r = 0:15
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g
		4. for r = 16:63
				W[r] = W[r-16] + sigma1(W[r-2]) + W[r-7] + sigma0(W[r-15]);
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g
				
	In the assembly implementation:	
		- a circular window of message schedule W(r:r+15) is updated and stored in q0-q3
		- its corresponding W+K(r:r+15) is updated and stored in a stack space circular buffer
		- the 8 digests (a-h) will be stored in GPR or memory

	the implementation per block looks like

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 4 bytes) into q0:q3
	pre_calculate and store W+K(0:15) in stack

	load digests a-h from ctx->state;

	for (r=0;r<48;r+=4) {
		digests a-h update and permute round r:r+3
		update W([r:r+3]%16) and WK([r:r+3]%16) for the next 4th iteration 
	}

	for (r=48;r<64;r+=4) {
		digests a-h update and permute round r:r+3
	}

	ctx->states += digests a-h;

	----------------------------------------------------------------------------

	our implementation (allows multiple blocks per call) pipelines the loading of W/WK of a future block 
	into the last 16 rounds of its previous block:

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 4 bytes) into q0:q3 
	pre_calculate and store W+K(0:15) in stack

L_loop:

	load digests a-h from ctx->state;

	for (r=0;r<48;r+=4) {
		digests a-h update and permute round r:r+3
		update W([r:r+3]%16) and WK([r:r+3]%16) for the next 4th iteration 
	}

	num_block--;
	if (num_block==0)	jmp L_last_block;

	for (r=48;r<64;r+=4) {
		digests a-h update and permute round r:r+3
		load W([r:r+3]%16) (big-endian per 4 bytes) into q0:q3 
		pre_calculate and store W+K([r:r+3]%16) in stack
	}

	ctx->states += digests a-h;

	jmp	L_loop;

L_last_block:

	for (r=48;r<64;r+=4) {
		digests a-h update and permute round r:r+3
	}

	ctx->states += digests a-h;

	------------------------------------------------------------------------

	Apple CoreOS vector & numerics
*/


	// associate variables with registers or memory

    #define ctx         x0
    #define num_blocks  x1
    #define data        x2
    #define ktable      x3

	#define	_i_loop	    x4

	#define	a			w5
	#define	bb			w6
	#define	c			w7
	#define	d			w8
	#define	e			w9
	#define	f			w10
	#define	g			w11
	#define	h			w12

	// 2 local variables
	#define	t	w13
	#define	s	w14

	// a window (16 words) of message scheule
	#define	W0	v0
	#define	W1	v1
	#define	W2	v2
	#define	W3	v3
	#define	qW0	q0
	#define	qW1	q1
	#define	qW2	q2
	#define	qW3	q3
	#define	zero	v16
	#define	WK0	v4
	#define	WK1	v5
	#define	WK2	v6
	#define	WK3	v7
	#define	qWK0	q4
	#define	qWK1	q5
	#define	qWK2	q6
	#define	qWK3	q7

	// circular buffer for WK[(r:r+15)%16]
	#define WK(r)   [sp,#((r)&15)*4]

// #define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))

	.macro Ch
	mvn		t, $0		// ~x
	and		s, $0, $1	// (x) & (y)
	and		t, t, $2	// (~(x)) & (z)
	eor		t, t, s		// t = Ch(x,y,z) = (((x) & (y)) ^ ((~(x)) & (z)))
	.endm

// #define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

	.macro	Maj
	eor		t, $1, $2		// y^z
	and		s, $1, $2		// y&z
	and		t, t, $0		// x&(y^z)
	eor		t, t, s			// t = Maj(x,y,z) = (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) 
	.endm

// #define sigma0_256(x)   (S32(7,  (x)) ^ S32(18, (x)) ^ R(3 ,   (x)))

	// performs sigma0_256 on 4 words on a Q register
	// use q6/q7 as intermediate registers
	.macro	sigma0
	vshr.u32	q6, $0, #7
	vshl.i32	q7, $0, #14
	vshr.u32	$0, $0, #3
	veor		$0, q6
	veor		$0, q7
	vshr.u32	q6, #11
	vshl.i32	q7, #11
	veor		$0, q6
	veor		$0, q7
	.endm

// #define sigma1_256(x)   (S32(17, (x)) ^ S32(19, (x)) ^ R(10,   (x)))

	// performs sigma1_256 on 4 words on a Q register
	// use q6/q7 as intermediate registers
	.macro	sigma1
	vshr.u32	q6, $0, #17
	vshl.i32	q7, $0, #13
	vshr.u32	$0, $0, #10
	veor		$0, q6
	veor		$0, q7
	vshr.u32	q6, #2
	vshl.i32	q7, #2
	veor		$0, q6
	veor		$0, q7
	.endm

// #define Sigma0_256(x)   (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))

	.macro	Sigma0
	ror		t, $0, #2		// S32(2,  (x))
	ror		s, $0, #13		// S32(13,  (x))
	eor		t, t, s			// S32(2,  (x)) ^ S32(13, (x))
	ror		s, s, #9		// S32(22,  (x))
	eor		t, t, s			// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))
	.endm

// #define Sigma1_256(x)   (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))

	.macro	Sigma1
	ror		t, $0, #6		// S32(6,  (x))
	ror		s, $0, #11		// S32(11, (x))
	eor		t, t, s			// S32(6,  (x)) ^ S32(11, (x))
	ror		s, s, #14		// S32(25, (x))	
	eor		t, t, s			// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	.endm

	// per round digests update
	.macro	round
	// ror		t, $4, #6			// S32(6,  (x))
	eor		t, t, $4, ror #11	// S32(6,  (x)) ^ S32(11, (x))
	eor		t, t, $4, ror #25	// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	and		s, $4, $5			// (x) & (y)
	add		$7, $7, t			// use h to store h+Sigma1(e)
	bic		t, $6, $4			// (~(x)) & (z)
	eor		t, t, s				// t = Ch(x,y,z) = (((x) & (y)) ^ ((~(x)) & (z)))
	mov		s, $8   			//
	add		$7, $7, t			// t = h+Sigma1(e)+Ch(e,f,g);
	ror		t, $0, #2			// S32(2,  (x))
	add		$7, $7, s			// h = T1
	eor		t, t, $0, ror #13	// S32(2,  (x)) ^ S32(13, (x))
	add		$3, $3, $7			// d += T1;
	eor		t, t, $0, ror #22	// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))				// t = Sigma0(a);
	add		$7, $7, t			// h = T1 + Sigma0(a);
	eor		t, $1, $2			// y^z
	and		s, $1, $2			// y&z
	and		t, t, $0			// x&(y^z)
	eor		s, s, t				// t = Maj(x,y,z) = (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
	// add		$7, s				// h = T1 + Sigma0(a) + Maj(a,b,c);			
	.endm

	// per 4 rounds digests update and permutation
	// permutation is absorbed by rotating the roles of digests a-h
	.macro	rounds
	ror		t, $4, #6
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
	ror		t, $3, #6
	add		$7, s
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8
	ror		t, $2, #6
	add		$6, s
	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
	ror		t, $1, #6
	add		$5, s
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8
	add		$4, s
	.endm

	.macro	rounds_a
	ror		t, e, #6
	round	a, bb, c, d, e, f, g, h, $0.s[0]
	ror		t, d, #6
	add		h, h, s
	round	h, a, bb, c, d, e, f, g, $0.s[1]
	ror		t, c, #6
	add		g, g, s
	round	g, h, a, bb, c, d, e, f, $0.s[2]
	ror		t, bb, #6
	add		f, f, s
	round	f, g, h, a, bb, c, d, e, $0.s[3]
	add		e, e, s
	.endm

	.macro	rounds_e
	ror		t, a, #6
	round	e, f, g, h, a, bb, c, d, $0.s[0]
	ror		t, h, #6
	add		d, d, s
	round	d, e, f, g, h, a, bb, c, $0.s[1]
	ror		t, g, #6
	add		c, c, s
	round	c, d, e, f, g, h, a, bb, $0.s[2]
	ror		t, f, #6
	add		bb, bb, s
	round	bb, c, d, e, f, g, h, a, $0.s[3]
	add		a, a, s
	.endm

	.macro	rounds_a_update_W_WK
	ror		t, e, #6
	ldr	$3, [data], #16
	round	a, bb, c, d, e, f, g, h, $0.s[0]
	ror		t, d, #6
	rev32.16b	$1, $1
	add		h, h, s
	round	h, a, bb, c, d, e, f, g, $0.s[1]
	ror		t, c, #6
	add		g, g, s
	ldr	    q17, [ktable], #16
	round	g, h, a, bb, c, d, e, f, $0.s[2]
	ror		t, bb, #6
	add		f, f, s
	round	f, g, h, a, bb, c, d, e, $0.s[3]
	add		e, e, s
	add.4s	$0, v17, $1
	.endm

	.macro	rounds_e_update_W_WK
	ror		t, a, #6
	ldr	    $3, [data], #16
	round	e, f, g, h, a, bb, c, d, $0.s[0]
	ror		t, h, #6
	rev32.16b	$1, $1
	add		d, d, s
	round	d, e, f, g, h, a, bb, c, $0.s[1]
	ror		t, g, #6
	add		c, c, s
	ldr	    q17, [ktable], #16
	round	c, d, e, f, g, h, a, bb, $0.s[2]
	ror		t, f, #6
	add		bb, bb, s
	round	bb, c, d, e, f, g, h, a, $0.s[3]
	add		a, a, s
	add.4s	$0, v17, $1
	.endm

	// this macro is used in the last 16 rounds of a current block
	// it reads the next message (16 4-byte words), load it into 4 words W[r:r+3], computes WK[r:r+3]
	// and save into stack to prepare for next block

	.macro	update_W_WK
	ldr	$3, [data]
	ldr	$2, [ktable]
    add     data, data, #16
	rev32.16b	$1, $1
    add     ktable, ktable, #16
	add.4s	$0, $0, $1
	.endm

	.macro	Update_Digits
	ldp		t, s, [ctx]
	add		a, a, t
	add		bb, bb, s
	stp	    a, bb, [ctx]

	ldp		t, s, [ctx,#8]
	add		c, c, t
	add		d, d, s
	stp	    c, d, [ctx, #8]

	ldp		t, s, [ctx,#16]
	add		e, e, t
	add		f, f, s
	stp	    e, f, [ctx, #16]

	ldp		t, s, [ctx,#24]
	add		g, g, t
	add		h, h, s
	stp	    g, h, [ctx, #24]
	.endm

	.macro	rounds_a_schedule_update
	eor		t, e, e, ror #5	// S32(6,  (x)) ^ S32(11, (x))
	ldr     q17, [ktable], #16
	eor		t, t, e, ror #19	// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	ext.16b  v18, $1, $2, #4			// w4:w1
    ror     t, t, #6
	and		s, e, f				// (x) & (y)
	add		h, h, t				// use h to store h+Sigma1(e)
	bic		t, g, e				// (~(x)) & (z)
	ushr.4s	v19, v18, #7
	eor		t, t, s				// t = Ch(x,y,z) = (((x) & (y)) ^ ((~(x)) & (z)))
	mov		s, $5.s[0]  		//
	add		h, h, t				// t = h+Sigma1(e)+Ch(e,f,g);
	shl.4s	v20, v18, #14
	eor		t, a, a, ror #11	// S32(2,  (x)) ^ S32(13, (x))
	ushr.4s v18, v18, #3
	add		h, h, s				// h = T1
	eor		t, t, a, ror #20	// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))				// t = Sigma0(a);
	add		d, d, h				// d += T1;
    ror     t, t, #2
	eor.16b		v18, v18, v19
	add		h, h, t				// h = T1 + Sigma0(a);
	ushr.4s	v19, v19, #11
	eor		t, bb, c			// y^z
	and		s, bb, c			// y&z
	and		t, t, a			// x&(y^z)
	eor.16b		v18, v18, v20
	eor		s, s, t				// t = Maj(x,y,z) = (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
	shl.4s	v20, v20, #11
	eor		t, d, d, ror #5	// S32(6,  (x)) ^ S32(11, (x))

	add		h, h, s
	eor		t, t, d, ror #19	// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	eor.16b		v18, v18, v19
	and		s, d, e				// (x) & (y)
	ext.16b	v19, $3, $4, #4			// q19 = w12:w9
    ror     t, t, #6
	add		g, g, t				// use h to store h+Sigma1(e)
	eor.16b		v18, v18, v20
	bic		t, f, d				// (~(x)) & (z)

	eor		t, t, s				// t = Ch(x,y,z) = (((x) & (y)) ^ ((~(x)) & (z)))
	mov		s, $5.s[1]  		//
	add		g, g, t				// t = h+Sigma1(e)+Ch(e,f,g);
	eor		t, h, h, ror #11	// S32(2,  (x)) ^ S32(13, (x))
	add.4s	$1, $1, v18				// w3:w0 + sigma0(w4:w1)
	add		g, g, s				// h = T1
	ext.16b	v18, $4, zero, #8		// 0 0 w15:w14
	eor		t, t, h, ror #20	// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))				// t = Sigma0(a);
	add.4s	$1, $1, v19				// w3:w0 + sigma0(w4:w1) + w12:w9
    ror     t, t, #2
	add		c, c, g				// d += T1;
	ushr.4s	v19, v18, #17
	add		g, g, t			// h = T1 + Sigma0(a);
	shl.4s	v20, v18, #13
	eor		t, a, bb				// y^z
	ushr.4s	v18, v18, #10
	and		s, a, bb				// y&z
	and		t, t, h				// x&(y^z)
	eor.16b		v18, v18, v19
	eor		s, s, t				// t = Maj(x,y,z) = (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
	ushr.4s	    v19, v19, #2



	eor		t, c, c, ror #5	// S32(6,  (x)) ^ S32(11, (x))
	add		g, g, s
	eor.16b		v18, v18, v20
	eor		t, t, c, ror #19	// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	shl.4s	    v20, v20, #2
    ror     t, t, #6
	and		s, c, d				// (x) & (y)
	eor.16b		v18, v18, v19
	add		f, f, t				// use h to store h+Sigma1(e)
	eor.16b		v18, v18, v20
	bic		t, e, c				// (~(x)) & (z)
	add.4s	$1, $1, v18				// w3:w0 + sigma0(w4:w1) + w12:w9 + sigma1(0 0 w15:w14)
	eor		t, t, s				// t = Ch(x,y,z) = (((x) & (y)) ^ ((~(x)) & (z)))
	mov		s, $5.s[2]  		//
	add		f, f, t				// t = h+Sigma1(e)+Ch(e,f,g);
	ext.16b	v18, zero, $1, #8		// Q4 = (w17:w16 0 0)
	eor		t, g, g, ror #11	// S32(2,  (x)) ^ S32(13, (x))
	add		f, f, s				// h = T1
	eor		t, t, g, ror #20	// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))				// t = Sigma0(a);
	ushr.4s	v19, v18, #17
	add		bb, bb, f				// d += T1;
	shl.4s	v20, v18, #13
    ror     t, t, #2 
	ushr.4s	v18, v18, #10
	add		f, f, t 			// h = T1 + Sigma0(a);
	eor		t, h, a				// y^z
	and		s, h, a				// y&z
	eor.16b		v18, v18, v19
	and		t, t, g				// x&(y^z)
	eor		s, s, t				// t = Maj(x,y,z) = (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

	eor		t, bb, bb, ror #5	// S32(6,  (x)) ^ S32(11, (x))
	add		f, f, s
	eor.16b		v18, v18, v20
	eor		t, t, bb, ror #19	// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	ushr.4s	v19, v19, #2
    ror     t, t, #6
	shl.4s	v20, v20, #2

	and		s, bb, c			// (x) & (y)
	eor.16b		v18, v18, v19
	add		e, e, t     		// use h to store h+Sigma1(e)
	bic		t, d, bb			// (~(x)) & (z)
	eor		t, t, s				// t = Ch(x,y,z) = (((x) & (y)) ^ ((~(x)) & (z)))
	mov		s, $5.s[3]  		//
	add		e, e, t				// t = h+Sigma1(e)+Ch(e,f,g);
	eor.16b		v18, v18, v20
	eor		t, f, f, ror #11	// S32(2,  (x)) ^ S32(13, (x))
	add		e, e, s				// h = T1
	eor		t, t, f, ror #20	// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))				// t = Sigma0(a);
	add		a, a, e				// d += T1;
    ror     t, t, #2
	add.4s	$1, $1, v18	    	// w19:w16 = w3:w0 + sigma0(w4:w1) + w12:w9 + sigma1(w17:w14)
	add		e, e, t				// h = T1 + Sigma0(a);
	eor		t, g, h				// y^z
	and		s, g, h				// y&z
	add.4s	$5, v17, $1			// W+K
	and		t, t, f				// x&(y^z)
	eor		s, s, t				// t = Maj(x,y,z) = (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
	add		e, e, s

	.endm

	.macro	rounds_e_schedule_update
	eor		t, a, a, ror #5			// S32(6,  (x)) ^ S32(11, (x))
	ldr     q17, [ktable], #16      // K
	eor		t, t, a, ror #19	// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	ext.16b v18, $1, $2, #4			// Q18 = w4:w1
    ror     t, t, #6
	and		s, a, bb				// (x) & (y)
	add		d, d, t				// use h to store h+Sigma1(e)
	bic		t, c, a				// (~(x)) & (z)
	ushr.4s	v19, v18, #7
	eor		t, t, s				// t = Ch(x,y,z) = (((x) & (y)) ^ ((~(x)) & (z)))
    mov     s, $5.s[0]
	add		d, d, t				// t = h+Sigma1(e)+Ch(e,f,g);
	shl.4s	v20, v18, #14
	eor		t, e, e, ror #11	// S32(2,  (x)) ^ S32(13, (x))
	ushr.4s	v18, v18, #3
	add		d, d, s				// h = T1
	eor		t, t, e, ror #20	// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))				// t = Sigma0(a);
	add		h, h, d				// d += T1;
    ror     t, t, #2
	eor.16b	v18, v18, v19
	add		d, d, t				// h = T1 + Sigma0(a);
	ushr.4s	v19, v19, #11
	eor		t, f, g				// y^z
	and		s, f, g				// y&z
	and		t, t, e				// x&(y^z)
	eor.16b		v18, v18, v20
	eor		s, s, t				// t = Maj(x,y,z) = (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
	shl.4s	v20, v20, #11
	eor		t, h, h, ror #5	// S32(6,  (x)) ^ S32(11, (x))


	add		d, d, s
	eor		t, t, h, ror #19	// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	eor.16b	v18, v18, v19
	and		s, h, a				// (x) & (y)
	ext.16b v19, $3, $4, #4			// q19 = w12:w9
    ror     t, t, #6
	add		c, c, t			// use h to store h+Sigma1(e)
	eor.16b	v18, v18, v20
	bic		t, bb, h				// (~(x)) & (z)

	eor		t, t, s				// t = Ch(x,y,z) = (((x) & (y)) ^ ((~(x)) & (z)))
    mov     s, $5.s[1]
	add		c, c, t				// t = h+Sigma1(e)+Ch(e,f,g);
	eor		t, d, d, ror #11	// S32(2,  (x)) ^ S32(13, (x))
	add.4s	$1, $1, v18				// w3:w0 + sigma0(w4:w1)
	add		c, c, s				// h = T1
	ext.16b v18, $4, zero, #8		// 0 0 w15:w14
	eor		t, t, d, ror #20	// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))				// t = Sigma0(a);
	add.4s	$1, $1, v19				// w3:w0 + sigma0(w4:w1) + w12:w9
    ror     t, t, #2
	add		g, g, c				// d += T1;
	ushr.4s	v19, v18, #17
	add		c, c, t 			// h = T1 + Sigma0(a);
	shl.4s	v20, v18, #13
	eor		t, e, f				// y^z
	ushr.4s v18, v18, #10
	and		s, e, f				// y&z
	and		t, t, d				// x&(y^z)
	eor.16b	v18, v18, v19
	eor		s, s, t				// t = Maj(x,y,z) = (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
	ushr.4s	v19, v19, #2


	eor		t, g, g, ror #5		// S32(6,  (x)) ^ S32(11, (x))
	add		c, c, s
	eor.16b	v18, v18, v20
	eor		t, t, g, ror #19	// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	shl.4s	v20, v20, #2
    ror     t, t, #6
	and		s, g, h				// (x) & (y)
	eor.16b	v18, v18, v19
	add		bb, bb, t 			// use h to store h+Sigma1(e)
	eor.16b	v18, v18, v20
	bic		t, a, g				// (~(x)) & (z)
	add.4s	$1, $1, v18				// w3:w0 + sigma0(w4:w1) + w12:w9 + sigma1(0 0 w15:w14)
	eor		t, t, s				// t = Ch(x,y,z) = (((x) & (y)) ^ ((~(x)) & (z)))
    mov     s, $5.s[2]
	add		bb, bb, t				// t = h+Sigma1(e)+Ch(e,f,g);
	ext.16b	v18, zero, $1, #8		// Q18 = (w17:w16 0 0)
	eor		t, c, c, ror #11	// S32(2,  (x)) ^ S32(13, (x))
	add		bb, bb, s				// h = T1
	eor		t, t, c, ror #20	// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))				// t = Sigma0(a);
	ushr.4s	v19, v18, #17
	add		f, f, bb				// d += T1;
	shl.4s	v20, v18, #13
    ror     t, t, #2
	ushr.4s	v18, v18, #10
	add		bb, bb, t 			// h = T1 + Sigma0(a);
	eor		t, d, e				// y^z
	and		s, d, e				// y&z
	eor.16b	v18, v18, v19
	and		t, t, c				// x&(y^z)
	eor		s, s, t				// t = Maj(x,y,z) = (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

	eor		t, f, f, ror #5	// S32(6,  (x)) ^ S32(11, (x))
	add		bb, bb, s
	eor.16b	v18, v18, v20
	eor		t, t, f, ror #19	// t = (S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
	ushr.4s	v19, v19, #2
    ror     t, t, #6
	shl.4s	    v20, v20, #2

	and		s, f, g				// (x) & (y)
	add		a, a, t         	// use h to store h+Sigma1(e)
	eor.16b	v18, v18, v19
	bic		t, h, f				// (~(x)) & (z)
	eor		t, t, s				// t = Ch(x,y,z) = (((x) & (y)) ^ ((~(x)) & (z)))
    mov     s, $5.s[3]
	add		a, a, t				// t = h+Sigma1(e)+Ch(e,f,g);
	eor.16b	v18, v18, v20
	eor		t, bb, bb, ror #11	// S32(2,  (x)) ^ S32(13, (x))
	add		a, a, s				// h = T1
	eor		t, t, bb, ror #20	// t = (S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))				// t = Sigma0(a);
    ror     t, t, #2
	add.4s	$1, $1, v18				// w19:w16 = w3:w0 + sigma0(w4:w1) + w12:w9 + sigma1(w17:w14)
	add		e, e, a				// d += T1;
	add		a, a, t				// h = T1 + Sigma0(a);
	eor		t, c, d				// y^z
	and		s, c, d				// y&z
	add.4s	$5, v17, $1			// W+K
	and		t, t, bb				// x&(y^z)
	eor		s, s, t				// t = Maj(x,y,z) = (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
	add		a, a, s
	.endm


#if defined(__arm64__) && defined(__ARM_NEON)
#include "ccarm_pac_bti_macros.h"

.subsections_via_symbols
	.text
	.p2align	4

K256:
	.long 	0x428a2f98
	.long 	0x71374491
	.long	0xb5c0fbcf
	.long	0xe9b5dba5
	.long	0x3956c25b
	.long	0x59f111f1
	.long	0x923f82a4
	.long	0xab1c5ed5
    .long	0xd807aa98
	.long	0x12835b01
	.long	0x243185be 
	.long	0x550c7dc3
    .long	0x72be5d74 
	.long	0x80deb1fe 
	.long	0x9bdc06a7 
	.long	0xc19bf174
    .long	0xe49b69c1 
	.long	0xefbe4786 
	.long	0x0fc19dc6 
	.long	0x240ca1cc
    .long	0x2de92c6f 
	.long	0x4a7484aa 
	.long	0x5cb0a9dc 
	.long	0x76f988da
    .long	0x983e5152 
	.long	0xa831c66d 
	.long	0xb00327c8 
	.long	0xbf597fc7
    .long	0xc6e00bf3 
	.long	0xd5a79147 
	.long	0x06ca6351 
	.long	0x14292967
    .long	0x27b70a85 
	.long	0x2e1b2138 
	.long	0x4d2c6dfc 
	.long	0x53380d13
    .long	0x650a7354 
	.long	0x766a0abb 
	.long	0x81c2c92e 
	.long	0x92722c85
    .long	0xa2bfe8a1 
	.long	0xa81a664b 
	.long	0xc24b8b70 
	.long	0xc76c51a3
    .long	0xd192e819 
	.long	0xd6990624 
	.long	0xf40e3585 
	.long	0x106aa070
    .long	0x19a4c116 
	.long	0x1e376c08 
	.long	0x2748774c 
	.long	0x34b0bcb5
    .long	0x391c0cb3 
	.long	0x4ed8aa4a 
	.long	0x5b9cca4f 
	.long	0x682e6ff3
    .long	0x748f82ee 
	.long	0x78a5636f 
	.long	0x84c87814 
	.long	0x8cc70208
    .long	0x90befffa
	.long	0xa4506ceb
	.long	0xbef9a3f7
	.long	0xc67178f2


    .p2align  4

    .globl _AccelerateCrypto_SHA256_compress_arm64neon
_AccelerateCrypto_SHA256_compress_arm64neon:
    BRANCH_TARGET_CALL
    adrp    ktable, K256@page
    cbnz    num_blocks, 1f                       // if number of blocks is nonzero, go on for sha256 transform operation
    ret     lr                          // otherwise, return
1:
    add     ktable, ktable, K256@pageoff

#if BUILDKERNEL
    // save q0-q7, q16-q20 8+4+1=13
    sub     x4, sp, #13*16
    sub     sp, sp, #13*16
    st1.4s  {v0, v1, v2, v3}, [x4], #64
    st1.4s  {v4, v5, v6, v7}, [x4], #64
    st1.4s  {v16, v17, v18, v19}, [x4], #64
    st1.4s  {v20}, [x4]
#endif


	// load W[0:15]
    ldr         qW0, [data, #0*16]
	movi.16b    zero, #0
    ldr         qW1, [data, #1*16]
    ldr         qW2, [data, #2*16]
    ldr         qW3, [data, #3*16]
    add         data, data, #4*16

	// load K[0:15] & per word byte swap
    rev32.16b   W0, W0
    ldr         qWK0, [ktable, #0*16]
    rev32.16b   W1, W1
    ldr         qWK1, [ktable, #1*16]
    rev32.16b   W2, W2
    ldr         qWK2, [ktable, #2*16]
    rev32.16b   W3, W3
    ldr         qWK3, [ktable, #3*16]

	// compute WK[0:15]
    add         ktable, ktable, #4*16
	add.4s	WK0, WK0, W0
    ldp     a, bb, [ctx, #0*4]
	add.4s	WK1, WK1, W1
    ldp     c, d, [ctx, #2*4]
	add.4s	WK2, WK2, W2
    ldp     e, f, [ctx, #4*4]
	add.4s	WK3, WK3, W3
    ldp     g, h, [ctx, #6*4]

L_loop:

	// rounds 0:47 interleaved with W/WK update for rounds 16:63
    mov     _i_loop, #3
L_i_loop:
	rounds_a_schedule_update	 0,W0,W1,W2,W3, WK0
	rounds_e_schedule_update	 4,W1,W2,W3,W0, WK1
	rounds_a_schedule_update	 8,W2,W3,W0,W1, WK2
	rounds_e_schedule_update	12,W3,W0,W1,W2, WK3
    subs    _i_loop, _i_loop, #1
    b.gt     L_i_loop

	// revert K to the beginning of K256[]
	subs	num_blocks, num_blocks, #1						// num_blocks--
	sub		ktable, ktable, #256
	b.eq	L_final_block				// if final block, wrap up final rounds

	// rounds 48:63 interleaved with W/WK initialization for next block rounds 0:15 
	rounds_a_update_W_WK	WK0, W0, qWK0, qW0
	rounds_e_update_W_WK	WK1, W1, qWK1, qW1
	rounds_a_update_W_WK	WK2, W2, qWK2, qW2
	rounds_e_update_W_WK	WK3, W3, qWK3, qW3

	// ctx->states += digests a-h, also update digest variables a-h
	Update_Digits

	b.al		L_loop				// branch for next block

	// wrap up digest update round 48:63 for final block
L_final_block:
	rounds_a	WK0
	rounds_e	WK1
	rounds_a	WK2
	rounds_e	WK3

	// ctx->states += digests a-h
	Update_Digits

#if BUILDKERNEL
    // restore q0-q7, q16-q20
    ld1.4s  {v0, v1, v2, v3}, [sp], #64
    ld1.4s  {v4, v5, v6, v7}, [sp], #64
    ld1.4s  {v16, v17, v18, v19}, [sp], #64
    ld1.4s  {v20}, [sp], #16
#endif

    ret     lr

#endif /* arm64 */

