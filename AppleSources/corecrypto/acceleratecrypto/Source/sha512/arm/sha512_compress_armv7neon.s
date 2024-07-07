# Copyright (c) (2016,2018,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
/*
	This file provides armv7 neon hand implementation of the following function

    void sha512_compress(uint64_t *state, size_t nblocks, const void *in);

	sha512 algorithm per block description:

		1. W(0:15) = big-endian (per 8 bytes) loading of input data (128 bytes)
		2. load 8 digests (each 64bit) a-h from state
		3. for r = 0:15
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g
		4. for r = 16:79
				W[r] = W[r-16] + Gamma1(W[r-2]) + W[r-7] + Gamma0(W[r-15]);
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g

	In the assembly implementation:
		- a circular window of message schedule W(r:r+15) is updated and stored in v0-v7
		- its corresponding W+K(r:r+15) is updated and stored in a stack space circular buffer
		- the 8 digests (a-h) will be stored in GPR (%r8-%r15) 

	----------------------------------------------------------------------------

	our implementation (allows multiple blocks per call) pipelines the loading of W/WK of a future block
	into the last 16 rounds of its previous block:

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 8 bytes) into v0:v7
	pre_calculate and store W+K(0:15) in stack

L_loop:

	load digests a-h from ctx->state;

	for (r=0;r<64;r+=2) {
		digests a-h update and permute round r:r+1
		update W([r:r+1]%16) and WK([r:r+1]%16) for the next 8th iteration
	}

	num_block--;
	if (num_block==0)	jmp L_last_block;

	for (r=64;r<80;r+=2) {
		digests a-h update and permute round r:r+1
		load W([r:r+1]%16) (big-endian per 8 bytes) into v0:v7
		pre_calculate and store W+K([r:r+1]%16) in stack
	}

	ctx->states += digests a-h;

	jmp	L_loop;

L_last_block:

	for (r=64;r<80;r+=2) {
		digests a-h update and permute round r:r+2
	}

	ctx->states += digests a-h;

	------------------------------------------------------------------------

	Apple CoreOS vector & numerics
*/

#if (defined(__arm__) && defined(__ARM_NEON__))

	// associate variables with registers or memory

    #define stack_size     (16*8) 

	#define	ctx			r0
	#define num_blocks	r1
	#define	data        r2

    /* use d0-d7 (q0-q3) for 8 digests */
	#define	a			d0
	#define	b			d1
	#define	c			d2
	#define	d			d3
	#define	e			d4
	#define	f			d5
	#define	g			d6
	#define	h			d7

	#define	K			r3

	// 3 local variables
	#define	s	d8
	#define	t	d9
	#define	u	d10

	// a window (16 quad-words) of message scheule
	#define	W0	q8
	#define	W1	q9
	#define	W2	q10
	#define	W3	q11
	#define	W4	q12
	#define	W5	q13
	#define	W6	q14
	#define	W7	q15

	// circular buffer for WK[(r:r+15)%16]
	#define WK(x)   [sp,#((x)&15)*8]

// #define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))

    /* t = Ch($0, $1, $2) */
	.macro Ch
    veor     t, $1, $2  
    vand     t, t, $0
    veor     t, t, $2
	.endm

// #define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

    
    /* t = Maj($0, $1, $2) */
	.macro	Maj
	veor    t, $1, $2  // y^z
	vand	s, $1,$2   // y&z
	vand	t, t, $0   // x&(y^z)
	veor	t, t, s    // Maj(x,y,z)
	.endm

// #define Gamma0(x)   (S64(1,  (x)) ^ S64(8, (x)) ^ R(7 ,   (x)))

	// performs Gamma0_512 on 2 words on an vector registers
	// use q6/q7 as intermediate registers
	.macro	Gamma0
    vshr.u64 q6, $0, #1         // part of S64(1, x)
    vshl.i64 q7, $0, #56        // part of S64(8, x)
    vshr.u64 $0, $0, #7         // R(7, x)
    veor     $0, $0, q6
    vshr.u64 q6, q6, #7         // part of S64(8, x)
    veor     $0, $0, q7
    vshl.i64 q7, q7, #7         // part of S64(1, x)
    veor     $0, $0, q6
    veor     $0, $0, q7
	.endm

// #define Gamma1(x)   (S64(19, (x)) ^ S64(61, (x)) ^ R(6,   (x)))

	// performs Gamma1_512 on 2 words on an vector registers
	// use v16/v17 as intermediate registers
	.macro	Gamma1
    vshr.u64 q6, $0, #19        // part of S64(19, x)
    vshl.i64 q7, $0, #3         // part of S64(61, x)
    vshr.u64 $0, $0, #6         // R(6, x)
    veor     $0, $0, q6
    vshr.u64 q6, q6, #42        // part of S64(61, x)
    veor     $0, $0, q7
    vshl.i64 q7, q7, #42        // part of S64(19, x)
    veor     $0, $0, q6
    veor     $0, $0, q7
	.endm

    // W[r] = W[r-16] + Gamma1(W[r-2]) + W[r-7] + Gamma0(W[r-15]);
    /*
        W0 W1 W2 W3 W4 W5 W6 W7
        
        update 2 quad words in W0 = W0 + Gamma1(W7) + vext(W4,W5) + Gamma0(vext(W0,W1)). 
        use q5-q7 for temp
    */
    .macro  message_update2
    vext.64     q7, $4, $5, #1      // W[r-7]
    vext.64     q5, $0, $1, #1      // W[r-15]
    vadd.s64    $0, $0, q7          // W[r-16] + W[r-7];
    Gamma0      q5
    vadd.s64    $0, $0, q5          // W[r-16] + W[r-7] + Gamma0(W[r-15]) 
    vshr.u64    q6, $7, #19         // Gamma1(W[r-2]), part of S64(19, x)
    vshl.i64    q7, $7, #3          // part of S64(61, x)
    vshr.u64    q5, $7, #6         // R(6, x)
    veor        q5, q5, q6
    vshr.u64    q6, q6, #42        // part of S64(61, x)
    veor        q5, q5, q7
    vshl.i64    q7, q7, #42        // part of S64(19, x)
    veor        q5, q5, q6
    veor        q5, q5, q7
    vadd.s64    $0, $0, q5         // W[r-16] + W[r-7] + Gamma1(W7) 
    .endm 

// #define Sigma0(x)   (S64(28,  (x)) ^ S64(34, (x)) ^ S64(39, (x)))

	.macro	Sigma0
    vshr.u64    t, $0, #28 
    vshl.i64    s, $0, #25 
    vshr.u64    u, t, #6 
    veor        t, t, s
    vshl.i64    s, s, #5 
    veor        t, t, u
    vshr.u64    u, u, #5
    veor        t, t, s
    vshl.i64    s, s, #6 
    veor        t, t, u
    veor        t, t, s
	.endm

// #define Sigma1(x)   (S(14,  (x)) ^ S(18, (x)) ^ S(41, (x)))

	.macro	Sigma1
    vshr.u64    t, $0, #14
    vshl.i64    s, $0, #23 
    vshr.u64    u, t, #4
    veor        t, t, s
    vshl.i64    s, s, #23
    veor        t, t, u
    vshr.u64    u, u, #23
    veor        t, t, s
    vshl.i64    s, s, #4
    veor        t, t, u
    veor        t, t, s
	.endm

	// per round digests update
	.macro	round_ref
	Sigma1	$4				// t = Sigma1(e);
	vadd.s64 $7, $7, t		// h = h+Sigma1(e)
	Ch		$4, $5, $6		// t = Ch (e, f, g);
    vldr    s, WK($8)       // s = WK
	vadd.s64	$7, $7, t		// h = h+Sigma1(e)+Ch(e,f,g);
	vadd.s64	$7, $7, s		// h = h+Sigma1(e)+Ch(e,f,g)+WK
	vadd.s64	$3, $3, $7		// d += h;
	Sigma0	$0				// t = Sigma0(a);
	vadd.s64	$7, $7, t		// h += Sigma0(a);
	Maj		$0, $1, $2		// t = Maj(a,b,c)
	vadd.s64	$7, $7, t		// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

	.macro	round
	Sigma1	$4				// t = Sigma1(e);
    vldr    s, WK($8)       // s = WK
	vadd.s64 $7, $7, t		// h = h+Sigma1(e)
    veor     t, $5, $6  
	vadd.s64	$7, $7, s	// h = h+Sigma1(e)+WK
    vand     t, t, $4
    veor     t, t, $6       // t = Ch (e, f, g);
	vadd.s64	$7, $7, t		// h = h+Sigma1(e)+Ch(e,f,g);
	Sigma0	$0				// t = Sigma0(a);
	vadd.s64	$3, $3, $7		// d += h;
	vadd.s64	$7, $7, t		// h += Sigma0(a);
	Maj		$0, $1, $2		// t = Maj(a,b,c)
	vadd.s64	$7, $7, t		// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

    /*
        16 rounds of hash update, update input schedule W (in vector register v0-v7) and WK = W + K (in stack)
    */
	.macro	rounds_schedule
    mov     r12, sp

    message_update2 W0, W1, W2, W3, W4, W5, W6, W7
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W0
    vst1.64 {q7}, [r12]!

    message_update2 W1, W2, W3, W4, W5, W6, W7, W0
	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W1
    vst1.64 {q7}, [r12]!


    message_update2 W2, W3, W4, W5, W6, W7, W0, W1
	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W2
    vst1.64 {q7}, [r12]!

    message_update2 W3, W4, W5, W6, W7, W0, W1, W2
	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W3
    vst1.64 {q7}, [r12]!

    message_update2 W4, W5, W6, W7, W0, W1, W2, W3
	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W4
    vst1.64 {q7}, [r12]!

    message_update2 W5, W6, W7, W0, W1, W2, W3, W4
	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W5
    vst1.64 {q7}, [r12]!

    message_update2 W6, W7, W0, W1, W2, W3, W4, W5
	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W6
    vst1.64 {q7}, [r12]!

    message_update2 W7, W0, W1, W2, W3, W4, W5, W6
	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8

    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W7
    vst1.64 {q7}, [r12]!

	.endm

    .macro  rev64
    vrev64.8    $0, $0
    .endm
    /*
        16 rounds of hash update, load new input schedule W (in vector register v0-v7) and update WK = W + K (in stack)
    */
	.macro	rounds_schedule_initial
    mov     r12, sp
    vld1.8 {W0}, [data]!
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
    rev64   W0
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W0
    vst1.64 {q7}, [r12]!
    
    vld1.8 {W1}, [data]!
	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
    rev64   W1
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W1
    vst1.64 {q7}, [r12]!

    vld1.8 {W2}, [data]!
	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
    rev64   W2
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W2
    vst1.64 {q7}, [r12]!

    vld1.8 {W3}, [data]!
	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
    rev64   W3
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W3
    vst1.64 {q7}, [r12]!

    vld1.8 {W4}, [data]!
	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
    rev64   W4
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W4
    vst1.64 {q7}, [r12]!

    vld1.8 {W5}, [data]!
	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
    rev64   W5
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W5
    vst1.64 {q7}, [r12]!

    vld1.8 {W6}, [data]!
	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
    rev64   W6
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W6
    vst1.64 {q7}, [r12]!

    vld1.8 {W7}, [data]!
	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
    rev64   W7
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
    vld1.64 {q7}, [K,:128]!
    vadd.s64 q7, q7, W7
    vst1.64 {q7}, [r12]!

	.endm

    /*
        16 rounds of hash update
    */
	.macro	rounds_schedule_final
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8

	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8

	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8

	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8

	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8

	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8

	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8

	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
	.endm

    .p2align  4
L_table1:
    .long   L_Tab$non_lazy_ptr-(L_table0+8)

    .p2align  4
	.text
    .globl	_AccelerateCrypto_SHA512_compress
_AccelerateCrypto_SHA512_compress:

    // push callee-saved registers
    push    {r4,r5,r7,lr}
    add     r7, sp, #8         // set up dtrace frame pointer

    vpush   {q4-q7}
#if BUILDKERNEL
    vpush   {q0-q3}
    vpush   {q8-q15}
#endif


	// allocate stack space for WK[0:15]
	sub		sp, sp, #stack_size

    ldr     K, L_table1
L_table0:
    mov     r12, pc
    ldr     K, [r12, K]

    vld1.8   {W0,W1}, [data]!
    vld1.8   {W2,W3}, [data]!
    vld1.8   {W4,W5}, [data]!
    vld1.8   {W6,W7}, [data]!

    rev64   W0
    rev64   W1
    rev64   W2
    rev64   W3
    rev64   W4
    rev64   W5
    rev64   W6
    rev64   W7

    mov     r12, sp
	// compute WK[0:15] and save in stack, use q0-q7 as they have not yet being used
    vld1.8   {q0,q1}, [K,:128]!
    vld1.8   {q2,q3}, [K,:128]!
    vld1.8   {q4,q5}, [K,:128]!
    vld1.8   {q6,q7}, [K,:128]!

    vadd.s64 q0, q0, W0
    vadd.s64 q1, q1, W1
    vadd.s64 q2, q2, W2
    vadd.s64 q3, q3, W3
    vadd.s64 q4, q4, W4
    vadd.s64 q5, q5, W5
    vadd.s64 q6, q6, W6
    vadd.s64 q7, q7, W7

    vst1.32   {q0,q1}, [r12]!
    vst1.32   {q2,q3}, [r12]!
    vst1.32   {q4,q5}, [r12]!
    vst1.32   {q6,q7}, [r12]!

L_loop:

	// digests a-h = ctx->states;
    mov     r12, ctx
    vld1.64  {q0,q1}, [r12]!
    vld1.64  {q2,q3}, [r12]

	// rounds 0:47 interleaved with W/WK update for rounds 16:63
    mov     r4, #4
L_i_loop:
    rounds_schedule a, b, c, d, e, f, g, h, 16
    subs    r4, r4, #1
    bgt     L_i_loop

	// revert K to the beginning of K256[]
	sub		K, K, #640
	subs    num_blocks, num_blocks, #1				// num_blocks--

	beq	    L_final_block				// if final block, wrap up final rounds

    rounds_schedule_initial a, b, c, d, e, f, g, h, 0

	// ctx->states += digests a-h
    mov     r12, ctx
    vld1.64  {q4,q5}, [r12]!
    vld1.64  {q6,q7}, [r12]
    vadd.s64    q4, q0, q4
    vadd.s64    q5, q1, q5
    vadd.s64    q6, q2, q6
    vadd.s64    q7, q3, q7
    vst1.64  {q4,q5}, [ctx]
    vst1.64  {q6,q7}, [r12]

	bal		L_loop				// branch for next block

	// wrap up digest update round 48:63 for final block
L_final_block:
    rounds_schedule_final a, b, c, d, e, f, g, h, 0

	// ctx->states += digests a-h
    mov     r12, ctx
    vld1.64  {q4,q5}, [r12]!
    vld1.64  {q6,q7}, [r12]
    vadd.s64    q4, q0, q4
    vadd.s64    q5, q1, q5
    vadd.s64    q6, q2, q6
    vadd.s64    q7, q3, q7
    vst1.64  {q4,q5}, [ctx]
    vst1.64  {q6,q7}, [r12]

	// free allocated stack memory
    add     sp, sp, #stack_size

	// if kernel, restore used vector registers
#if BUILDKERNEL
    vpop   {q8-q15}
    vpop   {q0-q3}
#endif
    vpop    {q4-q7}

	// return
    pop     {r4,r5,r7,pc}


    .section    __DATA,__nl_symbol_ptr,non_lazy_symbol_pointers
    .p2align  4
L_Tab$non_lazy_ptr:
    .indirect_symbol    _sha512_K
    .long   0


#endif // (defined(__arm__) && defined(__ARM_NEON__))
