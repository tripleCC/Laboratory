# Copyright (c) (2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
#include <corecrypto/cc_config.h>

/*
	This file provides x86_64 hand implementation of the following function

	sha2_void sha256_compile(sha256_ctx ctx[1]);

	which is a C function in CommonCrypto Source/Digest/sha2.c

	The implementation here is modified from another sha256 x86_64 implementation for sha256 in the xnu.
	To modify to fit the new API,
		the old ctx (points to ctx->hashes) shoule be changed to ctx->hashes, 8(ctx).
		the old data (points to ctx->wbuf), should be changed to ctx->wbuf, 40(ctx).

	sha256_compile handles 1 input block (64 bytes) per call.


	The following is comments for the initial xnu-sha256.s.

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
		- a circular window of message schedule W(r:r+15) is updated and stored in ymm0-ymm1
		- its corresponding W+K(r:r+15) is updated and stored in a stack space circular buffer
		- the 8 digests (a-h) will be stored in GPR or m32 (all in GPR for x86_64, and some in m32 for i386)

	the implementation per block looks like

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 4 bytes) into ymm0:ymm1
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

	load W(0:15) (big-endian per 4 bytes) into ymm0:ymm1
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
		load W([r:r+3]%16) (big-endian per 4 bytes) into ymm0:ymm1
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
#if defined __x86_64__

	// associate variables with registers or memory

	#define	sp			%rsp

	#define	ctx			%rdi
	#define	data        %rdx

	#define	a			%r8d
	#define	b			%r9d
	#define	c			%r10d
	#define	d			%r11d
	#define	e			%r12d
	#define	f			%r13d
	#define	g			%r14d
	#define	h			%r15d

	#define stack_size	(8*5+32*8+16+64)	// _K/_ctx/num_blocks/i_loop/8-byte align + 16 (32-byte align) + ymm0:ymm7 + WK(0:15)

	#define	L_aligned_bswap	L_bswap(%rip)	// bswap : big-endian loading of 4-byte words
	#define	_i_loop	    -72(%rbp)
	#define	num_blocks	-64(%rbp)
	#define	_ctx		-56(%rbp) 
	#define	_K         	-48(%rbp) 

	// local variables
	#define	y0	%eax
	#define	y1	%ecx
	#define	y2	%ebx
	#define	y3	%esi
	#define	T1	%edi

	// a window (16 words) of message scheule
	#define	W0	%ymm0
	#define	W1	%ymm1

	// circular buffer for WK[(r:r+15)%16]
	#define WK(x)   ((x)&15)*4(sp)

    /*
        $0 : 8 messages w0-w7
        $1 : 8 messages w8-w15

        need to update $0 (w16-w23) as follows

            y2 = vext($0, $1, 1);   // 8-1
            y3 = shr($1, 6);        // 6z 15-14
            y4 = shr($1, 1);        // z 15-9
            $0 = $0 + Gamma0(y2)+Gamma1(y3)+y4;     // w16-w17 updated
            $0 += shl($0, 7);       // the previous w16 in y3 is compensated
            $0 += Gamma1([ 0 0 0 0 w17 w16 0 0]);
            $0 += Gamma1([ 0 0 w19 w18 0 0 0 0]);
            $0 += Gamma1([ w21 w20 0 0 0 0 0 0]);

            vperm2f128  $$0xf1, $1, $1, %ymm4    // ymm4 = [ z z z z 15-12 ]; latency 3
            vperm2f128  $$33, $1, $0, %ymm2      // ymm2 = [ 11-8 7-4 ]; latency 3
            vpsrldq     $$8, %ymm4, %ymm3        // ymm3 = [ z z z z z z 15 14]
            vpalignr    $$4, $1, %ymm4, %ymm4    // ymm4 = [ z 15-13 12-9 ];
            vpalignr    $$4, $0, %ymm2, %ymm2    // ymm2 = [ 8 7 6 5 4 3 2 1 ];
            vpadd       %ymm4, $0, $0           // $0 + y4

            // Gamma0(y2)
		    vpslld	$$14, %ymm2, %ymm5		// part of ROTR18
		    vpsrld	$$7, %ymm2, %ymm4		// part of ROTR7
		    vpsrld	$$3, %ymm2, %ymm2		// SHR3(x)
		    vpxor	%ymm5, %ymm2, %ymm2
		    vpslld	$$11, %ymm5, %ymm5		// part of ROTR7
		    vpxor	%ymm4, %ymm2, %ymm2
		    vpsrld	$$11, %ymm4, %ymm4		// part of ROTR18
		    vpxor	%ymm5, %ymm2, %ymm2
		    vpxor	%ymm4, %ymm2, %ymm2

		    vpaddd	%ymm2, $0, $0			// $0 + y4 + Gamma0(y2)

            // Gamma1(y3)
		    vpslld	$$13, %ymm3, %ymm7		// part of ROTR18
		    vpsrld	$$17, %ymm3, %ymm6		// part of ROTR7
		    vpsrld	$$10, %ymm3, %ymm3		// SHR3(x)
		    vpxor	%ymm7, %ymm3, %ymm3
		    vpslld	$$2, %ymm7, %ymm7		// part of ROTR7
		    vpxor	%ymm6, %ymm3, %ymm3
		    vpsrld	$$2, %ymm6, %ymm6		// part of ROTR18
		    vpxor	%ymm7, %ymm3, %ymm3
		    vpxor	%ymm6, %ymm3, %ymm3
		    vpaddd	%ymm3, $0, $0			// $0 + y4 + Gamma0(y2) + Gamma1(y3);

            vperm2f128  $$0x0f, $0, $0, %ymm2    // ymm2 = [ x x 17 16 z z z z ]; latency 3
            vperm2f128  $$0xf0, $0, $0, %ymm3    // ymm3 = [ z z z z x x 17 16 ]; latency 3
            vpslldq     $$12, %ymm2, %ymm2       // ymm2 = [ 16 z z z z... ];
            vpslldq     $$8, %ymm3, %ymm3       // ymm3 = [ z z z z 17 16 z z ];
		    vpaddd	    %ymm2, $0, $0			 // $0 + y4 + Gamma0(y2) + Gamma1(y3); add back w16 missing previously in y4

            // Gamma1(y3)
		    vpslld	$$13, %ymm3, %ymm7		// part of ROTR18
		    vpsrld	$$17, %ymm3, %ymm6		// part of ROTR7
		    vpsrld	$$10, %ymm3, %ymm3		// SHR3(x)
		    vpxor	%ymm7, %ymm3, %ymm3
		    vpslld	$$2, %ymm7, %ymm7		// part of ROTR7
		    vpxor	%ymm6, %ymm3, %ymm3
		    vpsrld	$$2, %ymm6, %ymm6		// part of ROTR18
		    vpxor	%ymm7, %ymm3, %ymm3
		    vpxor	%ymm6, %ymm3, %ymm3
		    vpaddd	%ymm3, $0, $0			// $0 + y4 + Gamma0(y2) + Gamma1(y3) + Gamma1( w17-w16 );

            vperm2f128  $$0x0f, $0, $0, %ymm3    // ymm3 = [ 19 18 17 16 z z z z ]; latency 3
            vpsrldq     $$8, %ymm3, %ymm3       // ymm3 = [ z z 19 18 z z z z... ];

            // Gamma1(y3)
		    vpslld	$$13, %ymm3, %ymm7		// part of ROTR18
		    vpsrld	$$17, %ymm3, %ymm6		// part of ROTR7
		    vpsrld	$$10, %ymm3, %ymm3		// SHR3(x)
		    vpxor	%ymm7, %ymm3, %ymm3
		    vpslld	$$2, %ymm7, %ymm7		// part of ROTR7
		    vpxor	%ymm6, %ymm3, %ymm3
		    vpsrld	$$2, %ymm6, %ymm6		// part of ROTR18
		    vpxor	%ymm7, %ymm3, %ymm3
		    vpxor	%ymm6, %ymm3, %ymm3
		    vpaddd	%ymm3, $0, $0			// $0 + y4 + Gamma0(y2) + Gamma1(y3) + Gamma1( w17-w16 ) + Gamma1( w19-w18 );

            vperm2f128  $$0x1f, $0, $0, %ymm3    // ymm3 = [ x x 21 20 z z z z ]; latency 3
            vpslldq     $$8, %ymm3, %ymm3       // ymm3 = [ 21 20 z z z z... ];

            // Gamma1(y3)
		    vpslld	$$13, %ymm3, %ymm7		// part of ROTR18
		    vpsrld	$$17, %ymm3, %ymm6		// part of ROTR7
		    vpsrld	$$10, %ymm3, %ymm3		// SHR3(x)
		    vpxor	%ymm7, %ymm3, %ymm3
		    vpslld	$$2, %ymm7, %ymm7		// part of ROTR7
		    vpxor	%ymm6, %ymm3, %ymm3
		    vpsrld	$$2, %ymm6, %ymm6		// part of ROTR18
		    vpxor	%ymm7, %ymm3, %ymm3
		    vpxor	%ymm6, %ymm3, %ymm3
		    vpaddd	%ymm3, $0, $0			// $0 + y4 + Gamma0(y2) + Gamma1(y3) + Gamma1( w17-w16 ) + Gamma1( w19-w18 ) + Gamma1( w21-w20 );

    */

	.macro	rounds8_schedule arg0, arg1, arg2
	// round	a, b, c, d, e, f, g, h, 0+\arg4
	mov		a, y3
            vperm2f128  $0xf1, \arg1, \arg1, %ymm4    // ymm4 = [ z z z z 15-12 ]; latency 3
	rorx	$25, e, y0
            vperm2f128  $33, \arg1, \arg0, %ymm2      // ymm2 = [ 11-8 7-4 ]; latency 3
	rorx	$11, e, y1
	add		WK(0+\arg2), h
	or		c, y3
	mov		f, y2
            vpsrldq     $8, %ymm4, %ymm3        // ymm3 = [ z z z z z z 15 14]
	rorx	$13, a, T1
	xor		y1, y0
	xor		g, y2
            vpalignr    $4, \arg1, %ymm4, %ymm4    // ymm4 = [ z 15-13 12-9 ];
	rorx	$6, e, y1
	and		e, y2
	xor		y1, y0
	rorx	$22, a, y1
            vpalignr    $4, \arg0, %ymm2, %ymm2    // ymm2 = [ 8 7 6 5 4 3 2 1 ];
	add		h, d
	and		b, y3
	xor		T1, y1
            vpaddd      %ymm4, \arg0, \arg0           // \arg0 + y4
	rorx	$2, a, T1
	xor		g, y2
	xor		T1, y1
		    vpslld	$14, %ymm2, %ymm5		// part of ROTR18
	mov		a, T1
	and		c, T1
	add		y1, h
	add		y0, y2
		    vpsrld	$7, %ymm2, %ymm4		// part of ROTR7
	or		T1, y3
	add		y2, h
	add		y2, d
		    vpsrld	$3, %ymm2, %ymm2		// SHR3(x)
	add		y3, h


		    vpslld	$13, %ymm3, %ymm7		// part of ROTR18

	// round	h, a, b, c, d, e, f, g, 1+\arg4
	mov		h, y3
	rorx	$25, d, y0
	rorx	$11, d, y1
		    vpsrld	$17, %ymm3, %ymm6		// part of ROTR7
	add		WK(1+\arg2), g
	mov		e, y2
	or		b, y3
		    vpsrld	$10, %ymm3, %ymm3		// SHR3(x)
	rorx	$13, h, T1
	xor		y1, y0
	xor		f, y2
		    vpxor	%ymm5, %ymm2, %ymm2
	rorx	$6, d, y1
	and		d, y2
	xor		y1, y0
		    vpslld	$11, %ymm5, %ymm5		// part of ROTR7
	rorx	$22, h, y1
	add		g, c
	and		a, y3
		    vpxor	%ymm7, %ymm3, %ymm3
	xor		T1, y1
	rorx	$2, h, T1
	xor		f, y2
		    vpslld	$2, %ymm7, %ymm7		// part of ROTR7
	xor		T1, y1
	mov		h, T1
	add		y0, y2
		    vpxor	%ymm4, %ymm2, %ymm2
	and		b, T1
	add		y1, g
	or		T1, y3
		    vpsrld	$11, %ymm4, %ymm4		// part of ROTR18
	add		y2, g
	add		y2, c
		    vpxor	%ymm6, %ymm3, %ymm3
	add		y3, g
		    vpsrld	$2, %ymm6, %ymm6		// part of ROTR18






	// round	g, h, a, b, c, d, e, f, 2+\arg4
		    vpxor	%ymm5, %ymm2, %ymm2
	mov		g, y3
		    vpxor	%ymm7, %ymm3, %ymm3
	rorx	$25, c, y0
		    vpxor	%ymm4, %ymm2, %ymm2
	rorx	$11, c, y1
		    vpxor	%ymm6, %ymm3, %ymm3
	add		WK(2+\arg2), f
	or		a, y3
	mov		d, y2
		    vpaddd	%ymm2, \arg0, \arg0			// \arg0 + y4 + Gamma0(y2)
	rorx	$13, g, T1
	xor		y1, y0
	xor		e, y2
		    vpaddd	%ymm3, \arg0, \arg0			// \arg0 + y4 + Gamma0(y2) + Gamma1(y3);
	rorx	$6, c, y1
	and		c, y2
	xor		y1, y0
	rorx	$22, g, y1
	add		f, b
            vperm2f128  $0x0f, \arg0, \arg0, %ymm2    // ymm2 = [ x x 17 16 z z z z ]; latency 3
	and		h, y3
	xor		T1, y1
	rorx	$2, g, T1
            vperm2f128  $0xf0, \arg0, \arg0, %ymm3    // ymm3 = [ z z z z x x 17 16 ]; latency 3
	xor		e, y2
	xor		T1, y1
	mov		g, T1
            vpslldq     $12, %ymm2, %ymm2       // ymm2 = [ 16 z z z z... ];
	and		a, T1
	add		y1, f
	add		y0, y2
	or		T1, y3
            vpslldq     $8, %ymm3, %ymm3       // ymm3 = [ z z z z 17 16 z z ];
	add		y2, f
	add		y2, b
		    vpaddd	    %ymm2, \arg0, \arg0			 // \arg0 + y4 + Gamma0(y2) + Gamma1(y3); add back w16 missing previously in y4
	add		y3, f



	// round	f, g, h, a, b, c, d, e, 3+\arg4
		    vpslld	$13, %ymm3, %ymm7		// part of ROTR18
	mov		f, y3
	rorx	$25, b, y0
		    vpsrld	$17, %ymm3, %ymm6		// part of ROTR7
	rorx	$11, b, y1
	add		WK(3+\arg2), e
	or		h, y3
		    vpsrld	$10, %ymm3, %ymm3		// SHR3(x)
	mov		c, y2
	rorx	$13, f, T1
	xor		y1, y0
		    vpxor	%ymm7, %ymm3, %ymm3
	xor		d, y2
	rorx	$6, b, y1
	and		b, y2
		    vpslld	$2, %ymm7, %ymm7		// part of ROTR7
	xor		y1, y0
	rorx	$22, f, y1
	add		e, a
		    vpxor	%ymm6, %ymm3, %ymm3
	and		g, y3
	xor		T1, y1
	rorx	$2, f, T1
		    vpsrld	$2, %ymm6, %ymm6		// part of ROTR18
	xor		d, y2
	xor		T1, y1
	mov		f, T1
		    vpxor	%ymm7, %ymm3, %ymm3
	and		h, T1
	add		y1, e
	add		y0, y2
	or		T1, y3
		    vpxor	%ymm6, %ymm3, %ymm3
	add		y2, e
	add		y2, a
	add		y3, e
		    vpaddd	%ymm3, \arg0, \arg0			// \arg0 + y4 + Gamma0(y2) + Gamma1(y3) + Gamma1( w17-w16 );

	// round	e, f, g, h, a, b, c, d, 0+\arg4

	mov		e, y3
	rorx	$25, a, y0
	rorx	$11, a, y1
	add		WK(4+\arg2), d
            vperm2f128  $0x0f, \arg0, \arg0, %ymm3    // ymm3 = [ 19 18 17 16 z z z z ]; latency 3
	or		g, y3
	mov		b, y2
	rorx	$13, e, T1
	xor		y1, y0
            vpsrldq     $8, %ymm3, %ymm3       // ymm3 = [ z z 19 18 z z z z... ];
	xor		c, y2
	rorx	$6, a, y1
	and		a, y2
		    vpslld	$13, %ymm3, %ymm7		// part of ROTR18
	xor		y1, y0
	rorx	$22, e, y1
	add		d, h
		    vpsrld	$17, %ymm3, %ymm6		// part of ROTR7
	and		f, y3
	xor		T1, y1
	rorx	$2, e, T1
		    vpsrld	$10, %ymm3, %ymm3		// SHR3(x)
	xor		c, y2
	xor		T1, y1
	mov		e, T1
		    vpxor	%ymm7, %ymm3, %ymm3
	and		g, T1
	add		y1, d
	add		y0, y2
	or		T1, y3
		    vpslld	$2, %ymm7, %ymm7		// part of ROTR7
	add		y2, d
	add		y2, h
		    vpxor	%ymm6, %ymm3, %ymm3
	add		y3, d
		    vpsrld	$2, %ymm6, %ymm6		// part of ROTR18



	// round	d, e, f, g, h, a, b, c, 1+\arg4
	mov		d, y3
	rorx	$25, h, y0
	rorx	$11, h, y1
		    vpxor	%ymm7, %ymm3, %ymm3
	add		WK(5+\arg2), c
	or		f, y3
	mov		a, y2
		    vpxor	%ymm6, %ymm3, %ymm3
	rorx	$13, d, T1
	xor		y1, y0
	xor		b, y2
		    vpaddd	%ymm3, \arg0, \arg0			// \arg0 + y4 + Gamma0(y2) + Gamma1(y3) + Gamma1( w17-w16 ) + Gamma1( w19-w18 );
	rorx	$6, h, y1
	and		h, y2
	xor		y1, y0
	rorx	$22, d, y1
	add		c, g
	and		e, y3
            vperm2f128  $0x1f, \arg0, \arg0, %ymm3    // ymm3 = [ x x 21 20 z z z z ]; latency 3
	xor		T1, y1
	rorx	$2, d, T1
	xor		b, y2
	xor		T1, y1
            vpslldq     $8, %ymm3, %ymm3       // ymm3 = [ 21 20 z z z z... ];
	mov		d, T1
	and		f, T1
	add		y1, c
	add		y0, y2
	or		T1, y3
		    vpslld	$13, %ymm3, %ymm7		// part of ROTR18
	add		y2, c
	add		y2, g
		    vpsrld	$17, %ymm3, %ymm6		// part of ROTR7
	add		y3, c
		    vpsrld	$10, %ymm3, %ymm3		// SHR3(x)

	//round	c, d, e, f, g, h, a, b, 2+\arg4
	mov		c, y3
	rorx	$25, g, y0
	rorx	$11, g, y1
	add		WK(6+\arg2), b
		    vpxor	%ymm7, %ymm3, %ymm3
	or		e, y3
	mov		h, y2
	rorx	$13, c, T1
		    vpslld	$2, %ymm7, %ymm7		// part of ROTR7
	xor		y1, y0
	xor		a, y2
	rorx	$6, g, y1
		    vpxor	%ymm6, %ymm3, %ymm3
	and		g, y2
	xor		y1, y0
		    vpsrld	$2, %ymm6, %ymm6		// part of ROTR18
	rorx	$22, c, y1
	add		b, f
	and		d, y3
	xor		T1, y1
		    vpxor	%ymm7, %ymm3, %ymm3
	rorx	$2, c, T1
	xor		a, y2
	xor		T1, y1
		    vpxor	%ymm6, %ymm3, %ymm3
	mov		c, T1
	and		e, T1
	add		y1, b
	add		y0, y2
		    vpaddd	%ymm3, \arg0, \arg0			// \arg0 + y4 + Gamma0(y2) + Gamma1(y3) + Gamma1( w17-w16 ) + Gamma1( w19-w18 ) + Gamma1( w21-w20 );
	or		T1, y3
	add		y2, b
	add		y2, f
	add		y3, b

	// round	b, c, d, e, f, g, h, a, 3+\arg4
	mov		b, y3
	rorx	$25, f, y0
	rorx	$11, f, y1
	add		WK(7+\arg2), a
	or		d, y3
	mov		g, y2
	rorx	$13, b, T1
	xor		y1, y0
	xor		h, y2
	rorx	$6, f, y1
	and		f, y2
	xor		y1, y0
	rorx	$22, b, y1
	add		a, e
	and		c, y3
	xor		T1, y1
	rorx	$2, b, T1
	xor		h, y2
	xor		T1, y1
	mov		b, T1
	and		d, T1
	add		y1, a
	add		y0, y2
	or		T1, y3
        mov     _K, %rax
	add		y2, a
	add		y2, e
	add		y3, a

		vpaddd	(%rax), \arg0, %ymm2			// WK

		addq	$32, _K
		vmovdqa	%ymm2, WK(\arg2)

	.endm

	.macro	rounds8_update arg0, arg1
	// round	a, b, c, d, e, f, g, h, 0+\arg0
		vmovdqu	((\arg0&8)*4)(data), \arg1		// read 8 4-byte words
	mov		a, y3
	rorx	$25, e, y0
	rorx	$11, e, y1
	add		WK(0+\arg0), h
	or		c, y3
	mov		f, y2
	rorx	$13, a, T1
	xor		y1, y0
	xor		g, y2
	rorx	$6, e, y1
	and		e, y2
	xor		y1, y0
	rorx	$22, a, y1
	add		h, d
	and		b, y3
	xor		T1, y1
	rorx	$2, a, T1
	xor		g, y2
	xor		T1, y1
	mov		a, T1
	and		c, T1
	add		y1, h
	add		y0, y2
	or		T1, y3
	add		y2, h
	add		y2, d
	add		y3, h

	// round	h, a, b, c, d, e, f, g, 1+\arg0
		vpshufb	L_aligned_bswap, \arg1, \arg1	// big-endian of each 4-byte word, W[r:r+7]
	mov		h, y3
	rorx	$25, d, y0
	rorx	$11, d, y1
	add		WK(1+\arg0), g
	or		b, y3
	mov		e, y2
	rorx	$13, h, T1
	xor		y1, y0
	xor		f, y2
	rorx	$6, d, y1
	and		d, y2
	xor		y1, y0
	rorx	$22, h, y1
	add		g, c
	and		a, y3
	xor		T1, y1
	rorx	$2, h, T1
	xor		f, y2
	xor		T1, y1
	mov		h, T1
	and		b, T1
	add		y1, g
	add		y0, y2
	or		T1, y3
	add		y2, g
	add		y2, c
	add		y3, g

	// round	g, h, a, b, c, d, e, f, 2+\arg0
	mov		g, y3
	rorx	$25, c, y0
	rorx	$11, c, y1
	add		WK(2+\arg0), f
	or		a, y3
	mov		d, y2
	rorx	$13, g, T1
	xor		y1, y0
	xor		e, y2
	rorx	$6, c, y1
	and		c, y2
	xor		y1, y0
	rorx	$22, g, y1
	add		f, b
	and		h, y3
	xor		T1, y1
	rorx	$2, g, T1
	xor		e, y2
	xor		T1, y1
	mov		g, T1
	and		a, T1
	add		y1, f
	add		y0, y2
	or		T1, y3
    mov     _K, %rax
	add		y2, f
	add		y2, b
	add		y3, f

	// round	f, g, h, a, b, c, d, e, 3+\arg0
		vpaddd	((\arg0&8)*4)(%rax), \arg1, %ymm2			// WK[r:r+7]

	mov		f, y3
	rorx	$25, b, y0
	rorx	$11, b, y1
	add		WK(3+\arg0), e
	or		h, y3
	mov		c, y2
	rorx	$13, f, T1
	xor		y1, y0
	xor		d, y2
	rorx	$6, b, y1
	and		b, y2
	xor		y1, y0
	rorx	$22, f, y1
	add		e, a
	and		g, y3
	xor		T1, y1
	rorx	$2, f, T1
	xor		d, y2
	xor		T1, y1
	mov		f, T1
	and		h, T1
	add		y1, e
	add		y0, y2
	or		T1, y3
	add		y2, e
	add		y2, a
	add		y3, e

	// round	e, f, g, h, a, b, c, d, 0+\arg0
	mov		e, y3
	rorx	$25, a, y0
	rorx	$11, a, y1
	add		WK(4+\arg0), d
	or		g, y3
	mov		b, y2
	rorx	$13, e, T1
	xor		y1, y0
	xor		c, y2
	rorx	$6, a, y1
	and		a, y2
	xor		y1, y0
	rorx	$22, e, y1
	add		d, h
	and		f, y3
	xor		T1, y1
	rorx	$2, e, T1
	xor		c, y2
	xor		T1, y1
	mov		e, T1
	and		g, T1
	add		y1, d
	add		y0, y2
	or		T1, y3
	add		y2, d
	add		y2, h
	add		y3, d

	// round	d, e, f, g, h, a, b, c, 1+\arg0
	mov		d, y3
	rorx	$25, h, y0
	rorx	$11, h, y1
	add		WK(5+\arg0), c
	or		f, y3
	mov		a, y2
	rorx	$13, d, T1
	xor		y1, y0
	xor		b, y2
	rorx	$6, h, y1
	and		h, y2
	xor		y1, y0
	rorx	$22, d, y1
	add		c, g
	and		e, y3
	xor		T1, y1
	rorx	$2, d, T1
	xor		b, y2
	xor		T1, y1
	mov		d, T1
	and		f, T1
	add		y1, c
	add		y0, y2
	or		T1, y3
	add		y2, c
	add		y2, g
	add		y3, c

	//round	c, d, e, f, g, h, a, b, 2+\arg0
	mov		c, y3
	rorx	$25, g, y0
	rorx	$11, g, y1
	add		WK(6+\arg0), b
	or		e, y3
	mov		h, y2
	rorx	$13, c, T1
	xor		y1, y0
	xor		a, y2
	rorx	$6, g, y1
	and		g, y2
	xor		y1, y0
	rorx	$22, c, y1
	add		b, f
	and		d, y3
	xor		T1, y1
	rorx	$2, c, T1
	xor		a, y2
	xor		T1, y1
	mov		c, T1
	and		e, T1
	add		y1, b
	add		y0, y2
	or		T1, y3
	add		y2, b
	add		y2, f
	add		y3, b

	// round	b, c, d, e, f, g, h, a, 3+\arg0
	mov		b, y3
	rorx	$25, f, y0
	rorx	$11, f, y1
	add		WK(7+\arg0), a
	or		d, y3
	mov		g, y2
	rorx	$13, b, T1
	xor		y1, y0
	xor		h, y2
	rorx	$6, f, y1
	and		f, y2
	xor		y1, y0
	rorx	$22, b, y1
	add		a, e
	and		c, y3
	xor		T1, y1
	rorx	$2, b, T1
	xor		h, y2
	xor		T1, y1
	mov		b, T1
	and		d, T1
	add		y1, a
	add		y0, y2
	or		T1, y3
	add		y2, a
	add		y2, e
	add		y3, a

		vmovdqa	%ymm2, WK(\arg0&8)		// save WK[r:r+3] into stack circular buffer
	.endm

	.macro	rounds8 arg0
	// round	a, b, c, d, e, f, g, h, 0+\arg0
	mov		a, y3
	rorx	$25, e, y0
	rorx	$11, e, y1
	add		WK(0+\arg0), h
	or		c, y3
	mov		f, y2
	rorx	$13, a, T1
	xor		y1, y0
	xor		g, y2
	rorx	$6, e, y1
	and		e, y2
	xor		y1, y0
	rorx	$22, a, y1
	add		h, d
	and		b, y3
	xor		T1, y1
	rorx	$2, a, T1
	xor		g, y2
	xor		T1, y1
	mov		a, T1
	and		c, T1
	add		y1, h
	add		y0, y2
	or		T1, y3
	add		y2, h
	add		y2, d
	add		y3, h

	// round	h, a, b, c, d, e, f, g, 1+\arg0
	mov		h, y3
	rorx	$25, d, y0
	rorx	$11, d, y1
	add		WK(1+\arg0), g
	or		b, y3
	mov		e, y2
	rorx	$13, h, T1
	xor		y1, y0
	xor		f, y2
	rorx	$6, d, y1
	and		d, y2
	xor		y1, y0
	rorx	$22, h, y1
	add		g, c
	and		a, y3
	xor		T1, y1
	rorx	$2, h, T1
	xor		f, y2
	xor		T1, y1
	mov		h, T1
	and		b, T1
	add		y1, g
	add		y0, y2
	or		T1, y3
	add		y2, g
	add		y2, c
	add		y3, g

	// round	g, h, a, b, c, d, e, f, 2+\arg0
	mov		g, y3
	rorx	$25, c, y0
	rorx	$11, c, y1
	add		WK(2+\arg0), f
	or		a, y3
	mov		d, y2
	rorx	$13, g, T1
	xor		y1, y0
	xor		e, y2
	rorx	$6, c, y1
	and		c, y2
	xor		y1, y0
	rorx	$22, g, y1
	add		f, b
	and		h, y3
	xor		T1, y1
	rorx	$2, g, T1
	xor		e, y2
	xor		T1, y1
	mov		g, T1
	and		a, T1
	add		y1, f
	add		y0, y2
	or		T1, y3
	add		y2, f
	add		y2, b
	add		y3, f

	// round	f, g, h, a, b, c, d, e, 3+\arg0
	mov		f, y3
	rorx	$25, b, y0
	rorx	$11, b, y1
	add		WK(3+\arg0), e
	or		h, y3
	mov		c, y2
	rorx	$13, f, T1
	xor		y1, y0
	xor		d, y2
	rorx	$6, b, y1
	and		b, y2
	xor		y1, y0
	rorx	$22, f, y1
	add		e, a
	and		g, y3
	xor		T1, y1
	rorx	$2, f, T1
	xor		d, y2
	xor		T1, y1
	mov		f, T1
	and		h, T1
	add		y1, e
	add		y0, y2
	or		T1, y3
	add		y2, e
	add		y2, a
	add		y3, e

	// round	e, f, g, h, a, b, c, d, 0+\arg0
	mov		e, y3
	rorx	$25, a, y0
	rorx	$11, a, y1
	add		WK(4+\arg0), d
	or		g, y3
	mov		b, y2
	rorx	$13, e, T1
	xor		y1, y0
	xor		c, y2
	rorx	$6, a, y1
	and		a, y2
	xor		y1, y0
	rorx	$22, e, y1
	add		d, h
	and		f, y3
	xor		T1, y1
	rorx	$2, e, T1
	xor		c, y2
	xor		T1, y1
	mov		e, T1
	and		g, T1
	add		y1, d
	add		y0, y2
	or		T1, y3
	add		y2, d
	add		y2, h
	add		y3, d

	// round	d, e, f, g, h, a, b, c, 1+\arg0
	mov		d, y3
	rorx	$25, h, y0
	rorx	$11, h, y1
	add		WK(5+\arg0), c
	or		f, y3
	mov		a, y2
	rorx	$13, d, T1
	xor		y1, y0
	xor		b, y2
	rorx	$6, h, y1
	and		h, y2
	xor		y1, y0
	rorx	$22, d, y1
	add		c, g
	and		e, y3
	xor		T1, y1
	rorx	$2, d, T1
	xor		b, y2
	xor		T1, y1
	mov		d, T1
	and		f, T1
	add		y1, c
	add		y0, y2
	or		T1, y3
	add		y2, c
	add		y2, g
	add		y3, c

	//round	c, d, e, f, g, h, a, b, 2+\arg0
	mov		c, y3
	rorx	$25, g, y0
	rorx	$11, g, y1
	add		WK(6+\arg0), b
	or		e, y3
	mov		h, y2
	rorx	$13, c, T1
	xor		y1, y0
	xor		a, y2
	rorx	$6, g, y1
	and		g, y2
	xor		y1, y0
	rorx	$22, c, y1
	add		b, f
	and		d, y3
	xor		T1, y1
	rorx	$2, c, T1
	xor		a, y2
	xor		T1, y1
	mov		c, T1
	and		e, T1
	add		y1, b
	add		y0, y2
	or		T1, y3
	add		y2, b
	add		y2, f
	add		y3, b

	// round	b, c, d, e, f, g, h, a, 3+\arg0
	mov		b, y3
	rorx	$25, f, y0
	rorx	$11, f, y1
	add		WK(7+\arg0), a
	or		d, y3
	mov		g, y2
	rorx	$13, b, T1
	xor		y1, y0
	xor		h, y2
	rorx	$6, f, y1
	and		f, y2
	xor		y1, y0
	rorx	$22, b, y1
	add		a, e
	and		c, y3
	xor		T1, y1
	rorx	$2, b, T1
	xor		h, y2
	xor		T1, y1
	mov		b, T1
	and		d, T1
	add		y1, a
	add		y0, y2
	or		T1, y3
	add		y2, a
	add		y2, e
	add		y3, a

	.endm

	.text
    .globl	_AccelerateCrypto_SHA256_compress_AVX2
_AccelerateCrypto_SHA256_compress_AVX2:

	// push callee-saved registers
	push	%rbp
    mov     %rsp, %rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	// allocate stack space
	sub		$stack_size, sp
    andq    $-32, sp

	mov		%rsi, num_blocks
	mov		%rdi, _ctx

	// if kernel code, save used ymm registers
#if BUILDKERNEL
    leaq    64(%rsp), %rax   
	vmovdqa	%ymm0, 0*32(%rax)
	vmovdqa	%ymm1, 1*32(%rax)
	vmovdqa	%ymm2, 2*32(%rax)
	vmovdqa	%ymm3, 3*32(%rax)
	vmovdqa	%ymm4, 4*32(%rax)
	vmovdqa	%ymm5, 5*32(%rax)
	vmovdqa	%ymm6, 6*32(%rax)
	vmovdqa	%ymm7, 7*32(%rax)
#endif

	lea		CC_C_LABEL(sha256_K)(%rip), %rcx
    movq    %rcx, _K

	// load W[0:15] into ymm0-ymm1
	vmovdqu	0*32(data), W0
	vmovdqu	1*32(data), W1
	addq	$64, data

	vpshufb	L_aligned_bswap, W0, W0
	vpshufb	L_aligned_bswap, W1, W1

	// compute WK[0:15] and save in stack
    movq    _K, %rax
	vpaddd	0*32(%rax), W0, %ymm2
	vpaddd	1*32(%rax), W1, %ymm3
    addq	$64, _K
	vmovdqa	%ymm2, WK(0)
	vmovdqa	%ymm3, WK(8)

L_loop:

	// digests a-h = ctx->states;
	mov		_ctx, ctx
	mov		0*4(ctx), a
	mov		1*4(ctx), b
	mov		2*4(ctx), c
	mov		3*4(ctx), d
	mov		4*4(ctx), e
	mov		5*4(ctx), f
	mov		6*4(ctx), g
	mov		7*4(ctx), h

	// rounds 0:47 interleaved with W/WK update for rounds 16:63
    movq    $3, _i_loop
L_i_loop:
	rounds8_schedule W0, W1, 16
	rounds8_schedule W1, W0, 24
    subq    $1, _i_loop
    jg      L_i_loop

	// revert K to the beginning of K256[]
	subq		$256, _K
	subq		$1, num_blocks				// num_blocks--

	je		L_final_block				// if final block, wrap up final rounds

	// rounds 48:63 interleaved with W/WK initialization for next block rounds 0:15
	rounds8_update	48, W0
	rounds8_update	56, W1

	addq	$64, _K
	addq	$64, data

	// ctx->states += digests a-h
	mov		_ctx, ctx
	add		a, 0*4(ctx)
	add		b, 1*4(ctx)
	add		c, 2*4(ctx)
	add		d, 3*4(ctx)
	add		e, 4*4(ctx)
	add		f, 5*4(ctx)
	add		g, 6*4(ctx)
	add		h, 7*4(ctx)

	jmp		L_loop				// branch for next block

	// wrap up digest update round 48:63 for final block
L_final_block:
	rounds8	48
	rounds8 56	

	// ctx->states += digests a-h
	mov		_ctx, ctx
	add		a, 0*4(ctx)
	add		b, 1*4(ctx)
	add		c, 2*4(ctx)
	add		d, 3*4(ctx)
	add		e, 4*4(ctx)
	add		f, 5*4(ctx)
	add		g, 6*4(ctx)
	add		h, 7*4(ctx)

	// if kernel, restore ymm0-ymm7
#if BUILDKERNEL
    leaq    64(%rsp), %rax   
	vmovdqa	0*32(%rax), %ymm0
	vmovdqa	1*32(%rax), %ymm1
	vmovdqa	2*32(%rax), %ymm2
	vmovdqa	3*32(%rax), %ymm3
	vmovdqa	4*32(%rax), %ymm4
	vmovdqa	5*32(%rax), %ymm5
	vmovdqa	6*32(%rax), %ymm6
	vmovdqa	7*32(%rax), %ymm7
#endif

	// free allocated stack memory
    leaq    -40(%rbp), sp

	// restore callee-saved registers
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	pop		%rbx
	pop		%rbp

	// return
	ret

	// data for using ssse3 pshufb instruction (big-endian loading of data)
    CC_ASM_SECTION_CONST
    .p2align  5, 0x90

L_bswap:
    .long   0x00010203
    .long   0x04050607
    .long   0x08090a0b
    .long   0x0c0d0e0f
    .long   0x10111213
    .long   0x14151617
    .long   0x18191a1b
    .long   0x1c1d1e1f


#endif      // x86_64

