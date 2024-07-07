# Copyright (c) (2010,2011,2012,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
#include <corecrypto/cc_config.h>

#if (defined(__x86_64__) || defined(__i386__))

/* 	vng_sha1LittleEndian.s : this file provides optimized x86_64 and i386 implementation of the sha1 function
	CoreOS - vector and numerics group

	The implementation is based on the principle described in an Intel online article
	"Improving the Performance of the Secure Hash Algorithm (SHA-1)"
	http://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1/


	Update HASH[] by processing a one 64-byte block in MESSAGE[] can be represented by the following C function

void SHA1( int HASH[], int MESSAGE[] )
{
    int A[81], B[81], C[81], D[81], E[81];
    int W[80];

    int i, FN;

    A[0] = HASH[0];
    B[0] = HASH[1];
    C[0] = HASH[2];
    D[0] = HASH[3];
    E[0] = HASH[4];

    for ( i=0; i<80; ++i )
    {
        if ( i < 16 )
            W[i] = BIG_ENDIAN_LOAD( MESSAGE[i] );
        else
            W[i] = ROTATE_LEFT( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 );

        FN = F( i, B[i], C[i], D[i] );

        A[i+1] = FN + E[i] + ROTATE_LEFT( A[i], 5 ) + W[i] + K(i);
        B[i+1] = A[i];
        C[i+1] = ROTATE_LEFT( B[i], 30 );
        D[i+1] = C[i];
        E[i+1] = D[i];
    }

    HASH[0] += A[80];
    HASH[1] += B[80];
    HASH[2] += C[80];
    HASH[3] += D[80];
    HASH[4] += E[80];
}

	For i=0:15, W[i] is simply big-endian loading of MESSAGE[i]. For i=16:79, W[i] is updated according to W[i] = ROTATE_LEFT( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 );

	The approach (by Dean Gaudet) can be used to vectorize the computation of W[i] for i=16:79,

	1. done on 4 consequtive W[i] values in a single XMM register
    W[i  ] = (W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]) rol 1
    W[i+1] = (W[i-2] ^ W[i-7] ^ W[i-13] ^ W[i-15]) rol 1
    W[i+2] = (W[i-1] ^ W[i-6] ^ W[i-12] ^ W[i-14]) rol 1
    W[i+3] = (   0   ^ W[i-5] ^ W[i-11] ^ W[i-13]) rol 1

    2. this additional calculation unfortunately requires many additional operations
    W[i+3] ^= W[i] rol 1

    3. once we have 4 W[i] values in XMM we can also add four K values with one instruction
    W[i:i+3] += {K,K,K,K}

	Let W0 = {W[i] W[i+1] W[i+2] W[i+3]} be the current W-vector to be computed, W4 = {W[i-4] W[i-3] W[i-2] W[i-1]} be the previous vector, and so on
	The Dean Gaudet approach can be expressed as

	1. W0 = rotate_left(left_shift(W4,32) ^ W8 ^ left_shift(concatenate(W16,W12),64) ^ W16,1);
	2. W[i+3] ^= W[i] rol 1
	3. W0 += {K,K,K,K}

	For i>=32, the Intel online article suggests that (using a basic identity (X rol 1) rol 1 = X rol 2) the update equation is equivalent to

	1. W0 = rotate_left(left_shift(concatenate(W8,W4),64) ^ W16 ^ W28 ^ W32, 2);

	Note:
	1. In total, we need 8 16-byte registers or memory for W0,W4,...,W28. W0 and W32 can be the same register or memory.
	2. The registers are used in a circular buffering mode. For example, we start with W28,W24,...,W0 (with W0 indicating the most recent 16-byte)
		i=0, W28,W24,...,W0
		i=4, W24,W20,...,W28
		i=8, W20,W16,...,W24
		.
		.
		and so forth.
	3. 2 ssse3 instructions are used in the Intel article, pshufb and palignr.
		a. pshufb is used to simplify the BIG_ENDIAN_LOAD operation
		b. palignr is used to simplify the computation of left_shift(concatenate(W12,W8),64)

*/

/* the code can be compiled into single block (64 bytes) per call mode by setting Multiple_blocks to 0 */
#define	Multiple_Blocks	1

#if defined (__x86_64__) || defined(__i386__)		// x86_64 or i386 architectures

#if defined(__x86_64__)

	// set up for x86_64
#define	stack_size	(16*11+16*4)					// x0-x10 + 4 128-bits for intermediate WK(t) storage
#define	sp			%rsp							// unifying architectural stack pointer representation
#define	ctx			%rdi							// 1st input argument, will move to HASH_PTR (%r9)
#define	buf			%rdx							// 3rd input argument, will move to BUFFER_PTR (%r10)
#define	cnt         %r11							// will copy from the 2nd input argument (%rsi)
#define K_BASE		%r8								// an aligned pointer to point to shufb reference numbers of table of K values
#define HASH_PTR	%r9								// pointer to Hash values (A,B,C,D,E)
#define BUFFER_PTR  %r10							// pointer to input blocks

#else	// !__x86_64__

	// set up for i386
#define stack_size	(12+16*2+16*11+16*4)			// 12-bytes (alignment) + extra 2 + 3 (W24/W28/XMM_SHUFB_BSWAP) + 8 (xmm0-xmm7) + 4 (WK(t))
#define	sp			%esp							// unifying architectural stack pointer representation
#define HASH_PTR	stack_size+16+4(sp)				// use 1st input argument from caller function, 16 for (esi/edi/ebx/ebp)
#define cnt         stack_size+16+8(sp)				// use 2nd input argument from caller function
#define BUFFER_PTR	stack_size+16+12(sp)			// use 3rd input argument from caller function
#define K_BASE		stack_size-4(sp)				// use for K_BASE

#endif	// __x86_64__

// symbolizing registers or stack memory with algorithmic variables	W0,W4,...,W28 + W_TMP, W_TMP2, and XMM_SHUFB_BSWAP for code with ssse3 support

#define W_TMP  	%xmm0
#define W_TMP2 	%xmm1
#define W0  	%xmm2
#define W4  	%xmm3
#define W8  	%xmm4
#define W12 	%xmm5
#define W16 	%xmm6
#define W20 	%xmm7
#if defined(__x86_64__)
#define W24 	%xmm8
#define W28 	%xmm9
#define XMM_SHUFB_BSWAP %xmm10				// used only when ssse3 is supported
#else	// defined (__i386__)
#define W24     12*16(sp)
#define W28     13*16(sp)
#define XMM_SHUFB_BSWAP 14*16(sp)			// used only when ssse3 is supported
#endif

#define	xmov	movaps						// aligned 16-byte move
#define	xmovu	movups						// unaligned 16-byte move

// intermediate hash variables
#define A %ecx
#define B %esi
#define C %edi
#if defined(__x86_64__)
#define D %r15d
#else
#define D %ebp
#endif
#define E %edx

// temp variables
#define T1 %eax
#define T2 %ebx

#define WK(t)	((t)&15)*4(sp)

	// int F1(int B, int C, int D) { return (D ^ ( B & (C ^ D)); }
	// result in T1
	.macro	F1 arg0, arg1, arg2
	mov	\arg1, T1
	xor	\arg2, T1
	and	\arg0, T1
	xor	\arg2, T1
	.endm

	// int F2(int B, int C, int D) { return (D ^ B ^ C); }
	// result in T1
	.macro	F2 arg0, arg1, arg2
	mov	\arg2, T1
	xor	\arg1, T1
	xor	\arg0, T1
	.endm

	// int F3(int B, int C, int D) { return (B & C) | (D & (B ^ C)); }
	// result in T1
	.macro	F3 arg0, arg1, arg2
		mov \arg1, T1
        mov \arg0, T2
        or  \arg0, T1
        and \arg1, T2
        and \arg2, T1
        or  T2, T1
	.endm

	// for i=60:79, F4 is identical to F2
	#define	F4	F2


	/*
		i=0:15, W[i] = BIG_ENDIAN_LOAD(MESSAGE[i]);

		with ssse3 support, this is achived via
		for (i=0;i<16;i+=4) {
			1. W_TMP = new 16 bytes from MESSAGE[]
			2. W_TMP = pshufb(W_TMP, XMM_SHUFB_BSWAP); save to W circular buffer for updating W
			3. WTMP += {K,K,K,K};
			4. save quadruple W[i]+K[i] = W_TMP in the stack memory;
		}

		each step is represented in one of the following 4 macro definitions

	*/

	.macro	W_PRECALC_00_15_0_ssse3 arg0			// input argument $0 : 0/4/8/12
#if defined (__x86_64__)					// BUFFER_PTR is already an address register in x86_64
	xmovu	\arg0*4(BUFFER_PTR), W_TMP			// read 16-bytes into W_TMP, BUFFER_PTR possibly not 16-byte aligned
#else										// BUFFER_PTR is from the argument set up in the caller
	mov     BUFFER_PTR, T1					// T1 = BUFFER_PTR
    xmovu  \arg0*4(T1), W_TMP					// read 16-bytes into W_TMP, BUFFER_PTR possibly not 16-byte aligned
#endif
	.endm

	.macro	W_PRECALC_00_15_1_ssse3 arg0			// input argument $0 : current 16-bytes in the circular buffer, one of W0,W4,W8,...,W28
	pshufb	XMM_SHUFB_BSWAP, W_TMP			// convert W_TMP from little-endian into big-endian
	xmov	W_TMP, \arg0						// save W_TMP in the circular buffer
	.endm

	.macro	W_PRECALC_00_15_2				// K_BASE points to the current K quadruple.
#if defined (__x86_64__)					// K_BASE is already an address register in x86_64
	paddd	(K_BASE), W_TMP					// W_TMP += {K,K,K,K};
#else										// K_BASE is previously set up in the stack memory
	mov     K_BASE, T1						// T1 = K_BASE
    paddd   (T1), W_TMP						// W_TMP += {K,K,K,K};
#endif
	.endm

	.macro	W_PRECALC_00_15_3 arg0
	xmov	W_TMP, WK(\arg0&~3)				// save quadruple W[i]+K in the stack memory, which would be used later for updating the hashes A/B/C/D/E
	.endm

	// rounds 16-31 compute W[0] using the vectorization approach by Dean Gaudet
	/*
	W[i  ] = (W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]) rol 1
    W[i+1] = (W[i-2] ^ W[i-7] ^ W[i-13] ^ W[i-15]) rol 1
    W[i+2] = (W[i-1] ^ W[i-6] ^ W[i-12] ^ W[i-14]) rol 1
    W[i+3] = (   0   ^ W[i-5] ^ W[i-11] ^ W[i-13]) rol 1

	W[i+3] ^= W[i] rol 1;	// this W[i] is already rol by 1, if we are taking from the intial W before rol 1, we should rol this by 2

	The operation (updating W and W+K) is scheduled as and divided into 4 steps

	0. W_tmp = W3; W = W14 ^ W8
	1. W = W3 ^ W8 ^ W14 ^ W16; W_TMP = W; W_TMP2 = (W[i] 0 0 0);
	2. W_TMP = (W3 ^ W8 ^ W14 ^ W16) rol 1; split (W[i] 0 0 0) rol 2 in W_TMP2 and W
	3. W = W_TMP = W_TMP ^ W_TMP2 ^ W = (W3 ^ W8 ^ W14 ^ W16) rol 1 ^ (W[i] 0 0 0) rol 2; WK = W _TMP+K;

	*/

	.macro	W_PRECALC_16_31_0_ssse3 arg0, arg1, arg2, arg3, arg4	// input arguments : W16,W12,W8,W4,W
	xmov	\arg1, \arg4					// W = W12
	palignr	$8, \arg0, \arg4				// W = W14
	xmov	\arg3, W_TMP				// W_TMP = W4
	psrldq	$4, W_TMP				// W_TMP = W3
	pxor	\arg2, \arg4					// W = W8 ^ W14
	.endm

	.macro	W_PRECALC_16_31_1 arg0, arg1		// input arguments : W16,W
	pxor	\arg0, W_TMP				// W_TMP = W3 ^ W16
	pxor	W_TMP, \arg1				// W = W3 ^ W16 ^ W8 ^ W14
	xmov	\arg1, W_TMP2				// W_TMP2 = W3 ^ W16 ^ W8 ^ W14
	xmov	\arg1, W_TMP				// W_TMP = W3 ^ W16 ^ W8 ^ W14
	pslldq	$12, W_TMP2			// W_TMP2 = (W[i] 0 0 0)
	.endm

	.macro	W_PRECALC_16_31_2 arg0		// input argument : W
	psrld	$31, \arg0				// (W3 ^ W16 ^ W8 ^ W14)>>31
	pslld	$1, W_TMP				// (W3 ^ W16 ^ W8 ^ W14)<<1
	por		\arg0, W_TMP				// W_TMP = (W3 ^ W16 ^ W8 ^ W14) rol 1
	xmov	W_TMP2, \arg0				// copy W[i] at location of W[i+3]
	psrld	$30, W_TMP2			// W_TMP2 = W[i] lower 2 bits after rol 2
	pslld	$2, \arg0					// W = W[i] higher 30 bits after rol 2
	.endm

	.macro	W_PRECALC_16_31_3 arg0, arg1, arg2		// input arguments: W, i, K_XMM
#if defined (__i386__)
	mov     K_BASE, T1				// K_BASE is store in the stack memory for i386
#endif
	pxor	\arg0, W_TMP
	pxor	W_TMP2, W_TMP			// W_TMP = (W3 ^ W16 ^ W8 ^ W14) rol 1 ^ (W[i] 0 0 0) rol 2
	xmov	W_TMP, \arg0				// save W = W_TMP in the W circular buffer
#if defined (__x86_64__)
	paddd	\arg2(K_BASE), W_TMP		// W+K
#else
    paddd   \arg2(T1), W_TMP			// W+K
#endif
	xmov	W_TMP, WK(\arg1&~3)		// save WK = W+K for later update of the hashes A/B/C/D/E
	.endm

	/* rounds 32-79 compute W und W+K iusing the vectorization approach from the Intel article

		W = rotate_left(left_shift(concatenate(W8,W4),64) ^ W16 ^ W28 ^ W32, 2);

		where left_shift(concatenate(W8,W4),64) is equivalent to W6. Note also that W32 and W use the same register.


	0. W_tmp = W6; W = W28 ^ W32;
	1. W = W_tmp = W6 ^ W16 ^ W28 ^ W32;
	2. W_tmp = (W6 ^ W16 ^ W28 ^ W32) rol 2;
	3. W = W_Tmp; WK = W_tmp + K;

	*/


	.macro	W_PRECALC_32_79_0_ssse3 arg0, arg1, arg2, arg3		// inputr arguments : W28,W8,W4,W
	xmov	\arg2, W_TMP					// (w1 w2 w3 w4)
	pxor	\arg0, \arg3						// W = W28 ^ W32;
	palignr	$8, \arg1, W_TMP				// W_tmp = (w3 w4 w5 w6) = W6;
	.endm

	// this is a variant of W_PRECALC_32_79_0_ssse3 for i386 (as W24/W28 are stored in memory, not in registers)
	.macro  W_PRECALC_32_79_0_i386_ssse3 arg0, arg1, arg2, arg3	// input arguments : W28,W8,W4,W
    xmov    \arg3, W_TMP						// W32
    pxor    \arg0, W_TMP						// W28 ^ W32
    xmov    W_TMP, \arg3						// W = W28 ^ W32;
    xmov    \arg2, W_TMP						// W4
    palignr $8, \arg1, W_TMP					// W_tmp = (w3 w4 w5 w6) = W6;
    .endm

	.macro	W_PRECALC_32_79_1 arg0, arg1			// input arguments : W16,W
	pxor	\arg0, W_TMP					// W_tmp = W6 ^ W16
	pxor	\arg1, W_TMP					// W_tmp = W6 ^ W16 ^ W28 ^ W32
	xmov	W_TMP, \arg1					// W = W_tmp = W6 ^ W16 ^ W28 ^ W32
	.endm

	.macro	W_PRECALC_32_79_2 arg0			// input argument : W
	psrld	$30, \arg0					// W >> 30
	pslld	$2, W_TMP					// W << 2
	por		\arg0, W_TMP					// W_tmp = (W6 ^ W16 ^ W28 ^ W32) rol 2
	.endm

	// this is a variant of W_PRECALC_32_79_2 for i386 (as W24/W28 are stored in memory, not in registers)
	// this should be used when the input is either W24 or W28 on i386 architecture
    .macro  W_PRECALC_32_79_2_i386 arg0  	// input argument : W
    xmov    \arg0, W_TMP2					// W
    psrld   $30, W_TMP2				// W >> 30
    xmov    W_TMP2, \arg0					// save (W >> 30) at W
    pslld   $2, W_TMP					// W_tmp << 2
    por     \arg0, W_TMP					// W_tmp = (W6 ^ W16 ^ W28 ^ W32) rol 2
    .endm

	.macro	W_PRECALC_32_79_3 arg0, arg1, arg2			// input argument W, i, K_XMM
#if defined (__x86_64__)
	xmov	W_TMP, \arg0					// W = (W6 ^ W16 ^ W28 ^ W32) rol 2
	paddd	\arg2(K_BASE), W_TMP			// W + K
	xmov	W_TMP, WK(\arg1&~3)			// write W+K
#else
    mov     K_BASE, T1					// T1 = K_BASE (which is in the caller argument)
    xmov    W_TMP, \arg0					// W = (W6 ^ W16 ^ W28 ^ W32) rol 2
    paddd   \arg2(T1), W_TMP				// W_tmp = W + K
    xmov    W_TMP, WK(\arg1&~3)			// write WK
#endif
	.endm


	/* The hash update operation is completed by the following statements.

		A[i+1] = FN + E[i] + ROTATE_LEFT( A[i], 5 ) + WK(i);
        B[i+1] = A[i];
        C[i+1] = ROTATE_LEFT( B[i], 30 );
        D[i+1] = C[i];
        E[i+1] = D[i];

		Suppose we start with A0,B0,C0,D0,E0. The 1st iteration can be expressed as follows:

		A1 = FN + E0 + rol(A0,5) + WK;
		B1 = A0;
		C1 = rol(B0, 30);
		D1 = C0;
		E1 = D0;

		to avoid excessive memory movement between registers,
			1. A1 = FN + E0 + rol(A0,5) + WK; can be temporarily saved in E0,
			2. C1 = rol(B0,30) can be temporarily saved in B0.

		Therefore, ignoring the time index, the update operation is equivalent to
			1. E = FN(B,C,D) + E + rol(A,5) + WK(i)
			2. B = rol(B,30)
			3. the hashes are now stored in the order of E,A,B,C,D


		To pack 2 hash update operations in 1 iteration, starting with A,B,C,D,E
		1. E = FN(B,C,D) + E + rol(A,5) + WK(i)
		2. B = rol(B,30)
		// now the hashes are in the order of E,A,B,C,D
		3. D = FN(A,B,C) + D + rol(E,5) + WK(i+1)
		4. A = rol(A,30)
		// now the hashes are in the order of D,E,A,B,C

		These operations are distributed into the following 2 macro definitions RR0 and RR1.

	*/

	.macro	RR0 arg0, arg1, arg2, arg3, arg4, arg5, arg6				// input arguments : FN, A, B, C, D, E, i
	\arg0		\arg2, \arg3, \arg4		// T1 = FN(B,C,D)
	add		WK(\arg6), \arg5		// E + WK(i)
	rol		$30, \arg2		// B = rol(B,30)
	mov		\arg1, T2			// T2 = A
	add		WK(\arg6+1), \arg4	// D + WK(i+1)
	rol		$5, T2			// rol(A,5)
	add		T1, \arg5			// E = FN(B,C,D) + E + WK(i)
	.endm

	.macro	RR1 arg0, arg1, arg2, arg3, arg4, arg5, arg6
	add		\arg5, T2			// T2 = FN(B,C,D) + E + rol(A,5) + WK(i)
	mov		T2, \arg5			// E = FN(B,C,D) + E + rol(A,5) + WK(i)
	rol		$5, T2			// rol(E,5)
	add		T2, \arg4			// D + WK(i+1) + rol(E,5)
	\arg0		\arg1, \arg2, \arg3		// FN(A,B,C)
	add		T1, \arg4			// D = FN(A,B,C) + D + rol(E,5) + WK(i+1)
	rol		$30, \arg1		// A = rol(A,30)
	.endm



	/*

		The following macro definitions are used to expand code for the per-block sha1 operation.

			INITIAL_W_PRECALC_ssse3	: BIG_ENDIAN_LOAD(64 bytes block) into W (i=0:15) and store W+K into the stack memory
			INTERNAL_ssse3 : updating W (16:79) and update the digests A/B/C/D/E (i=0:63, based on W+K stored in the stack memory)
			ENDING : finishing up update the digests A/B/C/D/E (i=64:79)

		For multiple-block sha1 operation (Multiple_Blocks = 1), INITIAL_W_PRECALC_ssse3 and ENDING are combined
		into 1 macro definition for software pipeling.

			SOFTWARE_PIPELINING_ssse3 : BIG_ENDIAN_LOAD(64 bytes block) into W (i=0:15) and store W+K into the stack, and finishing up update the digests A/B/C/D/E (i=64:79)

		assume cnt (the number of blocks)  >= 1, the main code body should look like

		INITIAL_W_PRECALC_ssse3				// W = big_endian_load and pre-compute W+K (i=0:15)
		do {
			INTERNAL_ssse3					// update W(i=16:79), and update hash digests A/B/C/D/E (i=0:63)
			cnt--;
			if (cnt==0) break;
			BUFFER_PTR += 64;
			SOFTWARE_PIPELINING_ssse3;		// update hash digests A/B/C/D/E (i=64:79) + W = big_endian_load and pre-compute W+K (i=0:15)
		}
		ENDING								// update hash digests A/B/C/D/E (i=64:79)

	*/

	#define	W_PRECALC_00_15_0	W_PRECALC_00_15_0_ssse3
	#define	W_PRECALC_00_15_1	W_PRECALC_00_15_1_ssse3
	#define	W_PRECALC_16_31_0	W_PRECALC_16_31_0_ssse3
	#define	W_PRECALC_32_79_0	W_PRECALC_32_79_0_ssse3
	#define	W_PRECALC_32_79_0_i386	W_PRECALC_32_79_0_i386_ssse3


	.macro	INITIAL_W_PRECALC_ssse3			// BIG_ENDIAN_LOAD(64 bytes block) into W (i=0:15) and store W+K into the stack memory

	// i=0 	: W28,W24,W20,W16,W12,W8,W4,W0
	W_PRECALC_00_15_0	0					// W_TMP = (BUFFER_PTR)
	W_PRECALC_00_15_1	W0					// convert W_TMP to big-endian, and save W0 = W_TMP
	W_PRECALC_00_15_2						// W_TMP = W0 + K
	W_PRECALC_00_15_3	3					// (sp) = W_TMP = W0 + K

	// i=4	: W24,W20,W16,W12,W8,W4,W0,W28
	W_PRECALC_00_15_0	4					// W_TMP = 16(BUFFER_PTR)
	W_PRECALC_00_15_1	W28					// convert W_TMP to big-endian, and save W28 = W_TMP
	W_PRECALC_00_15_2						// W_TMP = W28 + K
	W_PRECALC_00_15_3	7					// 16(sp) = W_TMP = W28 + K

	// i=8  : W20,W16,W12,W8,W4,W0,W28,W24
	W_PRECALC_00_15_0	8					// W_TMP = 32(BUFFER_PTR)
	W_PRECALC_00_15_1	W24					// convert W_TMP to big-endian, and save W24 = W_TMP
	W_PRECALC_00_15_2						// W_TMP = W24 + K
	W_PRECALC_00_15_3	11					// 32(sp) = W_TMP = W24 + K

	// i=12 : W16,W12,W8,W4,W0,W28,W24,W20
	W_PRECALC_00_15_0	12					// W_TMP = 48(BUFFER_PTR)
	W_PRECALC_00_15_1	W20					// convert W_TMP to big-endian, and save W20 = W_TMP
	W_PRECALC_00_15_2						// W_TMP = W20 + K
	W_PRECALC_00_15_3	15					// 48(sp) = W_TMP = W20 + K

	.endm


	.macro	INTERNAL_ssse3					// updating W (16:79) and update the digests A/B/C/D/E (i=0:63, based on W+K stored in the stack memory)

	// i=16 : W12,W8,W4,W0,W28,W24,W20,W16
	W_PRECALC_16_31_0	W0,W28,W24,W20,W16
	RR0					F1,A,B,C,D,E,0
	W_PRECALC_16_31_1	W0,W16
	RR1					F1,A,B,C,D,E,0
	W_PRECALC_16_31_2	W16
	RR0					F1,D,E,A,B,C,2
	W_PRECALC_16_31_3	W16, 2, 0
	RR1					F1,D,E,A,B,C,2

	// i=20 : W8,W4,W0,W28,W24,W20,W16,W12
	W_PRECALC_16_31_0	W28,W24,W20,W16,W12
	RR0					F1,B,C,D,E,A,4
	W_PRECALC_16_31_1	W28,W12
	RR1					F1,B,C,D,E,A,4
	W_PRECALC_16_31_2	W12
	RR0					F1,E,A,B,C,D,6
	W_PRECALC_16_31_3	W12, 6, 16
	RR1					F1,E,A,B,C,D,6

	// i=24 : W4,W0,W28,W24,W20,W16,W12,W8
	W_PRECALC_16_31_0	W24,W20,W16,W12,W8
	RR0					F1,C,D,E,A,B,8
	W_PRECALC_16_31_1	W24,W8
	RR1					F1,C,D,E,A,B,8
	W_PRECALC_16_31_2	W8
	RR0					F1,A,B,C,D,E,10
	W_PRECALC_16_31_3	W8,10,16
	RR1					F1,A,B,C,D,E,10

	// i=28 : W0,W28,W24,W20,W16,W12,W8,W4
	W_PRECALC_16_31_0	W20,W16,W12,W8,W4
	RR0					F1,D,E,A,B,C,12
	W_PRECALC_16_31_1	W20,W4
	RR1					F1,D,E,A,B,C,12
	W_PRECALC_16_31_2	W4
	RR0					F1,B,C,D,E,A,14
	W_PRECALC_16_31_3	W4,14,16
	RR1					F1,B,C,D,E,A,14

	// i=32 : W28,W24,W20,W16,W12,W8,W4,W0
	W_PRECALC_32_79_0	W28,W8,W4,W0
	RR0					F1,E,A,B,C,D,16
	W_PRECALC_32_79_1	W16,W0
	RR1					F1,E,A,B,C,D,16
	W_PRECALC_32_79_2	W0
	RR0					F1,C,D,E,A,B,18
	W_PRECALC_32_79_3	W0,18,16
	RR1					F1,C,D,E,A,B,18

	// starting using F2

	// i=36 : W24,W20,W16,W12,W8,W4,W0,W28
#if defined (__x86_64__)
	W_PRECALC_32_79_0	W24,W4,W0,W28
#else
	W_PRECALC_32_79_0_i386	W24,W4,W0,W28
#endif
	RR0					F2,A,B,C,D,E,20
	W_PRECALC_32_79_1	W12,W28
	RR1					F2,A,B,C,D,E,20
#if defined (__x86_64__)
	W_PRECALC_32_79_2	W28
#else
	W_PRECALC_32_79_2_i386	W28
#endif
	RR0					F2,D,E,A,B,C,22
	W_PRECALC_32_79_3	W28,22,16
	RR1					F2,D,E,A,B,C,22

	// i=40 : W20,W16,W12,W8,W4,W0,W28,W24
	#undef  K_XMM
    #define K_XMM   32
#if defined (__x86_64__)
	W_PRECALC_32_79_0	W20,W0,W28,W24
#else
	W_PRECALC_32_79_0_i386	W20,W0,W28,W24
#endif
	RR0					F2,B,C,D,E,A,24
	W_PRECALC_32_79_1	W8,W24
	RR1					F2,B,C,D,E,A,24
#if defined (__x86_64__)
	W_PRECALC_32_79_2	W24
#else
	W_PRECALC_32_79_2_i386	W24
#endif
	RR0					F2,E,A,B,C,D,26
	W_PRECALC_32_79_3	W24,26,K_XMM
	RR1					F2,E,A,B,C,D,26

	// i=44 : W16,W12,W8,W4,W0,W28,W24,W20
	W_PRECALC_32_79_0	W16,W28,W24,W20
	RR0					F2,C,D,E,A,B,28
	W_PRECALC_32_79_1	W4,W20
	RR1					F2,C,D,E,A,B,28
	W_PRECALC_32_79_2	W20
	RR0					F2,A,B,C,D,E,30
	W_PRECALC_32_79_3	W20,30,K_XMM
	RR1					F2,A,B,C,D,E,30

	// i=48 : W12,W8,W4,W0,W28,W24,W20,W16
	W_PRECALC_32_79_0	W12,W24,W20,W16
	RR0					F2,D,E,A,B,C,32
	W_PRECALC_32_79_1	W0,W16
	RR1					F2,D,E,A,B,C,32
	W_PRECALC_32_79_2	W16
	RR0					F2,B,C,D,E,A,34
	W_PRECALC_32_79_3	W16,34,K_XMM
	RR1					F2,B,C,D,E,A,34

	// i=52 : W8,W4,W0,W28,W24,W20,W16,W12
	W_PRECALC_32_79_0	W8,W20,W16,W12
	RR0					F2,E,A,B,C,D,36
	W_PRECALC_32_79_1	W28,W12
	RR1					F2,E,A,B,C,D,36
	W_PRECALC_32_79_2	W12
	RR0					F2,C,D,E,A,B,38
	W_PRECALC_32_79_3	W12,38,K_XMM
	RR1					F2,C,D,E,A,B,38

	// starting using F3

	// i=56 : W4,W0,W28,W24,W20,W16,W12,W8
	W_PRECALC_32_79_0	W4,W16,W12,W8
	RR0					F3,A,B,C,D,E,40
	W_PRECALC_32_79_1	W24,W8
	RR1					F3,A,B,C,D,E,40
	W_PRECALC_32_79_2	W8
	RR0					F3,D,E,A,B,C,42
	W_PRECALC_32_79_3	W8,42,K_XMM
	RR1					F3,D,E,A,B,C,42

	// i=60 : W0,W28,W24,W20,W16,W12,W8,W4
	#undef	K_XMM
	#define	K_XMM	48
	W_PRECALC_32_79_0	W0,W12,W8,W4
	RR0					F3,B,C,D,E,A,44
	W_PRECALC_32_79_1	W20,W4
	RR1					F3,B,C,D,E,A,44
	W_PRECALC_32_79_2	W4
	RR0					F3,E,A,B,C,D,46
	W_PRECALC_32_79_3	W4,46,K_XMM
	RR1					F3,E,A,B,C,D,46

	// i=64 : W28,W24,W20,W16,W12,W8,W4,W0
	W_PRECALC_32_79_0	W28,W8,W4,W0
	RR0					F3,C,D,E,A,B,48
	W_PRECALC_32_79_1	W16,W0
	RR1					F3,C,D,E,A,B,48
	W_PRECALC_32_79_2	W0
	RR0					F3,A,B,C,D,E,50
	W_PRECALC_32_79_3	W0,50,K_XMM
	RR1					F3,A,B,C,D,E,50

	// i=68 : W24,W20,W16,W12,W8,W4,W0,W28
#if defined (__x86_64__)
	W_PRECALC_32_79_0	W24,W4,W0,W28
#else
	W_PRECALC_32_79_0_i386	W24,W4,W0,W28
#endif
	RR0					F3,D,E,A,B,C,52
	W_PRECALC_32_79_1	W12,W28
	RR1					F3,D,E,A,B,C,52
#if defined (__x86_64__)
	W_PRECALC_32_79_2	W28
#else
	W_PRECALC_32_79_2_i386	W28
#endif
	RR0					F3,B,C,D,E,A,54
	W_PRECALC_32_79_3	W28,54,K_XMM
	RR1					F3,B,C,D,E,A,54

	// i=72 : W20,W16,W12,W8,W4,W0,W28,W24
#if defined (__x86_64__)
	W_PRECALC_32_79_0	W20,W0,W28,W24
#else
	W_PRECALC_32_79_0_i386	W20,W0,W28,W24
#endif
	RR0					F3,E,A,B,C,D,56
	W_PRECALC_32_79_1	W8,W24
	RR1					F3,E,A,B,C,D,56
#if defined (__x86_64__)
	W_PRECALC_32_79_2	W24
#else
	W_PRECALC_32_79_2_i386	W24
#endif
	RR0					F3,C,D,E,A,B,58
	W_PRECALC_32_79_3	W24,58,K_XMM
	RR1					F3,C,D,E,A,B,58

	// starting using F4

	// i=76 : W16,W12,W8,W4,W0,W28,W24,W20
	W_PRECALC_32_79_0	W16,W28,W24,W20
	RR0					F4,A,B,C,D,E,60
	W_PRECALC_32_79_1	W4,W20
	RR1					F4,A,B,C,D,E,60
	W_PRECALC_32_79_2	W20
	RR0					F4,D,E,A,B,C,62
	W_PRECALC_32_79_3	W20,62,K_XMM
	RR1					F4,D,E,A,B,C,62

	.endm

	.macro	SOFTWARE_PIPELINING_ssse3
	// i=0  : W28,W24,W20,W16,W12,W8,W4,W0
	W_PRECALC_00_15_0	0					// W_TMP = (BUFFER_PTR)
	RR0					F4,B,C,D,E,A,64
	W_PRECALC_00_15_1	W0					// convert W_TMP to big-endian, and save W0 = W_TMP
	RR1					F4,B,C,D,E,A,64
	W_PRECALC_00_15_2						// W_TMP = W0 + K
	RR0					F4,E,A,B,C,D,66
	W_PRECALC_00_15_3	3					// (sp) = W_TMP = W0 + K
	RR1					F4,E,A,B,C,D,66

	// i=4  : W24,W20,W16,W12,W8,W4,W0,W28
	W_PRECALC_00_15_0	4					// W_TMP = 16(BUFFER_PTR)
	RR0					F4,C,D,E,A,B,68
	W_PRECALC_00_15_1	W28					// convert W_TMP to big-endian, and save W28 = W_TMP
	RR1					F4,C,D,E,A,B,68
	W_PRECALC_00_15_2						// W_TMP = W28 + K
	RR0					F4,A,B,C,D,E,70
	W_PRECALC_00_15_3	7					// 16(sp) = W_TMP = W28 + K[0]
	RR1					F4,A,B,C,D,E,70

	// i=8  : W20,W16,W12,W8,W4,W0,W28,W24
	W_PRECALC_00_15_0	8					// W_TMP = 32(BUFFER_PTR)
	RR0					F4,D,E,A,B,C,72
	W_PRECALC_00_15_1	W24					// convert W_TMP to big-endian, and save W24 = W_TMP
	RR1					F4,D,E,A,B,C,72
	W_PRECALC_00_15_2						// W_TMP = W24 + K
	RR0					F4,B,C,D,E,A,74
	W_PRECALC_00_15_3	11					// 32(sp) = W_TMP = W24 + K
	RR1					F4,B,C,D,E,A,74

	// i=12 : W16,W12,W8,W4,W0,W28,W24,W20
	W_PRECALC_00_15_0	12					// W_TMP = 48(BUFFER_PTR)
	RR0					F4,E,A,B,C,D,76
	W_PRECALC_00_15_1	W20					// convert W_TMP to big-endian, and save W20 = W_TMP
	RR1					F4,E,A,B,C,D,76
	W_PRECALC_00_15_2						// W_TMP = W20 + K
	RR0					F4,C,D,E,A,B,78
	W_PRECALC_00_15_3	15					// 48(sp) = W_TMP = W20 + K
	RR1					F4,C,D,E,A,B,78
	.endm


	#undef	W_PRECALC_00_15_0
	#undef	W_PRECALC_00_15_1
	#undef	W_PRECALC_16_31_0
	#undef	W_PRECALC_32_79_0
	#undef	W_PRECALC_32_79_0_i386

	.macro	ENDING		// finish up updating hash digests (i=64:79)
	//i=80
	RR0					F4,B,C,D,E,A,64
	RR1					F4,B,C,D,E,A,64
	RR0					F4,E,A,B,C,D,66
	RR1					F4,E,A,B,C,D,66

	//i=84
	RR0					F4,C,D,E,A,B,68
	RR1					F4,C,D,E,A,B,68
	RR0					F4,A,B,C,D,E,70
	RR1					F4,A,B,C,D,E,70

	//i=88
	RR0					F4,D,E,A,B,C,72
	RR1					F4,D,E,A,B,C,72
	RR0					F4,B,C,D,E,A,74
	RR1					F4,B,C,D,E,A,74

	//i=92
	RR0					F4,E,A,B,C,D,76
	RR1					F4,E,A,B,C,D,76
	RR0					F4,C,D,E,A,B,78
	RR1					F4,C,D,E,A,B,78
	.endm

	// load hash digests A,B,C,D,E from memory into registers
	.macro	LOAD_HASH
#if defined (__x86_64__)
	mov			(HASH_PTR), A
	mov			4(HASH_PTR), B
	mov			8(HASH_PTR), C
	mov			12(HASH_PTR), D
	mov			16(HASH_PTR), E
#else
    mov         HASH_PTR, T1
    mov         (T1), A
    mov         4(T1), B
    mov         8(T1), C
    mov         12(T1), D
    mov         16(T1), E
#endif
	.endm

	.macro	UPDATE_HASH arg0, arg1
	add		\arg0, \arg1
	mov		\arg1, \arg0
	.endm

	.macro UPDATE_ALL_HASH
#if defined (__x86_64__)
	UPDATE_HASH		(HASH_PTR), A
	UPDATE_HASH		4(HASH_PTR), B
	UPDATE_HASH		8(HASH_PTR), C
	UPDATE_HASH		12(HASH_PTR), D
	UPDATE_HASH		16(HASH_PTR), E
#else
    mov             HASH_PTR, T1
    UPDATE_HASH     (T1), A
    UPDATE_HASH     4(T1), B
    UPDATE_HASH     8(T1), C
    UPDATE_HASH     12(T1), D
    UPDATE_HASH     16(T1), E
#endif
	.endm


	/*
		 main sha1 code for system with ssse3 support
	*/

	.macro  SHA1_PIPELINED_MAIN_BODY_ssse3
	LOAD_HASH						// load initial hashes into A,B,C,D,E
	INITIAL_W_PRECALC_ssse3			// big_endian_load(W) and W+K (i=0:15)
	.p2align	4,0x90
0:
	INTERNAL_ssse3					// update W (i=16:79) and update ABCDE (i=0:63)
#if Multiple_Blocks
#if defined (__x86_64__)
	addq	_IMM(64), BUFFER_PTR			// BUFFER_PTR+=64;
	subq	_IMM(1), cnt					// pre-decrement cnt by 1
#else
	addl	_IMM(64), BUFFER_PTR			// BUFFER_PTR+=64;
	subl	_IMM(1), cnt					// pre-decrement cnt by 1
#endif
	jbe	1f							// if cnt <= 0, branch to finish off
	SOFTWARE_PIPELINING_ssse3		// update ABCDE (i=64:79) || big_endian_load(W) and W+K (i=0:15)
	UPDATE_ALL_HASH					// update output hashes
	jmp	0b							// repeat for next block
	.p2align	4,0x90
1:
#endif
	ENDING							// update ABCDE (i=64:79)
	UPDATE_ALL_HASH					// update output hashes
	.endm

/*
	I removed the cpu capabilities check.  The check is now down
	in C code and the appropriate version of the assembler code
	is selected.
*/
	.text
	.globl _AccelerateCrypto_SHA1_compress_ssse3
_AccelerateCrypto_SHA1_compress_ssse3:

	// start the sha1 code with ssse3 support

	// save callee-save registers
#if defined (__x86_64__)
	push	%rbp
    mov     %rsp, %rbp
	push	%rbx
	push	%r15
#else
    push    %ebx
    push    %ebp
    push    %esi
    push    %edi
#endif

	sub		$stack_size, sp					// allocate stack memory for use

	// save used xmm register if this is for kernel
#if BUILDKERNEL
	xmov	%xmm0, 4*16(sp)
	xmov	%xmm1, 5*16(sp)
	xmov	%xmm2, 6*16(sp)
	xmov	%xmm3, 7*16(sp)
	xmov	%xmm4, 8*16(sp)
	xmov	%xmm5, 9*16(sp)
	xmov	%xmm6, 10*16(sp)
	xmov	%xmm7, 11*16(sp)
#if defined (__x86_64__)
	xmov	%xmm8, 12*16(sp)
	xmov	%xmm9, 13*16(sp)
	xmov	%xmm10, 14*16(sp)
#endif
#endif

#if defined (__x86_64__)

	// set up registers to free %edx/%edi/%esi for other use (ABCDE)
	mov		ctx, HASH_PTR
	mov		buf, BUFFER_PTR
#if Multiple_Blocks
	mov		%rsi, cnt
#endif
	lea		K_XMM_AR(%rip), K_BASE
	xmov	0x40(K_BASE), XMM_SHUFB_BSWAP

#else	// __i386__

#if BUILDKERNEL
    lea     K_XMM_AR, %eax
#else
	// Get address of 0 in R.
           call    0f          // Push program counter onto stack.
        0: pop     %eax      // Get program counter.
		lea	K_XMM_AR-0b(%eax), %eax
#endif
    mov     %eax, K_BASE
    xmov    0x40(%eax), %xmm0
    xmov    %xmm0, XMM_SHUFB_BSWAP

#endif

	SHA1_PIPELINED_MAIN_BODY_ssse3

	// restore used xmm registers if this is for kernel
#if BUILDKERNEL
	xmov	4*16(sp), %xmm0
	xmov	5*16(sp), %xmm1
	xmov	6*16(sp), %xmm2
	xmov	7*16(sp), %xmm3
	xmov	8*16(sp), %xmm4
	xmov	9*16(sp), %xmm5
	xmov	10*16(sp), %xmm6
	xmov	11*16(sp), %xmm7
#if defined (__x86_64__)
	xmov	12*16(sp), %xmm8
	xmov	13*16(sp), %xmm9
	xmov	14*16(sp), %xmm10
#endif
#endif

	add		$stack_size, sp		// deallocate stack memory

	// restore callee-save registers
#if defined (__x86_64__)
	pop		%r15
	pop		%rbx
	pop		%rbp
#else
    pop     %edi
    pop     %esi
    pop     %ebp
    pop     %ebx
#endif

	ret							// return

	CC_ASM_SECTION_CONST
	.p2align	4, 0x90

#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

K_XMM_AR:
    .long	K1
	.long	K1
	.long	K1
	.long	K1
    .long	K2
	.long	K2
	.long	K2
	.long	K2
    .long	K3
	.long	K3
	.long	K3
	.long	K3
    .long	K4
	.long	K4
	.long	K4
	.long	K4
// bswap_shufb_ctl: accessed thru 0x40(K_XMM_AR)
    .long	0x00010203
    .long	0x04050607
    .long	0x08090a0b
    .long	0x0c0d0e0f


#endif	// architecture x86_64 or i386

#endif // (defined(__x86_64__) || defined(__i386__))

