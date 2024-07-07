# Copyright (c) (2019,2020,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#if defined(__arm64__) && defined(__ARM_NEON) && defined(__ARM_FEATURE_AES)
#include "arm64_isa_compatibility.h"
#include "ccarm_pac_bti_macros.h"
	// per block
	#define in      x0
    #define out     x1
    #define key     x2
    #define keylen  x3
    #define t       x5


.subsections_via_symbols
	.text	
	.p2align	4
	    .globl _AccelerateCrypto_AES_decrypt
_AccelerateCrypto_AES_decrypt:
	BRANCH_TARGET_CALL
#if BUILDKERNEL
	// save used vector registers
	sub		sp, sp, #3*16
	st1.4s		{v0,v1,v2}, [sp]
#endif

    ldr     w3, [key, #240]         // keylength = 32-bit
    ldr     q0, [in]                // plain data
    mov     t, keylen
    ldr     q1, [key, t]		        // expanded key
	sub		t, t, #16
    ldr     q2, [key]               // expanded key
0:
    AESD    0, 1
    AESIMC   0, 0
    ldr     q1, [key, t]				// expanded key
    subs    t, t, #16
    b.gt    0b
    AESD    0, 1
    eor.16b v0, v0, v2
    str     q0, [out]

#if BUILDKERNEL
	// restore used vector registers
	ld1.4s		{v0,v1,v2}, [sp], #48
#endif

    mov     x0, #0
    ret     lr

	#undef in
    #undef out
    #undef key
    #undef keylen


#endif

