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


#if defined(__x86_64__) && CCN_CMP_ASM

.text
.p2align 2

	.globl _ccn_cmp_asm
_ccn_cmp_asm: /* int ccn_cmp_asm(cc_size count, const cc_unit *s, const cc_unit *t); */

    #define count   %rdi
    #define s       %rsi
    #define t       %rdx
    #define ip      %r9
    #define x0      %rax
    #define x3      %rcx
    #define x5      %r8
    #define x6      %r10
    #define x7      %r11

    // push rbp and set up frame base
    pushq   %rbp
    movq    %rsp, %rbp


    xor     x0, x0                  // default output x0 = 0
    cmp     $0, count
    jle     1f                      // if count==0, early exit
    movq    $1, x6
    movq    $-1, x7
    xor     ip, ip
0:
    movq    (s, ip, 8), x3                 // read forward a new word
    movq    (t, ip, 8), x5                 // read forward a new word
    addq    $1, ip

    cmp     x5, x3
    cmova   x6, x0
    cmovb   x7, x0

    cmp     count, ip
    jl      0b

1:

    popq    %rbp
    ret

#endif /* CCN_CMP_ASM */
