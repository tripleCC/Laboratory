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


#if defined(__x86_64__) && CCN_N_ASM

.text
.p2align 2

	.globl _ccn_n_asm

_ccn_n_asm: /* cc_size ccn_n_asm(cc_size count, const cc_unit *s); */

    #define count   %rdi
    #define s       %rsi
    #define ip      %rdx
    #define r0      %rax
    #define r3      %rcx
    #define r2      %r8

    // push rbp and set up frame base
    pushq   %rbp
    movq    %rsp, %rbp


    xor     r0, r0                  // default output r0 = 0
    cmp     $0, count
    jle     1f                      // if count==0, early exit
    xor     r3, r3                  // r3 = 0 indicates string is still zero
0:
    movq    (s, r3, 8), r2          // read forward a new word
    addq    $1, r3                  // i++
    cmp     $0, r2                  // test whether input word is zero
    cmovne  r3, r0                  // the last count s.t. s[count]!=0

    cmp     count, r3
    jl      0b

1:

    popq    %rbp
    ret

#endif /* CCN_N_ASM */
