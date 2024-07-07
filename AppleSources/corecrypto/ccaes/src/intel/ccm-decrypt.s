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


#if CCAES_INTEL_ASM && (defined(__x86_64__))


    /*
            SupplementalSSE3 implementation of ccm-decrypt functions

            void ccm128_decrypt(void *in, void *out, void *tag, int nblocks, void *key, void *ctr, int ctr_len);
            void ccm192_decrypt(void *in, void *out, void *tag, int nblocks, void *key, void *ctr, int ctr_len);
            void ccm256_decrypt(void *in, void *out, void *tag, int nblocks, void *key, void *ctr, int ctr_len);
    */


    .p2align  6
ONE:
    .quad 1,0
.Lbswap_mask:
    .byte 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
    .quad   0x00ffff, 0         // ctr_len = 2
    .quad   0x00ffffff, 0       // ctr_len = 3
    .quad   0x00ffffffff, 0     // ctr_len = 4
    .quad   0x00ffffffffff, 0     // ctr_len = 5
    .quad   0x00ffffffffffff, 0     // ctr_len = 6
    .quad   0x00ffffffffffffff, 0     // ctr_len = 7
    .quad   0xffffffffffffffff, 0     // ctr_len = 8


#define pin     %rdi
#define pout    %rsi
#define ptag    %rdx
#define nblocks %ecx
#define KS      %r8
#define pctr    %r9

#define in      %xmm0
#define tag     %xmm1
#define ctr     %xmm2
#define out     %xmm3
#define key     %xmm4
#define mask    %xmm5

    .macro  update_ctr_and_output_head
    movdqa  ctr, in
    movdqa  mask, ctr
    pandn   in, ctr                     // ctr now has part no need to update
    paddq   ONE(%rip), in
    pand    mask, in                    // in has the part of ctr_len bytes
    por     in, ctr
    movdqu  (pin), in
    movdqa  ctr, out
    pshufb  .Lbswap_mask(%rip), out     // byte swap back for aes_encrypt
    movdqu  (KS), key
    pxor    key, out
    movdqu  16*1(KS), key
    aesenc  key, out
    movdqu  16*2(KS), key
    aesenc  key, out
    movdqu  16*3(KS), key
    aesenc  key, out
    movdqu  16*4(KS), key
    aesenc  key, out
    movdqu  16*5(KS), key
    aesenc  key, out
    movdqu  16*6(KS), key
    aesenc  key, out
    movdqu  16*7(KS), key
    aesenc  key, out
    movdqu  16*8(KS), key
    aesenc  key, out
    movdqu  16*9(KS), key
    aesenc  key, out
    movdqu  16*10(KS), key
    .endm

    .macro  update_ctr_and_output_tail
    aesenclast  key, out
    pxor        in, out
    movdqu  out, (pout)
    add     _IMM(16), pin
    add     _IMM(16), pout
    .endm

    .macro  single_block_decrypt_head   // input in ctr and output in t
    movdqa  ctr, in
    movdqa  mask, ctr
    pandn   in, ctr                     // ctr now has part no need to update
    paddq   ONE(%rip), in
    pand    mask, in                    // in has the part of ctr_len bytes
    por     in, ctr
    movdqu  (pin), in
    pxor    out, tag                     // tag = tag ^ in;
    movdqa  ctr, out
    pshufb  .Lbswap_mask(%rip), out     // byte swap back for aes_encrypt
    movdqu  (KS), key
    pxor    key, tag
    pxor    key, out
    movdqu  16*1(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*2(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*3(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*4(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*5(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*6(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*7(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*8(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*9(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*10(KS), key
    .endm

    .macro  single_block_decrypt_tail
    aesenclast  key, tag
    aesenclast  key, out
    pxor        in, out
    movdqu  out, (pout)
    add     _IMM(16), pin
    add     _IMM(16), pout
    .endm

    .macro  final_tag_update_head        // input in ctr and output in t
    pxor    out, tag                     // tag = tag ^ in;
    movdqu  (KS), key
    pxor    key, tag
    movdqu  16*1(KS), key
    aesenc  key, tag
    movdqu  16*2(KS), key
    aesenc  key, tag
    movdqu  16*3(KS), key
    aesenc  key, tag
    movdqu  16*4(KS), key
    aesenc  key, tag
    movdqu  16*5(KS), key
    aesenc  key, tag
    movdqu  16*6(KS), key
    aesenc  key, tag
    movdqu  16*7(KS), key
    aesenc  key, tag
    movdqu  16*8(KS), key
    aesenc  key, tag
    movdqu  16*9(KS), key
    aesenc  key, tag
    movdqu  16*10(KS), key
    .endm

    .macro  final_tag_update_tail
    aesenclast  key, tag
    .endm

    .globl _ccm128_decrypt
    .p2align 4
_ccm128_decrypt:

    /* allocate stack memory */
    pushq %rbp
    movq   %rsp, %rbp   

#if CC_KERNEL
    sub    $16+6*16, %rsp
    andq   $-16, %rsp
    movdqa  %xmm0, 0*16(%rsp)
    movdqa  %xmm1, 1*16(%rsp)
    movdqa  %xmm2, 2*16(%rsp)
    movdqa  %xmm3, 3*16(%rsp)
    movdqa  %xmm4, 4*16(%rsp)
    movdqa  %xmm5, 5*16(%rsp)
#endif

    // load mask vector for modulo(ctr++);
    movl    16(%rbp), %eax
    shll    $4, %eax
    leaq    ONE(%rip), %r10
    movdqa  (%r10, %rax), mask
  
    // copy ctr/NR to registers
    movdqu  (pctr), ctr
    movdqu  (ptag), tag
  
    // byte swap ctr
    pshufb  .Lbswap_mask(%rip), ctr

    update_ctr_and_output_head
    update_ctr_and_output_tail

    sub      $1, nblocks
    je       9f // L_Decrypt_done

0:      // Main_Loop:

    single_block_decrypt_head
    single_block_decrypt_tail

    sub      $1, nblocks
    jg       0b     // Main_Loop

9:      // L_Decrypt_done:

    final_tag_update_head
    final_tag_update_tail

    // byte swap ctr and save to *ptr_ctx 
    pshufb  .Lbswap_mask(%rip), ctr
    movdqu  ctr, (pctr)
    movdqu  tag, (ptag)

#if CC_KERNEL
    movdqa  0*16(%rsp), %xmm0
    movdqa  1*16(%rsp), %xmm1
    movdqa  2*16(%rsp), %xmm2
    movdqa  3*16(%rsp), %xmm3
    movdqa  4*16(%rsp), %xmm4
    movdqa  5*16(%rsp), %xmm5
#endif    

    // restore rsp and return
    movq   %rbp, %rsp
    popq   %rbp
    ret


// ccm-192-decrypt

    .globl _ccm192_decrypt
    .p2align 4
_ccm192_decrypt:

    /* allocate stack memory */
    pushq %rbp
    movq   %rsp, %rbp   

#if CC_KERNEL
    sub    $16+6*16, %rsp
    andq   $-16, %rsp
    movdqa  %xmm0, 0*16(%rsp)
    movdqa  %xmm1, 1*16(%rsp)
    movdqa  %xmm2, 2*16(%rsp)
    movdqa  %xmm3, 3*16(%rsp)
    movdqa  %xmm4, 4*16(%rsp)
    movdqa  %xmm5, 5*16(%rsp)
#endif

    // load mask vector for modulo(ctr++);
    movl    16(%rbp), %eax
    shll    $4, %eax
    leaq    ONE(%rip), %r10
    movdqa  (%r10, %rax), mask
  
    // copy ctr/NR to registers
    movdqu  (pctr), ctr
    movdqu  (ptag), tag
  
    // byte swap ctr
    pshufb  .Lbswap_mask(%rip), ctr

    update_ctr_and_output_head
    aesenc  key, out
    movdqu  16*11(KS), key
    aesenc  key, out
    movdqu  16*12(KS), key
    update_ctr_and_output_tail

    sub      $1, nblocks
    je       9f // L_Decrypt_done

0:      // Main_Loop:

    single_block_decrypt_head
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*11(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*12(KS), key
    single_block_decrypt_tail

    sub      $1, nblocks
    jg       0b     // Main_Loop

9:      // L_Decrypt_done:

    final_tag_update_head
    aesenc  key, tag
    movdqu  16*11(KS), key
    aesenc  key, tag
    movdqu  16*12(KS), key
    final_tag_update_tail

    // byte swap ctr and save to *ptr_ctx 
    pshufb  .Lbswap_mask(%rip), ctr
    movdqu  ctr, (pctr)
    movdqu  tag, (ptag)

#if CC_KERNEL
    movdqa  0*16(%rsp), %xmm0
    movdqa  1*16(%rsp), %xmm1
    movdqa  2*16(%rsp), %xmm2
    movdqa  3*16(%rsp), %xmm3
    movdqa  4*16(%rsp), %xmm4
    movdqa  5*16(%rsp), %xmm5
#endif    

    // restore rsp and return
    movq   %rbp, %rsp
    popq   %rbp
    ret


// ccm-256-decrypt

    .globl _ccm256_decrypt
    .p2align 4
_ccm256_decrypt:

    /* allocate stack memory */
    pushq %rbp
    movq   %rsp, %rbp   

#if CC_KERNEL
    sub    $16+6*16, %rsp
    andq   $-16, %rsp
    movdqa  %xmm0, 0*16(%rsp)
    movdqa  %xmm1, 1*16(%rsp)
    movdqa  %xmm2, 2*16(%rsp)
    movdqa  %xmm3, 3*16(%rsp)
    movdqa  %xmm4, 4*16(%rsp)
    movdqa  %xmm5, 5*16(%rsp)
#endif

    // load mask vector for modulo(ctr++);
    movl    16(%rbp), %eax
    shll    $4, %eax
    leaq    ONE(%rip), %r10
    movdqa  (%r10, %rax), mask
  
    // copy ctr/NR to registers
    movdqu  (pctr), ctr
    movdqu  (ptag), tag
  
    // byte swap ctr
    pshufb  .Lbswap_mask(%rip), ctr

    update_ctr_and_output_head
    aesenc  key, out
    movdqu  16*11(KS), key
    aesenc  key, out
    movdqu  16*12(KS), key
    aesenc  key, out
    movdqu  16*13(KS), key
    aesenc  key, out
    movdqu  16*14(KS), key
    update_ctr_and_output_tail

    sub      $1, nblocks
    je       9f // L_Decrypt_done

0:      // Main_Loop:

    single_block_decrypt_head
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*11(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*12(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*13(KS), key
    aesenc  key, tag
    aesenc  key, out
    movdqu  16*14(KS), key
    single_block_decrypt_tail

    sub      $1, nblocks
    jg       0b     // Main_Loop

9:      // L_Decrypt_done:

    final_tag_update_head
    aesenc  key, tag
    movdqu  16*11(KS), key
    aesenc  key, tag
    movdqu  16*12(KS), key
    aesenc  key, tag
    movdqu  16*13(KS), key
    aesenc  key, tag
    movdqu  16*14(KS), key
    final_tag_update_tail

    // byte swap ctr and save to *ptr_ctx 
    pshufb  .Lbswap_mask(%rip), ctr
    movdqu  ctr, (pctr)
    movdqu  tag, (ptag)

#if CC_KERNEL
    movdqa  0*16(%rsp), %xmm0
    movdqa  1*16(%rsp), %xmm1
    movdqa  2*16(%rsp), %xmm2
    movdqa  3*16(%rsp), %xmm3
    movdqa  4*16(%rsp), %xmm4
    movdqa  5*16(%rsp), %xmm5
#endif    

    // restore rsp and return
    movq   %rbp, %rsp
    popq   %rbp
    ret


#endif  // __x86_64__

