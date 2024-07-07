# Copyright (c) (2015-2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


//  This file implements schoolbook multiplication implemented for arm64.
//  Pseudo-code in C:
//
//    cc_dunit mulAdd2(cc_unit a, cc_unit b, cc_unit c, cc_unit d) { return (cc_dunit)a*b + c + d; }
//    cc_unit hi(cc_dunit a) { return a >> CCN_UNIT_BITS; }
//    cc_unit lo(cc_dunit a) { return a; }
//
//    void ccn_mul(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
//      cc_unit c = 0;
//      for (cc_size j=0; j<n; ++j) {
//        cc_dunit p = mulAdd2(s[j], t[0], 0, c);
//        r[j] = lo(p);
//        c = hi(p);
//      }
//      r[n] = c;
//      for (cc_size i=1; i<n; ++i) {
//        c = 0;
//        for (cc_size j=0; j<n; ++j) {
//          cc_dunit p = mulAdd2(s[j], t[i], r[i+j], c);
//          r[i+j] = lo(p);
//          c = hi(p);
//        }
//        r[i+n] = c;
//      }
//    }



#if defined __arm64__ && CCN_MUL_ASM

#include "ccarm_pac_bti_macros.h"

#define n  x0
#define r  x1
#define s  x2
#define t  x3
#define ti x4
#define sj x5
#define p  x6
#define q  x7
#define c  x8
#define j  x9
#define i  x10

.align 4
.globl _ccn_mul
_ccn_mul:
    SIGN_LR
//  Establish a stack frame and early out if n is zero.
    stp     fp, lr, [sp, #-16]!
    mov     fp, sp
    cbz     n,      L_exit
//  Scale n by 8 to convert elements to bytes and negate so that we can use
//  negative indexing that counts up to zero, avoiding an extra compare in our
//  loops; advance r, s, and t to point to the nth element of the corresponding
//  buffers to be compatible with this scheme.
    neg     n,      n,  lsl #3
    sub     r,      r,  n
    sub     s,      s,  n
    sub     t,      t,  n
//  First multiplication loop; we compute the (n+1)-word product s[0...n]*t[0]
//  and store it to the low-order n+1 words of r.  Before the loop starts, we
//  need to set up a counter, zero out a c register (since there is no
//  c-in to the low partial product), and load t[0].
    mov     i,      n
    mov     j,      n
    mov     c,      xzr
    ldr     ti,    [t,i]
//  In the loop itself, we load a word from s, compute the full product with
//  t[0], add the high part of the previous multiplication, and store the
//  result to r.
L_sj_t0_product:
    ldr     sj,    [s,j]
    mul     p,      sj, ti
    umulh   q,      sj, ti
    adds    p,      p,  c
    adc     q,      q,  xzr
    str     p,     [r,j]
    mov     c,      q
    adds    j,      j,  #8
    b.ne    L_sj_t0_product
//  Store the remaining high word of the product we just computed; decrement
//  the outer-loop counter and exit if we have run out of words in t.
L_loop_over_i:
    str     c, [r]
    adds    i,      i,  #8
    b.eq    L_exit
//  More work remains to be done; load the next word of t, and add its product
//  with s to the accumulated buffer.  This code is essentially identical
//  to the s * t0 product above, except that we need to add the corresponding
//  already-computed word from the result buffer to each partial product.
    add     r,      r,  #8
    mov     j,      n
    mov     c,      xzr
    ldr     ti,    [t,i]
L_sj_ti_product:
//  Main work loop: compute the partial product p:q = s[j]*t[i] + r[i+j] + c.
//  The low part of the result (p) is stored back to r[i+j].  The high part
//  of the result (q) becomes c for the next iteration.
    ldr     sj,    [s,j]
    mul     p,      sj, ti
    umulh   q,      sj, ti
    adds    p,      p,  c
    adc     q,      q,  xzr
    ldr     c,     [r,j]
    adds    p,      p,  c
    adc     q,      q,  xzr
    str     p,     [r,j]
    mov     c,      q
    adds    j,      j,  #8
    b.ne    L_sj_ti_product
    b       L_loop_over_i
L_exit:
    ldp     fp, lr, [sp], #16
    AUTH_LR_AND_RET

#endif // defined __arm64__ && CCN_MUL_ASM
