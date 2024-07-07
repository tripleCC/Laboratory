# Copyright (c) (2010,2011,2015,2016,2018,2019,2021,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if CC_ARM_ARCH_7 && CCN_ADD1_ASM

.text
.align 2
.syntax unified
.code 16
.thumb_func
.globl _ccn_add1_asm

_ccn_add1_asm: // cc_unit ccn_add1_asm(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v);
  cbz r0, L_zero

  ldr ip, [r2], #4
  adds r3, ip, r3
  str r3, [r1], #4

L_loop:
  sub r0, #1
  cbz r0, L_done

  ldr ip, [r2], #4
  adcs r3, ip, #0
  str r3, [r1], #4

  b L_loop

L_done:
  adc r0, r0, #0
  bx lr

L_zero:
  mov r0, r3
  bx lr

#endif /* CCN_ADD1_ASM */
