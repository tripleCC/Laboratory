/* Copyright (c) (2011,2015,2016,2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCARM_PAC_BTI_MACROS_H_
#define _CORECRYPTO_CCARM_PAC_BTI_MACROS_H_

/*
 * This file defines commonly used macros in handwritten assembly
 * for making functions BTI and PAC compatible.
 */

#ifndef __arm64e__
#define __arm64e__ 0
#endif

.macro SIGN_LR
#if __arm64e__
        pacibsp
#endif
.endmacro

.macro AUTH_LR_AND_RET
#if __arm64e__
        retab
#else
        ret
#endif
.endmacro

.macro BRANCH_TARGET_CALL
#if __arm64e__
        hint #34 /* bti c */
#endif
.endmacro



#endif /* _CORECRYPTO_CCARM_PAC_BTI_MACROS_H_ */
