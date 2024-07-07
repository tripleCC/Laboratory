/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_FORTUNA_INTERNAL_H_
#define _CORECRYPTO_CCRNG_FORTUNA_INTERNAL_H_

#include <corecrypto/cc.h>
#include "ccrng_fortuna.h"

/*
 Internal Fortuna
 */

#define CCRNG_FORTUNA_LABEL(op) { 0x78, 0x6e, 0x75, 0x70, 0x72, 0x6e, 0x67, op }

enum CCRNG_FORTUNA_OP {
    CCRNG_FORTUNA_OP_SCHEDRESEED = 2,
    CCRNG_FORTUNA_OP_ADDENTROPY = 3,
};

#endif /* _CORECRYPTO_CCRNG_FORTUNA_INTERNAL_H_ */
