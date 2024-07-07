/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef CCSHADOW_H
#define CCSHADOW_H

#define CCSHADOW_DECL(funcname, rettype, paramlist, arglist)            \
                                                                        \
    extern rettype (*funcname##_mock) paramlist;                        \
    extern rettype (*funcname##_real) paramlist;                        \
                                                                        \
    enum { ccshadow_##funcname##_dummyenum } // Require a semicolon after macro invocations


#define CCSHADOW_VOID_DECL(funcname,  paramlist, arglist)   \
    CCSHADOW_DECL(funcname, void, paramlist, arglist)

#include "ccshadow_decls.h"

#undef CCSHADOW_DECL

#endif /* CCSHADOW_H */
