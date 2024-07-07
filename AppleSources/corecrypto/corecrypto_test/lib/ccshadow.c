/* Copyright (c) (2018,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#define _GNU_SOURCE // Needed as RTLD_NEXT is not defined by the posix standard
#include <dlfcn.h>

#define CCSHADOW_FULL_DECL(funcname, rettype, paramlist, arglist, ret)  \
                                                                        \
    rettype (*funcname##_mock) paramlist;                               \
    rettype (*funcname##_real) paramlist;                               \
                                                                        \
    rettype funcname paramlist;                                         \
                                                                        \
    rettype funcname paramlist                                          \
    {                                                                   \
        if (funcname##_mock != NULL) {                                  \
            ret funcname##_mock arglist;                                \
        } else {                                                        \
            if (funcname##_real == NULL) {                              \
                funcname##_real = dlsym(RTLD_NEXT, #funcname);          \
            }                                                           \
                                                                        \
            ret funcname##_real arglist;                                \
        }                                                               \
    }                                                                   \
                                                                        \
    enum { ccshadow_##funcname##_dummyenum } // Require a semicolon after macro invocations


#define CCSHADOW_DECL(funcname, rettype, paramlist, arglist)            \
        CCSHADOW_FULL_DECL(funcname, rettype, paramlist, arglist, return)

#define CCSHADOW_VOID_DECL(funcname, paramlist, arglist)                \
        CCSHADOW_FULL_DECL(funcname, void, paramlist, arglist,)

#include "../include/ccshadow_decls.h"
