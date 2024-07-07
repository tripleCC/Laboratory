/* Copyright (c) (2015,2016,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"

//cc_abort() is implemented to comply with by FIPS 140-2, when DRBG produces
//two equal consecutive blocks.

#if !CC_PROVIDES_ABORT

#error "This environment does not provide an abort()/panic()-like function"

#elif CC_KERNEL

#include <kern/debug.h>
void cc_abort(const char * msg)
{
    panic("%s", msg);
}

#elif CC_USE_L4

#include <sys/panic.h>
#include <stdarg.h>
void cc_abort(const char * msg)
{
    sys_panic(msg);
}

#elif CC_RTKIT

#include <RTK_platform.h>
void cc_abort(const char * msg)
{
    RTK_abort("%s", msg);
}

#else

#if CC_BUILT_FOR_TESTING
void (*cc_abort_mock)(const char *msg);
#endif

#include <stdlib.h>
void cc_abort(CC_UNUSED const char *msg)
{
    
#if CC_BUILT_FOR_TESTING
    if (cc_abort_mock) {
        cc_abort_mock(msg);
    }
#endif

    abort();
}

#endif
