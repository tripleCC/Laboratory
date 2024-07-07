/* Copyright (c) (2022) Apple Inc. All rights reserved.
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

#if CC_DARWIN

#include <crt_externs.h>
#include <mach-o/utils.h>

const char *cc_current_arch(void)
{
    const struct mach_header *header = (const struct mach_header *)_NSGetMachExecuteHeader();
    const char *name = macho_arch_name_for_mach_header(header);
    return name ? name : "unknown";
}

#else

const char *cc_current_arch(void)
{
    return "unknown";
}

#endif
