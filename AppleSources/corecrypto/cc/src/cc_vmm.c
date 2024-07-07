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

#include <sys/sysctl.h>

bool cc_is_vmm_present(void)
{
    int status;
    int vmm_present;

    size_t vmm_present_size = sizeof(vmm_present);
    status = sysctlbyname("kern.hv_vmm_present", &vmm_present, &vmm_present_size, NULL, 0);
    if (status == 0 && vmm_present == 1) {
        return true;
    }

    return false;
}

#else

bool cc_is_vmm_present(void)
{
    return false;
}

#endif
