/* Copyright (c) (2012,2015-2017,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_FIPSPOST_H_
#define _CORECRYPTO_FIPSPOST_H_

#include <stdint.h>
#include <corecrypto/cc_config.h>

// Boot-Arg fips_mode Flags
//
// When performing tests, if _FORCEFAIL is set to true, then the tests
// intentionally fail and log their failure. The kernelspace and userspace
// flags can be enabled independently.
//
// If it's not desired to panic, supply the _NOPANIC flag with the
// _FORCEFAIL flag.
//
// _NOINTEG is used to ignore just the results of the module integrity
// check process, which is very useful when setting breakpoints in the
// kext for diagnostic or auditing purposes.
//
// Supplying _TRACE causes a trace buffer to be accumulated of the instrumented
// functions for only one execution of the POST.  As the POST finishes, the
// _TRACE flag is cleared from the fips_mode and no further tracing will occur.
//
// The _DEBUG, _FULL and _VERBOSE flags are obsolete.

//      FIPS_MODE_FLAG_DEBUG        0x001    0b000000001
//      FIPS_MODE_FLAG_FULL         0x002    0b000000010
#define FIPS_MODE_FLAG_DISABLE      0x004 // 0b000000100
//      FIPS_MODE_FLAG_VERBOSE      0x008    0b000001000
#define FIPS_MODE_FLAG_US_FORCEFAIL 0x010 // 0b000010000
#define FIPS_MODE_FLAG_KS_FORCEFAIL 0x020 // 0b000100000
#define FIPS_MODE_FLAG_NOINTEG      0x040 // 0b001000000
#define FIPS_MODE_FLAG_TRACE        0x080 // 0b010000000
#define FIPS_MODE_FLAG_NOPANIC      0x100 // 0b100000000

#define FIPS_MODE_IS_DISABLE(MODE)      ((MODE) & FIPS_MODE_FLAG_DISABLE)
#define FIPS_MODE_IS_US_FORCEFAIL(MODE) ((MODE) & FIPS_MODE_FLAG_US_FORCEFAIL)
#define FIPS_MODE_IS_KS_FORCEFAIL(MODE) ((MODE) & FIPS_MODE_FLAG_KS_FORCEFAIL)
#define FIPS_MODE_IS_NOINTEG(MODE)      ((MODE) & FIPS_MODE_FLAG_NOINTEG)
#define FIPS_MODE_IS_TRACE(MODE)        ((MODE) & FIPS_MODE_FLAG_TRACE)
#define FIPS_MODE_IS_NOPANIC(MODE)      ((MODE) & FIPS_MODE_FLAG_NOPANIC)

#if CC_KERNEL
#define FIPS_MODE_FLAG_FORCEFAIL        FIPS_MODE_FLAG_KS_FORCEFAIL
#define FIPS_MODE_IS_FORCEFAIL(MODE)    FIPS_MODE_IS_KS_FORCEFAIL(MODE)
#else
#define FIPS_MODE_FLAG_FORCEFAIL        FIPS_MODE_FLAG_US_FORCEFAIL
#define FIPS_MODE_IS_FORCEFAIL(MODE)    FIPS_MODE_IS_US_FORCEFAIL(MODE)
#endif

struct mach_header;

/*
 * Entrypoint for all POST tests.
 */
int fipspost_post(uint32_t fips_mode, struct mach_header *pmach_header);

#endif /* _CORECRYPTO_FIPSPOST_H_ */
