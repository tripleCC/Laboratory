/* Copyright (c) (2016-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef cc_absolute_time_h
#define cc_absolute_time_h

#include <corecrypto/cc_config.h>
#include <stdint.h>

// For more info on mach_absolute_time() precision:
//     https://developer.apple.com/library/mac/qa/qa1398/_index.html

#define CC_NSEC_PER_USEC ((uint64_t)1000)
#define CC_NSEC_PER_MSEC (1000 * CC_NSEC_PER_USEC)
#define CC_NSEC_PER_SEC (1000 * CC_NSEC_PER_MSEC)

#define cc_absolute_time_to_msec(t) (cc_absolute_time_to_nsec(t) / CC_NSEC_PER_MSEC)
#define cc_absolute_time_to_usec(t) (cc_absolute_time_to_nsec(t) / CC_NSEC_PER_USEC)
#define cc_absolute_time_to_sec(t) (cc_absolute_time_to_nsec(t) / CC_NSEC_PER_SEC)

#if CC_USE_L4
    #include <ert/time.h>
    #define cc_absolute_time() ert_time_now()

    #define cc_absolute_time_to_nsec(t) (t)
#elif CC_KERNEL
    #include <mach/mach_time.h>
    #include <kern/clock.h>
    #define cc_absolute_time() (mach_absolute_time())

    #define cc_absolute_time_to_nsec(t) ({                              \
        struct mach_timebase_info info;                                 \
        clock_timebase_info(&info);                                     \
        (t) * info.numer / info.denom;                                  \
    })
#elif CC_DARWIN
    #include <mach/mach_time.h>
    #define cc_absolute_time() (mach_absolute_time())

    #define cc_absolute_time_to_nsec(t) ({                              \
        struct mach_timebase_info info;                                 \
        mach_timebase_info(&info);                                      \
        (t) * info.numer / info.denom;                                  \
    })
#elif defined(_WIN32)
    #include <windows.h>
    #define cc_absolute_time() ({                               \
        LARGE_INTEGER time;                                     \
        QueryPerformanceCounter(&time);                         \
        (uint64_t)time.QuadPart;                                \
    })

    #define cc_absolute_time_to_nsec(t) ({                              \
        LARGE_INTEGER freq;                                             \
        QueryPerformanceFrequency(&freq);                               \
        (t) * CC_NSEC_PER_SEC / freq.QuadPart;                          \
    })
#elif CC_LINUX
    // The following is specific to non x86 (arm/mips/etc...) architectures on Linux.
    #warning cc_absolute_time() has not been tested
    #include <time.h>
    CC_INLINE uint64_t cc_absolute_time() {
       struct timespec tm;
       clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tm);
       return tm.tv_sec * CC_NSEC_PER_SEC + tm.tv_nsec;
    }
    #define cc_absolute_time_to_nsec(t) (t)

#else
    #warning Target OS is not defined. There should be a definition for cc_absolute_time() for the target OS/platform.
#endif

#endif /* cc_absolute_time_h */
