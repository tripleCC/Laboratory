/* Copyright (c) (2018-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdio.h>
#include <sys/errno.h>
#include <sys/sysctl.h>

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include "cc_memory.h"
#include "cckprng_internal.h"
#include "ccrng_fortuna_internal.h"

#define ERR_LOADSEED 1
#define ERR_STORESEED 2
#define ERR_PRINTDIAG 4
#define ERR_LOAD_VIRTRAND 8

#include <IOKit/IOKitLib.h>

#if CC_BRIDGE
#define kAppleVirtIOEntropyClassName "ignore"
#define kAVIOEntropyGetRandomBytes 0
#else
#include <IOKit/AppleVirtIO/AppleVirtIOEntropyConnect.h>
#endif

static int load_virtrand(void)
{
    int err = CCERR_INTERNAL;
    kern_return_t kr = kIOReturnError;

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(kAppleVirtIOEntropyClassName));
    if (!service) {
        err = CCERR_IOSERVICE_GETMATCHING;
        goto out1;
    }

    io_connect_t port = (io_connect_t)0;
    kr = IOServiceOpen(service, mach_task_self(), 0, &port);
    IOObjectRelease(service);
    if (kr != kIOReturnSuccess) {
        printf("ServiceOpen failed %x\n", kr);
        err = CCERR_IOSERVICE_OPEN;
        goto out1;
    }

    uint8_t buf[32] = { 0 };
    size_t buf_size = sizeof(buf);

    kr = IOConnectCallStructMethod((mach_port_t)port, (uint32_t)kAVIOEntropyGetRandomBytes,
                                   NULL, 0,
                                   buf, &buf_size);
    if (kr != kIOReturnSuccess) {
        printf("CallStructMethod failed %x\n", kr);
        err = CCERR_IOCONNECT_CALL;
        goto out2;
    }

    int fd = open(CCKPRNG_RANDOMDEV, O_WRONLY);
    if (fd == -1) {
        err = CCKPRNG_RANDOMDEV_OPEN;
        goto out2;
    }

    for (size_t i = 0; i < buf_size;) {
        ssize_t m = write(fd, &buf[i], sizeof(buf) - i);
        if (m == -1) {
            err = CCKPRNG_RANDOMDEV_WRITE;
            goto out3;
        }

        i += (size_t)m;
    }

    err = CCERR_OK;

 out3:
    close(fd);
 out2:
    IOServiceClose(port);
 out1:
    if (err != CCERR_OK) {
        printf("failed to load virtual random: (%d) (%d)\n", err, kr);
        return ERR_LOAD_VIRTRAND;
    }

    return 0;
}

static int printsysctl(void)
{
    int err;
    uint64_t value;
    size_t value_size = sizeof(value);
    const char *names[] = {
        "kern.prng.user_reseed_count",
        "kern.prng.scheduled_reseed_count",
        "kern.prng.scheduled_reseed_max_sample_count",
        "kern.prng.entropy_max_sample_count",
    };

    for (size_t i = 0; i < CC_ARRAY_LEN(names); i += 1) {
        const char *name = names[i];

        err = sysctlbyname(name, &value, &value_size, NULL, 0);
        if (err != 0) {
            fprintf(stderr, "%s: (%d) (%d) %s\n", name, err, errno, strerror(errno));
            return ERR_PRINTDIAG;
        }

        fprintf(stderr, "%s: %llu\n", name, value);
    }

    for (size_t i = 0; i < CCRNG_FORTUNA_NPOOLS; i += 1) {
        const char *const fmt = "kern.prng.pool%zu.%s";
        char name[256];

        const char *fields[] = {
            "sample_count",
            "drain_count",
            "max_sample_count",
        };

        for (size_t j = 0; j < CC_ARRAY_LEN(fields); j += 1) {
            const char *field = fields[j];
            snprintf(name, sizeof(name), fmt, i, field);

            err = sysctlbyname(name, &value, &value_size, NULL, 0);
            if (err != 0) {
                fprintf(stderr, "%s: (%d) (%d) %s\n", name, err, errno, strerror(errno));
                return ERR_PRINTDIAG;
            }

            fprintf(stderr, "%s: %llu\n", name, value);
        }
    }

    return 0;
}

static int loadseed(void)
{
    int err;

    err = cckprng_loadseed();
    if (err != CCERR_OK) {
        fprintf(stderr, "failed to load kernel prng seed: (%d) (%d) %s\n", err, errno, strerror(errno));
        return ERR_LOADSEED;
    }

    return 0;
}

static int storeseed(void)
{
    int err;

    err = cckprng_storeseed();
    if (err != CCERR_OK) {
        fprintf(stderr, "failed to store kernel prng seed: (%d) (%d) %s\n", err, errno, strerror(errno));
        return ERR_STORESEED;
    }

    return 0;
}

int main(void)
{
    int err;

    err = printsysctl();
    err |= loadseed();
    err |= load_virtrand();
    err |= storeseed();

    return err;
}
