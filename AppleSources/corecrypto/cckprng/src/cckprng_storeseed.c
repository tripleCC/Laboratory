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

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <corecrypto/cc.h>
#include "cc_macros.h"
#include <corecrypto/cckprng.h>

#if CC_LINUX
#error "Cannot use the corecrypto kernel RNG; use the built-in Linux kernel RNG instead"
#else
#include <sys/random.h>
#endif

#include "cckprng_internal.h"

int cckprng_storeseed(void)
{
    int err = CCERR_INTERNAL;
    int rc;
    int seedfd;
    uint8_t buf[CCKPRNG_SEEDSIZE];

    rc = getentropy(buf, sizeof(buf));
    if (rc  == -1) {
        err = CCKPRNG_GETENTROPY;
        goto out1;
    }

    seedfd = open(CCKPRNG_SEEDFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (seedfd == -1) {
        err = CCKPRNG_SEEDFILE_OPEN;
        goto out1;
    }

    rc = fchmod(seedfd, 0600);
    if (rc == -1) {
        err = CCKPRNG_SEEDFILE_CHMOD;
        goto out2;
    }

    rc = fchown(seedfd, 0, 0);
    if (rc == -1) {
        err = CCKPRNG_SEEDFILE_CHOWN;
        goto out2;
    }

    ssize_t m;
    for (size_t n = 0; n < sizeof(buf); n += (size_t)m) {
        m = write(seedfd, buf + n, sizeof(buf) - n);
        if (m == -1) {
            err = CCKPRNG_SEEDFILE_WRITE;
            goto out2;
        }
    }

    err = CCERR_OK;

 out2:
    close(seedfd);
 out1:
    cc_clear(sizeof(buf), buf);
    return err;
}
