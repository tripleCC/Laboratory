/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
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
#include <sys/uio.h>

#include <corecrypto/cc.h>
#include "cc_macros.h"
#include <corecrypto/cckprng.h>

#include "cckprng_internal.h"

int cckprng_loadseed(void)
{
    int err = CCERR_INTERNAL;
    int seedfd, randomfd;
    uint8_t buf[CCKPRNG_SEEDSIZE];

    seedfd = open(CCKPRNG_SEEDFILE, O_RDONLY);
    if (seedfd == -1) {
        err = CCKPRNG_SEEDFILE_OPEN;
        goto out1;
    }

    randomfd = open(CCKPRNG_RANDOMDEV, O_WRONLY);
    if (randomfd == -1) {
        err = CCKPRNG_RANDOMDEV_OPEN;
        goto out2;
    }

    for (;;) {
        ssize_t m, n;
        size_t i;

        n = read(seedfd, buf, sizeof(buf));
        if (n == -1) {
            err = CCKPRNG_SEEDFILE_READ;
            goto out3;
        } else if (n == 0) {
            err = CCERR_OK;
            goto out3;
        }

        i = 0;
        while (n > 0) {
            m = write(randomfd, &buf[i], (size_t)n);
            if (m == -1) {
                err = CCKPRNG_RANDOMDEV_WRITE;
                goto out3;
            }

            i += (size_t)m;
            n -= m;
        }
    }

out3:
    cc_clear(sizeof(buf), buf);
    close(randomfd);
out2:
    close(seedfd);
out1:
    return err;
}
