/* Copyright (c) (2010,2012-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>
#include "ccrng_internal.h"
#include <corecrypto/cc.h>
#include "cc_debug.h"
#include "cc_memory.h"
#include "ccrng_getentropy.h"

// This file defines cc_get_entropy() for these environments:
// - OSX/iOS kernel
// - OSX/iOS
// - Linux
// - Windows

//==============================================================================
//
//      KERNEL
//
//==============================================================================

#if CC_KERNEL

#include <sys/types.h>
#include <sys/random.h>
#include <sys/attr.h>

int cc_get_entropy(size_t entropy_size, void *entropy)
{
    if (entropy_size>UINT_MAX) {
        return CCERR_OVERFLOW;
    }
    read_random(entropy, (u_int)entropy_size);
    return 0;
}

#elif CC_GETENTROPY_SUPPORTED

//==============================================================================
//
//      Darwin OSX >= 10.12 and iOS >= 10
//      This is checked with CC_DARWIN because this version of the library
//      will not be built against old OS
//
//==============================================================================

int cc_get_entropy(size_t entropy_size, void *entropy)
{
    return ccrng_generate(&ccrng_getentropy, entropy_size, entropy);
}

#elif CC_LINUX

//==============================================================================
//
//      dev/random (linux only)
//
//==============================================================================

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#define OP_INTERRUPT_MAX 1024

#define DEV_RANDOM "/dev/urandom"

static int init_dev_random(int *pfd)
{
    int status=CCERR_INTERNAL;
    int interrupts = 0;
    *pfd = -1;
    while(*pfd == -1) {
        *pfd = open(DEV_RANDOM, O_RDONLY | O_CLOEXEC);
        if(*pfd != -1) {
            break;
        }
        switch(errno) {
            case EINTR:
                interrupts++;
                if(OP_INTERRUPT_MAX && interrupts > OP_INTERRUPT_MAX) {
                    status=CCERR_INTERRUPTS;
                }
                break;
            case EACCES:
                status=CCERR_PERMS;
                break;
            case ENFILE:
            case EMFILE:
                status=CCERR_FILEDESC;
                break;
            case EISDIR:    /* FALLTHROUGH */
            case ELOOP:     /* FALLTHROUGH */
            case ENOENT:    /* FALLTHROUGH */
            case ENXIO:     /* FALLTHROUGH */
            default:
                status=CCERR_CRYPTO_CONFIG;  // We might actually want to abort here - any of these
                                              // indicate a bad entropy.
                break;
        }
    }
    if (*pfd>0) {
        status=0;  // success
    }
    return status;
}

static void close_dev_random(int *pfd) {
    close(*pfd);
    *pfd=-1;
}

//either gets entropy from getentropy() syscall or opens and closes /dev/urandom on each call
int cc_get_entropy(size_t entropy_size, void *entropy)
{
    int fd;
    int status;

    status=init_dev_random(&fd);

    if(status) return status; // No need to close the file
    int interrupts = 0;
    size_t pos = 0;

    while(entropy_size) {
        ssize_t read_now = read(fd, (uint8_t *)entropy+pos, entropy_size);
        if(read_now > -1) {
            entropy_size -= (size_t)read_now;
            pos += (size_t)read_now;
        }
        else if (read_now==0) {
            status=CCERR_OUT_OF_ENTROPY; // End of file is not expected
        }
        else {
            switch(errno) {
                case EINTR:
                    interrupts++;
                    if(OP_INTERRUPT_MAX && interrupts > OP_INTERRUPT_MAX) {
                        status=CCERR_INTERRUPTS;
                    }
                    break;
                case EAGAIN:
                    break;
                case EBADF: /* FALLTHROUGH */
                case ENXIO:
                    status=CCERR_DEVICE;
                    break;
                case EACCES:
                    status=CCERR_PERMS;
                    break;
                case EFAULT:
                    status=CCERR_PARAMETER;
                    break;
                case ENOBUFS: /* FALLTHROUGH */
                case ENOMEM:
                    status=CCERR_MEMORY;
                    break;
                default:
                    status=CCERR_CRYPTO_CONFIG;
                    break;
            }//switch
        }//else
        if (status!=0) {break;} // Close fd and return
    }
    close_dev_random(&fd);
    return status;
}

#elif defined(_WIN32)

#include <windows.h>
int cc_get_entropy(size_t entropy_size, void *entropy)
{
	HCRYPTPROV hProvider;

    BOOL rc = CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
	if (rc == TRUE) {
		rc = CryptGenRandom(hProvider, entropy_size, entropy);
		CryptReleaseContext(hProvider, 0);
    }

	return rc == TRUE ? 0 : CCERR_INTERNAL;
}
#else // getentropy
#error corecrypto requires cc_get_entropy() to be defined.
#endif // !CC_KERNEL
