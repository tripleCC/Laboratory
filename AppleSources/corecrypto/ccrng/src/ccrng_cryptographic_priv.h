/* Copyright (c) (2016-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef ccrng_cryptographic_priv_h
#define ccrng_cryptographic_priv_h

#if defined(_WIN32)
#include <windows.h>
#endif

//==============================================================================
//
//          ccrng support for multithreaded environments
//
// This part of corecrypto is OS dependent and it serves two purposes
// a) It allows multiple threads to use ccrng()
// b) If the process is forked, it reseeds the ccrng, so that parent and child
//    state differs and generate different random numbers
//==============================================================================

#if CC_LINUX && CC_KERNEL && CC_DARWIN && CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
#define CC_RNG_MULTITHREAD_POSIX 0 // this is only to allow linux development on macOS. It is not useful in practice.
#define CC_RNG_MULTITHREAD_USER 0
#define CC_RNG_MULTITHREAD_WIN 0
#define CC_RNG_MULTITHREAD_KERNEL 1
#elif CC_DARWIN && !CC_KERNEL && !CC_USE_L4 && \
    !CC_EFI && CC_INTERNAL_SDK // For Apple OSs (macOS, iOS, watchOS, tvOS), except kernel, L4 and EFI
#define CC_RNG_MULTITHREAD_POSIX 0
#define CC_RNG_MULTITHREAD_USER 1
#define CC_RNG_MULTITHREAD_WIN 0
#define CC_RNG_MULTITHREAD_KERNEL 0
#elif CC_DARWIN && CC_KERNEL // For the Apple Kernel
#define CC_RNG_MULTITHREAD_POSIX 0
#define CC_RNG_MULTITHREAD_USER 0
#define CC_RNG_MULTITHREAD_WIN 0
#define CC_RNG_MULTITHREAD_KERNEL 1
#elif defined(_WIN32) // for Windows
#define CC_RNG_MULTITHREAD_POSIX 0
#define CC_RNG_MULTITHREAD_USER 0
#define CC_RNG_MULTITHREAD_WIN 1
#define CC_RNG_MULTITHREAD_KERNEL 0
#elif CC_LINUX || !CC_INTERNAL_SDK // for systems that support pthread, such as Linux
#define CC_RNG_MULTITHREAD_POSIX 1
#define CC_RNG_MULTITHREAD_USER 0
#define CC_RNG_MULTITHREAD_WIN 0
#define CC_RNG_MULTITHREAD_KERNEL 0
#else
#error No multithread environment defined for ccrng_cryptographic.
#endif

//------------------------------------------------------------------------------
// os/lock library, Apple userland
//------------------------------------------------------------------------------
#if CC_RNG_MULTITHREAD_USER
#include <pthread.h>
#include <os/lock.h>
#include <os/once_private.h>

#define CC_INIT_ONCE(_function_)                        \
    static os_once_t _function_##_p;                    \
    os_once(&_function_##_p, NULL, _function_##_user)

//------------------------------------------------------------------------------
//          POSIX library, Linux
//------------------------------------------------------------------------------
#elif CC_RNG_MULTITHREAD_POSIX
#include <pthread.h>

#define CC_INIT_ONCE(_function_)                                 \
    static pthread_once_t _init_controller_ = PTHREAD_ONCE_INIT; \
    pthread_once(&_init_controller_, (void (*)(void))_function_)

//------------------------------------------------------------------------------
//          Kext, XNU
//------------------------------------------------------------------------------
#elif CC_RNG_MULTITHREAD_KERNEL

//------------------------------------------------------------------------------
//          Windows
//------------------------------------------------------------------------------
#elif CC_RNG_MULTITHREAD_WIN

// _function_ is appended the suffix _win
#define CC_INIT_ONCE(_function_)                                \
    static INIT_ONCE _init_controller_ = INIT_ONCE_STATIC_INIT; \
    InitOnceExecuteOnce(&_init_controller_, _function_##_win, NULL, NULL)

//------------------------------------------------------------------------------
//          default
//------------------------------------------------------------------------------
#else
#error "CC_RNG_MULTITHREAD support is not implemented."
#endif /* CC_RNG_MULTITHREAD_USER */

#endif /* ccrng_cryptographic_priv_h */
