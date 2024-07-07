/* Copyright (c) (2010-2013,2015,2016,2018-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef crypto_test_rng_h
#define crypto_test_rng_h
#include <corecrypto/ccrng.h>
#include <stddef.h>

#define THREAD_RESULT_ARRAY_LEN 64

int crypto_rng_test_kat(void);
int fortuna_test_kat(void);

void schedule_test(void);
void process_rng_test(void);

int multi_thread_test(struct ccrng_state* rng);
int find_duplicate_uint64(uint64_t *array, size_t array_size);

#if defined(_WIN32)
#include <windows.h>
HANDLE winthread_create(LPTHREAD_START_ROUTINE start_address, LPVOID param);
DWORD WINAPI gen_routine(LPVOID p);
int test_rng_win(struct ccrng_state* rng);
#else
void *gen_routine(void *p);
#endif

struct gen_thread_data {
    struct ccrng_state* rng;
    uint64_t *results;//in the current test function, it holds an array of size THREAD_RESULT_ARRAY_LEN
    int status;
#if defined(_WIN32)
    SYNCHRONIZATION_BARRIER *barrier;
#endif
};

int test_rng_uniform(void);

#endif /* crypto_test_rng_h */
