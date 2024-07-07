/* Copyright (c) (2012,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_config.h"
#if CC_LINUX
#define _GNU_SOURCE // For Dl_info
#endif

#include "cc_internal.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdbool.h>
#if defined(_WIN32)
 static int optind = 1;
#else
#include <unistd.h>
#include <dlfcn.h>
#endif

#include "testmore.h"
#include "testenv.h"

#include "cc_macros.h"
#include <corecrypto/ccrng.h>
#include "testbyteBuffer.h"

static int tests_printall(void);

static int
tests_summary(int verbose) {
    int failed_tests = 0;
    int todo_tests = 0;
    int actual_tests = 0;
    int planned_tests = 0;
    int warning_tests = 0;
    uint64_t duration_tests = 0;

    // First compute the totals to help decide if we need to print headers or not.
    for (int i = 0; testlist[i].name; ++i) {
        if (testlist[i].executed) {
            failed_tests += testlist[i].failed_tests;
            todo_tests += testlist[i].todo_tests;
            actual_tests += testlist[i].actual_tests;
            planned_tests += testlist[i].planned_tests;
            warning_tests += testlist[i].warning_tests;
            duration_tests += testlist[i].duration;
        }
    }

    fprintf(stdout, "\n[SUMMARY]\n");

    // -v makes the summary verbose as well.
    if (verbose || failed_tests || actual_tests != planned_tests || todo_tests || warning_tests) {
        fprintf(stdout, "Test name                                                failed  warning  todo  ran  planned\n");
        fprintf(stdout, "============================================================================================\n");
    }
    for (int i = 0; testlist[i].name; ++i) {
        if (testlist[i].executed) {
            const char *token = NULL;
            if (testlist[i].failed_tests) {
                token = "FAIL";
            } else if (testlist[i].actual_tests != testlist[i].planned_tests
                       || (testlist[i].todo_tests)
                       || (testlist[i].warning_tests)) {
                token = "WARN";
            } else if (verbose) {
                token = "PASS";
            }
            if (token) {
                fprintf(stdout, "[%s] %-49s %6d  %6d %6d %6d %6d\n", token,
                        testlist[i].name,
                        testlist[i].failed_tests, testlist[i].warning_tests,
                        testlist[i].todo_tests,
                        testlist[i].actual_tests, testlist[i].planned_tests);
            }
        }
    }
    if (verbose || failed_tests || warning_tests || todo_tests || actual_tests != planned_tests) {
        fprintf(stdout, "============================================================================================\n");
    }
    else {
        fprintf(stdout, "Test name                                                failed  warning  todo  ran  planned\n");
    }
    fprintf(stdout, "Totals (%6llus)                                         %6d  %6d %6d %6d %6d\n", duration_tests/1000, failed_tests, warning_tests, todo_tests, actual_tests, planned_tests);
    return failed_tests;
}

#if defined(_WIN32)
static int tests_run_index(int i, int argc, char * const *argv, byteBuffer seed)
{
    fprintf(stderr, "\n[BEGIN] %s\n", testlist[i].name);

    run_one_test(&testlist[i], argc, argv, seed->len, seed->bytes);
    if(testlist[i].failed_tests) {
        fprintf(stderr, "[FAIL] %s\n", testlist[i].name);
    } else {
        fprintf(stderr, "duration: %llu ms\n", testlist[i].duration);
        fprintf(stderr, "[PASS] %s\n", testlist[i].name);
    }

    return 0;
}
#else
static void usage(const char *progname)
{
    fprintf(stderr, "usage: %s [-L][-v][-s seed][-w][testname [-v] ...]\n", progname);
    fprintf(stderr, "\t-v verbose\n");
    fprintf(stderr, "\t-s <seed> to provide a specific seed (ex 8686b151ec2aa17c4ec41a59e496d2ff), reused for each sub-test.\n");
    fprintf(stderr, "\t-w sleep(100)\n");
    fprintf(stderr, "\t-L list supported tests by test names\n");
    fprintf(stderr, "Here is the list of supported tests:\n");
    tests_printall();
    exit(1);
}

static int tests_run_index(int i, int argc, char * const *argv, byteBuffer seed)
{
    int verbose = 0;
    int ch;

    while ((ch = getopt(argc, argv, "v")) != -1) {
        switch  (ch) {
            case 'v':
                verbose++;
                break;
            default:
                usage(argv[0]);
        }
    }

    fprintf(stderr, "\n[BEGIN] %s\n", testlist[i].name);
    run_one_test(&testlist[i], argc, argv, seed->len, seed->bytes);

    if (testlist[i].failed_tests) {
        fprintf(stderr, "[FAIL] %s\n", testlist[i].name);
    } else {
        fprintf(stderr, "duration: %llu ms\n", testlist[i].duration);
        fprintf(stderr, "[PASS] %s\n", testlist[i].name);
    }

    return 0;
}

static int tests_named_index(const char *testcase)
{
    int i;

    for (i = 0; testlist[i].name; ++i) {
        if (strcmp(testlist[i].name, testcase) == 0) {
            return i;
        }
    }

    return -1;
}

#endif

static int tests_printall(void)
{
    for (int i = 0; testlist[i].name; ++i) {
        fprintf(stdout, "%s\n", testlist[i].name);
    }

    return 0;
}

static int tests_run_all(int argc, char * const *argv, byteBuffer seed)
{
    int curroptind = optind;
    int i;

    for (i = 0; testlist[i].name; ++i) {
        tests_run_index(i, argc, argv,seed);
        optind = curroptind;
    }

    return 0;
}


#if CC_DARWIN || CC_LINUX
static off_t fsize(const char *fname)
{
    struct stat st;
    return (stat(fname, &st) == 0)? st.st_size:-1;
}

static void print_lib_info(void)
{
    Dl_info dl_info;
    if(dladdr((void *)cc_clear, &dl_info) != 0){
        fprintf(stderr, "corecrypto dylib path: %s\n", dl_info.dli_fname);
        fprintf(stderr, "corecrypto dylib size: %lld bytes\n", fsize(dl_info.dli_fname));
        fprintf(stderr, "corecrypto dylib arch: %s\n", cc_current_arch());
    }
}
#elif defined(_MSC_VER)
static void print_lib_info(void) {}
#endif

static int tests_init(byteBuffer *pSeedBuffer,const char *seedInput) {
    printf("[TEST] === corecrypto ===\n");
    print_lib_info();
    int status=-1;
    // Set a seed for reproducibility
    if (seedInput!=NULL) {
        *pSeedBuffer=hexStringToBytes(seedInput);
        if (*pSeedBuffer) {
            printByteBuffer(*pSeedBuffer,"\nInput seed value:");
            status=0;
        }
        else{
            printf("Error with input seed value: %s",seedInput);
        }
    } else {
        // If the seed is not in the argument, we generate one
        size_t entropy_size=16; // Default size of the seed
        cc_require((*pSeedBuffer=mallocByteBuffer(entropy_size))!=NULL,errOut);
        struct ccrng_state *rng = ccrng(&status);
        cc_require(rng!=NULL, errOut);
        cc_require((status=ccrng_generate(rng, (*pSeedBuffer)->len, (*pSeedBuffer)->bytes))==0, errOut);
        printByteBuffer(*pSeedBuffer,"\nRandom seed value:");
        printf("Seed used for every subtest. To reproduce a failure, you can run with '-s <seed> <subtest>'\n");
    }
    
    tests_print_impls();

errOut:
    return status;
}

#if defined(_WIN32)
int
tests_begin(int argc, char * const *argv)
{
    const char *seed=NULL;
    byteBuffer seedBuffer=NULL; //seed for test drbg
	int list = 0;
	int retval;
	int verbose = 0;

	printf("Command-line options are currently not supported on Windows.\n");

    if ((retval=tests_init(&seedBuffer, seed)) != 0) {
        printf("%08x unable to initialize tests", retval);
        return -1;
    }
	tests_run_all(argc, argv, seedBuffer);

	if (list) {
		tests_printall();
		retval = 0;
	}
	else {
		retval = tests_summary(verbose);
	}
	/* Cleanups */
    free(seedBuffer);

    retval = tests_summary(verbose);
	return retval;
}
#else

int
tests_begin(int argc, char * const *argv)
{
    const char *seed=NULL;
    byteBuffer seedBuffer=NULL;
	int retval;
	int verbose = 0;
    const char *testcase = NULL;
    bool initialized = false;
    int testix = -1;
    int ch;

	for (;;) {
        while (!testcase && (ch = getopt(argc, argv, "Livws:")) != -1) {
            switch  (ch) {
            case 's': // seed provided
                // The same seed is reused for all of the tests
                seed = optarg;
                break;
            case 'w': // wait
                sleep(100);
                break;
            case 'v': // verbose
                verbose=1;
                break;
            case 'L': // List test for test discovery
                tests_printall();
                exit(0);
            case 'i':
                    tests_print_impls();
                    exit(0);
            case '?':
            default:
                printf("invalid option %c\n",ch);
                usage(argv[0]);
            }
        }

        if (optind < argc) {
            testix = tests_named_index(argv[optind]);
            if (testix < 0) {
                printf("invalid test %s\n",argv[optind]);
                usage(argv[0]);
            }
            testcase = argv[optind];
            argc -= optind;
            argv += optind;
            optind = 1;
        }

        if (testix < 0) {
            // Not test specified or reached end of list
            if (!initialized) {
                // Not test specified
                if (tests_init(&seedBuffer, seed) != 0) {
                    return -1;
                }
                tests_run_all(argc, argv, seedBuffer);
            }
            break;
        } else {
            if (!initialized) {
                if (tests_init(&seedBuffer, seed) != 0) {
                    return -1;
                }
                initialized = true;
            }
            tests_run_index(testix, argc, argv,seedBuffer);
            testix = -1;
        }
    }

    /* Cleanups */
    free(seedBuffer);

    retval=tests_summary(verbose);
    return retval;
}
#endif
