/* Copyright (c) (2012,2014-2019,2021,2022) Apple Inc. All rights reserved.
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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(_WIN32)
 #include "cctime.h"
#else
 #include <sys/time.h>
 #include <unistd.h>
#endif

#include "testmore.h"
#include "cctest_driver.h"
#include "cctestvector_parser.h"
#include "cc_generated_test_vectors.h"

#include "cc_macros.h"
#include <corecrypto/ccrng_test.h>

//or, define like the following
//#definef printf_stderr(x...) fprintf(stderr, x)
//if cc_printf() is not available.
#define fprintf_stderr(x...) cc_printf(x)
#define fprintf_stdout(x...) cc_printf(x)

static int test_num = 0;
static int test_fails = 0;
static int test_cases = 0;
static int test_todo = 0;
static int test_warning = 0;
static const char *test_plan_file;
static unsigned int test_plan_line=0;

const char *test_directive = NULL;
const char *test_reason = NULL;

void test_skip(const char *reason, int how_many, int unless)
{
    if (unless)
        return;

    int done;
    for (done = 0; done < how_many; ++done)
        test_ok(1, NULL, "skip", reason, __FILE__, __LINE__, NULL);
}

void test_bail_out(const char *reason, const char *file, unsigned line)
{
    fprintf_stdout("BAIL OUT! (%s at line %u) %s\n", file, line, reason);
    fflush(stdout);
    exit(255);
}

void test_plan_skip_all(const char *reason)
{
    if (test_num > test_cases)
    {
	test_skip(reason, test_cases - test_num, 0);
	exit(test_fails > 255 ? 255 : test_fails);
    }
}

static void test_plan_reset(void) {
    test_fails = 0;
    test_num = 0;
    test_cases = 0;
    test_plan_file = NULL;
    test_plan_line = 0;
    test_warning = 0;
}

static void test_plan_exit(void)
{
    // int status = 0;
    fflush(stdout);

    if (!test_num)
    {
        if (test_cases)
        {
            fprintf_stderr("%s:%u: warning: No tests run!\n", test_plan_file, test_plan_line);
            // status = 255;
        }
        else
        {
            fprintf_stderr("%s:%u: error: Looks like your test died before it could "
                    "output anything.\n", test_plan_file, test_plan_line);
            // status = 255;
        }
    }
    else {
        if (test_fails)
        {
            fprintf_stderr("%s:%u: error: Looks like you failed %d tests of %d.\n",
                    test_plan_file, test_plan_line, test_fails, test_cases);
            // status = test_fails;
        }
        if (test_num < test_cases)
        {
            fprintf_stderr("%s:%u: warning: Looks like you planned %d tests but only ran %d.\n",
                   test_plan_file, test_plan_line, test_cases, test_num);
            // status = test_fails + test_cases - test_num;
        }
        else if (test_num > test_cases)
        {
            fprintf_stderr("%s:%u: warning: Looks like you planned %d tests but ran %d extra.\n",
                   test_plan_file, test_plan_line, test_cases, test_num - test_cases);
            // status = test_fails;
        }
    }

    fflush(stderr);
    test_plan_reset();
}

void test_plan_tests(int count, const char *file, unsigned line)
{
#if 0
    if (atexit(test_plan_exit) < 0)
    {
        fprintf_stderr("failed to setup atexit handler: %s\n",
                strerror(errno));
        fflush(stderr);
        exit(255);
    }
#endif

	if (test_cases)
    {
        fprintf_stderr(
                "%s:%u: error: You tried to plan twice!\n",
                file, line);
        
        fflush(stderr);
        exit(255);
    }
    else
	{
        if (!count)
        {
            fprintf_stderr("%s:%u: warning: You said to run 0 tests!  You've got to run "
                    "something.\n", file, line);
            fflush(stderr);
            exit(255);
        }

        test_plan_file=file;
        test_plan_line=line;
        
        test_cases = count;
		fprintf_stderr("%s:%u: note: 1..%d\n", file, line, test_cases);
		fflush(stdout);
	}
}

__cc_printflike(5, 6)
int
test_diag(const char *directive, TM_UNUSED const char *reason,
	TM_UNUSED const char *file, TM_UNUSED unsigned line, const char *fmt, ...)
{
	int is_todo = directive && !strcmp(directive, "TODO");
	va_list args;

	va_start(args, fmt);

    #define PRN_BUFF_SIZE 1024
    char buf[PRN_BUFF_SIZE];
    if(fmt!=NULL)
        vsnprintf(buf, PRN_BUFF_SIZE, fmt, args);
    else
        buf[0] = 0;
    
	if (is_todo)
	{
        fprintf_stdout("# %s \n", buf);
		fflush(stdout);
	}
	else
	{
		fflush(stdout);
        fprintf_stderr("# %s \n", buf);
        fflush(stderr);
	}

	va_end(args);

	return 1;
}

__cc_printflike(7, 8)
int
test_ok(int passed, const char *description, const char *directive,
	const char *reason, const char *file, unsigned line,
	const char *fmt, ...)
{
	int is_todo = !passed && directive && !strcmp(directive, "TODO");
    int is_warning = !passed && directive && !strcmp(directive, "WARNING");
	int is_setup = directive && !is_todo && !strcmp(directive, "SETUP");

	if (is_setup)
	{
		if (!passed)
		{
			fflush(stdout);
			fprintf_stderr("# SETUP not ok%s%s%s%s\n",
				   description ? " - " : "",
				   description ? description : "",
				   reason ? " - " : "",
				   reason ? reason : "");
		}
	}
	else
	{
		if (!test_cases)
		{
			atexit(test_plan_exit);
			fprintf_stderr("You tried to run a test without a plan!  "
					"Gotta have a plan. at %s line %u\n", file, line);
			fflush(stderr);
			exit(255);
		}

		++test_num;
		if (!passed && !is_todo && !is_warning) {
			++test_fails;
        }
/* We dont need to print this unless we want to */
#if 0
		fprintf_stderr("%s:%u: note: %sok %d%s%s%s%s%s%s\n", file, line, passed ? "" : "not ", test_num,
			   description ? " - " : "",
			   description ? description : "",
			   directive ? " # " : "",
			   directive ? directive : "",
			   reason ? " " : "",
			   reason ? reason : "");
#endif
 }

    if (passed)
		fflush(stdout);
	else
    {
		va_list args;

		va_start(args, fmt);

		if (is_todo)
		{
/* Enable this to output TODO as warning */
#if 0             
			fprintf_stdout("%s:%d: warning: Failed (TODO) test\n", file, line);
			if (fmt)
				vprintf(fmt, args);
#endif
            ++test_todo;
			fflush(stdout);
		}
        else if (is_warning)
        {
            /* Enable this to output warning */
            fprintf_stdout("%s:%d: warning: Failed test [%s]\n", file, line, description);
            if (fmt)
            vprintf(fmt, args);
            ++test_warning;
            fflush(stdout);
        }
        else
		{
			fflush(stdout);
            #define PRN_BUFF_SIZE 1024
            char buf[PRN_BUFF_SIZE];
            if(fmt!=NULL)
                vsnprintf(buf, PRN_BUFF_SIZE, fmt, args);
            else
                buf[0] = 0;
            
            if (description) {
                fprintf_stderr("%s:%d: error: Failed test [%s]\n", file, line, description);
                fprintf_stderr("%s", buf);
            } else {
                fprintf_stderr("%s:%d: error: Failed test [", file, line);
                fprintf_stderr("%s", buf);
                fprintf_stderr("]\n");
            }
			fflush(stderr);
		}

		va_end(args);
    }

    return passed;
}

static struct ccrng_test_state test_rng;
struct ccrng_state *global_test_rng=NULL;

static int test_rng_start(const char *test_name, size_t seed_nbytes, const unsigned char *seed) {
    int status=-1;
    // The seed is diversified with the test name
    // each test will use a different random sequence even provided the same seed
    cc_require(seed!=NULL && seed_nbytes>=1,errOut);
    cc_require((status=ccrng_test_init(&test_rng,
                                       seed_nbytes,seed,
                                       test_name))==0, errOut);
    uint64_t output_bytes;
    global_test_rng=(struct ccrng_state *)&test_rng;
    ccrng_generate(global_test_rng,sizeof(output_bytes),&output_bytes);
    return status;
errOut:
    printf("Error initializing test rng: %d\n",status);
    global_test_rng=NULL;
    return -1;
}

static int test_rng_end(void) {
    if (test_rng.drbg_state !=NULL) ccrng_test_done(&test_rng);
    global_test_rng=NULL;
    return 0;
}

/* run one test, described by test, return info in test struct */
int run_one_test(struct one_test_s *test, int argc, char * const *argv, size_t seed_nbytes, const unsigned char *seed)
{
    int rc=0;
    test->executed=1;
    rc=test_rng_start(test->name,seed_nbytes,seed);
    if(test->entry==NULL || rc!=0) {
        fprintf_stdout("%s:%d: error NULL test entry or RNG error (%d)\n", __FILE__, __LINE__,rc);
        return -1;
    }

#if defined(_WIN32)
    SYSTEMTIME st, end;
   
    GetSystemTime(&st);
    test->entry(argc, argv);
    GetSystemTime(&end);
	test->duration = (end.wMinute-st.wMinute)*60*1000 + (end.wSecond-st.wSecond)*1000 + (end.wMilliseconds-st.wMilliseconds);
#else
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    test->entry(argc, argv);
    gettimeofday(&stop, NULL);
    /* this may overflow... */
    test->duration=(unsigned long long)(stop.tv_sec-start.tv_sec)*1000+(unsigned long long)(stop.tv_usec/1000 - start.tv_usec/1000);
#endif

    // Select the test vector driver associated with the given test family and attempt
    // to parse each generated test vector using that driver. Only compatible vectors
    // will be run. The results, i.e., number of total and failed tests, are stored
    // in the driver upon completion.
    cctest_driver_t driver = cctest_driver_for_family(test->name);
    if (driver != NULL) {
        for (size_t i = 0; i < ccgenerated_test_vectors_count; i++) {
            struct ccgenerated_test_vector vector = ccgenerated_test_vectors[i];
            cctestvector_parser_t parser = cctestvector_parser_from_family(vector.parser);
            if (parser != NULL) {
                int rv = cctestvector_parser_parse(parser, vector.buffer, vector.buffer_len, driver);
                if (rv != CCERR_OK) {
                    fprintf(stderr, "Failed parsing test vector: %s\n", vector.name);
                    test->failed_tests += 1;
                    goto errOut;
                }
            } else {
                fprintf(stderr, "Unsupported test vector format: %s\n", vector.parser);
            }
        }
    }

    test->failed_tests=test_fails;
    test->actual_tests=test_num;
    test->planned_tests=test_cases;
    test->plan_file=test_plan_file;
    test->plan_line=test_plan_line;
    test->todo_tests=test_todo;
    test->warning_tests=test_warning;

    if (driver != NULL) {
        test->planned_tests += cctest_driver_get_num_tests(driver);
        test->actual_tests += cctest_driver_get_num_tests(driver);
        test->failed_tests += cctest_driver_get_num_failed_tests(driver);
    }

errOut:
    test_rng_end();
    test_plan_exit();

    return test->failed_tests;
};
