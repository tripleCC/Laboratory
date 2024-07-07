/* Copyright (c) (2014-2016,2018-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "testmore.h"
#include "testbyteBuffer.h"
#include <stdbool.h>
#include <limits.h>

#define CC_SECURITY_TEST

#if (CC == 0)
entryPoint(cc_tests,"cc")
#else

#ifdef CC_SECURITY_TEST
#include <corecrypto/ccrng_test.h>
#include "cccycles.h"
#include "ccstats.h"
#include "ccconstanttime.h"
#endif


// Disable the static analyzer for the code below since we do voluntary access to
// uninitialized memory area in stack

#ifdef __clang_analyzer__
int stack_clear_test(size_t size);
#endif

#ifndef __clang_analyzer__

#if defined(__has_feature) && __has_feature(address_sanitizer)
#define CC_NO_SANITIZE __attribute__((no_sanitize_address))
#else
#define CC_NO_SANITIZE
#endif // __has_feature

#define STACK_MAGIC 0xC0DEBA5E

CC_NO_SANITIZE static void
stack_dirty(size_t size)
{
    volatile uint32_t array[size];
    for (size_t i=0;i<size;i++)
    {
        array[i]=STACK_MAGIC;
    }
}

CC_NO_SANITIZE static void
stack_clear(size_t size)
{
    uint32_t array[size];
    cc_clear(sizeof(array),array);
}

CC_NO_SANITIZE static int
stack_test(size_t size)
{
    volatile uint32_t array[size];
    for (size_t i=0;i<size;i++)
    {
        if (array[i]==STACK_MAGIC)
        {
            return 1; //error stack was not cleared.
        }
    }
    return 0;
}

CC_NO_SANITIZE static int
stack_clear_test(size_t size)
{
    stack_dirty(size);
    stack_clear(size);
    return stack_test(size);
}

#endif  /* __clang_analyzer__ */
// Static analyzer re-enabled.

#define CLZ_RANDOM_TESTS 10000

static void
clz_tests(void) {
    int i;
    uint64_t r64;
    uint32_t r32;
    struct ccrng_state *rng = global_test_rng;

    is(cc_clz32_fallback(2863311530), cc_clz32(2863311530), "clz32 1010... pattern");
    is(cc_clz64_fallback(12297829382473034410U), cc_clz64(12297829382473034410U), "clz64 1010... pattern");
    is(cc_clz32_fallback(1431655765), cc_clz32(1431655765), "clz32 0101... pattern");
    is(cc_clz64_fallback(6148914691236517205U), cc_clz64(6148914691236517205U), "clz64 0101... pattern");

    for (i = 0; i < 32; i++) {
        is(cc_clz32_fallback(1U << i), cc_clz32(1U << i), "clz32");
        is(cc_clz32_fallback((1U << i) + 1), cc_clz32((1U << i) + 1), "clz32 + 1");
        is(cc_clz32_fallback((1U << i) + (1U << 16)), cc_clz32((1U << i) + (1U << 16)), "clz32 + 1 << 16");
    }

    for (i = 0; i < 64; i++) {
        is(cc_clz64_fallback(1ULL << i), cc_clz64(1ULL << i), "clz64");
        is(cc_clz64_fallback((1ULL << i) + 1), cc_clz64((1ULL << i) + 1), "clz64 + 1");
        is(cc_clz64_fallback((1ULL << i) + UINT_MAX + 1), cc_clz64((1ULL << i) + UINT_MAX + 1), "clz64 + 1 << 32");
    }

    for (i = 0; i < CLZ_RANDOM_TESTS; i++)
    {
        ccrng_generate(rng, sizeof(r64), &r64);
        is(cc_clz64_fallback(r64), cc_clz64(r64), "clz64 random");
        r32 = r64 >> 32;
        is(cc_clz32_fallback(r32), cc_clz32(r32), "clz32 random");
    }
}

#define CTZ_RANDOM_TESTS 10000

static void
ctz_tests(void) {
    int i;
    uint64_t r64;
    uint32_t r32;
    struct ccrng_state *rng = global_test_rng;

    is(cc_ctz32_fallback(2863311530), cc_ctz32(2863311530), "ctz32 1010... pattern");
    is(cc_ctz64_fallback(12297829382473034410U), cc_ctz64(12297829382473034410U), "ctz64 1010... pattern");
    is(cc_ctz32_fallback(1431655765), cc_ctz32(1431655765), "ctz32 0101... pattern");
    is(cc_ctz64_fallback(6148914691236517205U), cc_ctz64(6148914691236517205U), "ctz64 0101... pattern");

    for (i = 0; i < 32; i++) {
        is(cc_ctz32_fallback(1U << i), cc_ctz32(1U << i), "ctz32");
        is(cc_ctz32_fallback((1U << i) + 1), cc_ctz32((1U << i) + 1), "ctz32 + 1");
        is(cc_ctz32_fallback((1U << i) + (1U << 16)), cc_ctz32((1U << i) + (1U << 16)), "ctz32 + 1 << 16");
    }

    for (i = 0; i < 64; i++) {
        is(cc_ctz64_fallback(1ULL << i), cc_ctz64(1ULL << i), "ctz64");
        is(cc_ctz64_fallback((1ULL << i) + 1), cc_ctz64((1ULL << i) + 1), "ctz64 + 1");
        is(cc_ctz64_fallback((1ULL << i) + UINT_MAX + 1), cc_ctz64((1ULL << i) + UINT_MAX + 1), "ctz64 + 1 << 32");
    }

    for (i = 0; i < CTZ_RANDOM_TESTS; i++)
    {
        ccrng_generate(rng, sizeof(r64), &r64);
        is(cc_ctz64_fallback(r64), cc_ctz64(r64), "ctz64 random");
        r32 = r64 >> 32;
        is(cc_ctz32_fallback(r32), cc_ctz32(r32), "ctz32 random");
    }
}

#define FFS_RANDOM_TESTS 10000

static void
ffs_tests(void) {
    int i;
    int64_t r64;
    int32_t r32;
    struct ccrng_state *rng = global_test_rng;

    is(cc_ffs32_fallback(0), cc_ffs32(0), "ffs32 zero");
    is(cc_ffs64_fallback(0), cc_ffs64(0), "ffs64 zero");
    is(cc_ffs32_fallback((int32_t)2863311530), cc_ffs32((int32_t)2863311530), "ffs32 1010... pattern");
    is(cc_ffs64_fallback((int64_t)12297829382473034410U), cc_ffs64((int64_t)12297829382473034410U), "ffs64 1010... pattern");
    is(cc_ffs32_fallback(1431655765), cc_ffs32(1431655765), "ffs32 0101... pattern");
    is(cc_ffs64_fallback(6148914691236517205), cc_ffs64(6148914691236517205), "ffs64 0101... pattern");

    for (i = 0; i < 32; i++) {
        is(cc_ffs32_fallback(1 << i), cc_ffs32(1 << i), "ffs32");
        is(cc_ffs32_fallback((1 << i) + 1), cc_ffs32((1 << i) + 1), "ffs32 + 1");
        is(cc_ffs32_fallback((1 << i) + (1 << 16)), cc_ffs32((1 << i) + (1 << 16)), "ffs32 + 1 << 16");
    }

    for (i = 0; i < 64; i++) {
        is(cc_ffs64_fallback(1LL << i), cc_ffs64(1LL << i), "ffs64");
        is(cc_ffs64_fallback((1LL << i) + 1), cc_ffs64((1LL << i) + 1), "ffs64 + 1");
        is(cc_ffs64_fallback((1LL << i) + UINT_MAX + 1), cc_ffs64((1LL << i) + UINT_MAX + 1), "ffs64 + 1 << 32");
    }

    for (i = 0; i < FFS_RANDOM_TESTS; i++) {
        ccrng_generate(rng, sizeof(r64), &r64);
        is(cc_ffs64_fallback(r64), cc_ffs64(r64), "ffs64 random");
        r32 = r64 >> 32;
        is(cc_ffs32_fallback(r32), cc_ffs32(r32), "ffs32 random");
    }
}

#define POPCOUNT_RANDOM_TESTS 10000

static void
popcount_tests(void) {
    int i;
    uint64_t r64;
    uint32_t r32;
    struct ccrng_state *rng = global_test_rng;

    is(cc_popcount32_fallback(2863311530), cc_popcount32(2863311530), "popcount32 1010... pattern");
    is(cc_popcount64_fallback(12297829382473034410U), cc_popcount64(12297829382473034410U), "popcount64 1010... pattern");
    is(cc_popcount32_fallback(1431655765), cc_popcount32(1431655765), "popcount32 0101... pattern");
    is(cc_popcount64_fallback(6148914691236517205U), cc_popcount64(6148914691236517205U), "popcount64 0101... pattern");

    for (i = 0; i < 32; i++) {
        is(cc_popcount32_fallback(1U << i), cc_popcount32(1U << i), "popcount32");
        is(cc_popcount32_fallback((1U << i) + 1), cc_popcount32((1U << i) + 1), "popcount32 + 1");
        is(cc_popcount32_fallback((1U << i) + (1U << 16)), cc_popcount32((1U << i) + (1U << 16)), "popcount32 + 1 << 16");
    }

    for (i = 0; i < 64; i++) {
        is(cc_popcount64_fallback(1ULL << i), cc_popcount64(1ULL << i), "popcount64");
        is(cc_popcount64_fallback((1ULL << i) + 1), cc_popcount64((1ULL << i) + 1), "popcount64 + 1");
        is(cc_popcount64_fallback((1ULL << i) + UINT_MAX + 1), cc_popcount64((1ULL << i) + UINT_MAX + 1), "popcount64 + 1 << 32");
    }

    for (i = 0; i < POPCOUNT_RANDOM_TESTS; i++)
    {
        ccrng_generate(rng, sizeof(r64), &r64);
        is(cc_popcount64_fallback(r64), cc_popcount64(r64), "popcount64 random");
        r32 = r64 >> 32;
        is(cc_popcount32_fallback(r32), cc_popcount32(r32), "popcount32 random");
    }
}

static void
Rotate_Tests(void) {
    int c=1;
    uint32_t result32=0xaaaaaaaa;
    uint64_t result64=0xaaaaaaaaaaaaaaaa;

    /* The first argument is NOT a variable on purpose */
    is(result32, CC_ROL(0x55555555, c), "CC_ROL 1");

    is(result32, CC_ROLc(0x55555555, 1), "CC_ROLc 1");

    is(result64, CC_ROL64(0x5555555555555555, c), "CC_ROL64 1");

    is(result64, CC_ROL64c(0x5555555555555555, 1), "CC_ROL64c 1");

    is(result32, CC_ROR(0x55555555, c), "CC_ROR 1");

    is(result32, CC_RORc(0x55555555, 1), "CC_RORc 1");

    is(result64, CC_ROR64(0x5555555555555555, c), "CC_ROR64 1");

    is(result64, CC_ROR64c(0x5555555555555555, 1), "CC_ROR64c 1");
}

static void
mux_Tests(void) {

    uint8_t i8;
    uint16_t i16;
    uint32_t i32;
    uint64_t i64;

    CC_MUXU(i8,0U,(uint8_t)0xAB,(uint8_t)0xBA);
    is(i8,0xBA,"CC_MUXU() failed");
    CC_MUXU(i8,1U,(uint8_t)0xBA,(uint8_t)0xAB);
    is(i8,0xBA,"CC_MUXU() failed");

    CC_MUXU(i16,0U,(uint16_t)0xAB00,(uint16_t)0xBA00);
    is(i16,0xBA00,"CC_MUXU() failed");
    CC_MUXU(i16,1U,(uint16_t)0xBA00,(uint16_t)0xAB00);
    is(i16,0xBA00,"CC_MUXU() failed");

    CC_MUXU(i32,0U,(uint32_t)0xAB00BEEF,(uint32_t)0xBA00BEEF);
    is(i32,0xBA00BEEF,"CC_MUXU() failed");
    CC_MUXU(i32,1U,(uint32_t)0xBA00BEEF,(uint32_t)0xAB00BEEF);
    is(i32,0xBA00BEEF,"CC_MUXU() failed");

    CC_MUXU(i64,(uint64_t)0U,(uint64_t)0xAB00BEEF11223344,(uint64_t)0xBA00BEEF11223344);
    is(i64,0xBA00BEEF11223344,"CC_MUXU() failed");
    CC_MUXU(i64,(uint64_t)1U,(uint64_t)0xBA00BEEF11223344,(uint64_t)0xAB00BEEF11223344);
    is(i64,0xBA00BEEF11223344,"CC_MUXU() failed");
}

static void
HEAVISIDE_STEP_Tests(void)
{
    uint8_t i8;
    uint16_t i16;
    uint32_t i32;
    uint64_t i64;
    size_t i; // loop index
    uint8_t err=0,nb_test=0;

    // Sanity check on intended lengths
    ok(sizeof(uint8_t) == 1, "sizeof(uint8_t)!=1");
    ok(sizeof(uint16_t) == 2, "sizeof(uint16_t)!=2");
    ok(sizeof(uint32_t) == 4, "sizeof(uint32_t)!=4");
    ok(sizeof(uint64_t) == 8, "sizeof(uint64_t)!=1");

    for (i=0;i<8*sizeof(i8);i++)
    {
        nb_test++;
        CC_HEAVISIDE_STEP(i8,((uint8_t)1<<i));
        if (i8!=1) err++;
    }
    ok(err==0,"CC_HEAVISIDE_STEP(i8)");

    for (i=0;i<8*sizeof(i16);i++)
    {
        nb_test++;
        CC_HEAVISIDE_STEP(i16,((uint16_t)1<<i));
        if (i16!=1) err++;
    }
    ok(err==0,"CC_HEAVISIDE_STEP(i16)");

    for (i=0;i<8*sizeof(i32);i++)
    {
        nb_test++;
        CC_HEAVISIDE_STEP(i32,((uint32_t)1<<i));
        if (i32!=1) err++;
    }
    ok(err==0,"CC_HEAVISIDE_STEP(i32)");

    for (i=0;i<8*sizeof(i64);i++)
    {
        nb_test++;
        CC_HEAVISIDE_STEP(i64,((uint64_t)1<<i));
        if (i64!=1) err++;
    }
    ok(err==0,"CC_HEAVISIDE_STEP(i64)");

    ok(err + (64+32+16+8)-nb_test==0, "CC HEAVISIDE_STEP test failed");
}

static void
cmp_secure_functionalTests(void) {
#define ARRAY_SIZE 10

    // --- Bytes
    uint8_t array1[ARRAY_SIZE]={1,2,3,4,5,6,7,8,9,0};
    uint8_t array2[ARRAY_SIZE];

    memcpy(array2,array1,sizeof(array1));
    // Equal
    ok(cc_cmp_safe(sizeof(array1), array1,array2)==0, "array1 to array2");
    ok(cc_cmp_safe(sizeof(array1), array2,array1)==0, "array2 to array1");

    // length is zero
    ok(cc_cmp_safe(0, array2,array1)!=0, "Array of size 0");

    // Equal but first byte
    array1[0]++;
    ok(cc_cmp_safe(sizeof(array1), array1,array2)!=0, "first byte");
    array1[0]--;

    // Equal but last byte
    array1[sizeof(array1)-1]++;
    ok(cc_cmp_safe(sizeof(array1), array1,array2)!=0, "last byte");
    array1[sizeof(array1)-1]--;

    // --- cc_units
    uint64_t u64_array1[ARRAY_SIZE]={};
    for (size_t i=0;i<ARRAY_SIZE;i++) u64_array1[i]=i;
    uint64_t u64_array2[ARRAY_SIZE];
    uint64_t tmp;

    memcpy(u64_array2,u64_array1,sizeof(u64_array1));
    // Equal
    ok(cc_cmp_safe(sizeof(u64_array1), u64_array1,u64_array2)==0, "array1 to array2");
    ok(cc_cmp_safe(sizeof(u64_array1), u64_array2,u64_array1)==0, "array2 to array1");

    // length is zero
    ok(cc_cmp_safe(0, u64_array2,u64_array1)!=0, "Array of size 0");

    // Equal but first byte
    ((uint8_t *)u64_array1)[0]++;
    ok(cc_cmp_safe(sizeof(u64_array1),u64_array1,u64_array2)!=0, "first byte");
    ((uint8_t *)u64_array1)[0]--;

    // Equal but last byte
    tmp = cc_load64_be((uint8_t *) &u64_array1[ARRAY_SIZE-1]);
    cc_store64_be(tmp^0x80, (uint8_t *) &u64_array1[ARRAY_SIZE-1]);
    ok(cc_cmp_safe(sizeof(u64_array1), u64_array1,u64_array2)!=0, "last byte");
    cc_store64_be(tmp, (uint8_t *) &u64_array1[ARRAY_SIZE-1]);
}

#ifdef CC_SECURITY_TEST

//======================================================================
// Constant time verification parameters
//======================================================================

// Number of iteration of test where timings are not taken into account.
// Made to reach a stable performance state
#define CC_WARMUP        10

// Each sample is the average time for many iteration with identical inputs
#define CC_TIMING_REPEAT  150

// Number of sample for the statistical analysis
// typically 100~1000 is a good range
#define CC_TIMING_SAMPLES 200

// In case of failure, try many times
// This is to reduce false positives due to noise/timing accuracy.
// If implementation is not constant time, the behavior will be consistent
// So that this does not reduce the detection power.
#define CC_TIMING_RETRIES 10

// Two statitical tools are available: T-test and Wilcoxon.
// T-test assumes that the distribution to be compared are normal
// Wilcoxon measure offset between distribution.
// Due to potential switches between performance state or occasional
// latencies, Wilcoxon is recommended.
// > Set to 1 to use T-test instead of Wilcoxon
#define T_TEST  1

// Number of iteration of the full test (to play with to evaluate chances of false positives)
#define CMP_SECURITY_TEST_ITERATION 1

// Quantile for the repeated timing. Empirical value.
#define CC_TIMING_PERCENTILE 9

//======================================================================

static const int verbose=1;

#define TEST_LAST_BYTE 1
#define TEST_FIRST_BYTE 2
#define TEST_RANDOM 3
#define TEST_EQUAL 4

CC_WARN_RESULT static int
cmp_secure_timeconstantTests(size_t length, struct ccrng_state *rng, uint32_t test_id) {

    // Random for messages
    uint8_t array1[length];
    uint8_t array2[length];
    int failure_cnt=0;
    int early_abort=1;
    uint32_t j,sample_counter;
    bool retry=true;

    if (length<=0) {goto errOut;}
    j=0;
    while(retry)
    {
        sample_counter=0; // Index of current sample
        measurement_t timing_sample[2*CC_TIMING_SAMPLES];

        for (size_t i=0;i<2*CC_TIMING_SAMPLES+(CC_WARMUP/CC_TIMING_REPEAT);i++)
        {
            ccrng_generate(rng,length,array1);
            volatile int cmp_result;
            if ((i&1) == 0)
            {
                // -------------------------
                //      Random
                // -------------------------
                switch(test_id) {
                    // All equal, except last byte
                    case TEST_LAST_BYTE:
                        memcpy(array2,array1,length);
                        array2[length-1]^=1;
                        break;
                    // All equal, except first byte
                    case TEST_FIRST_BYTE:
                        memcpy(array2,array1,length);
                        array2[0]^=1;
                        break;
                    // Random
                    case TEST_RANDOM:
                        ccrng_generate(rng,length,array2);
                        break;
                    // All equal
                    case TEST_EQUAL:
                        memcpy(array2,array1,length);
                        break;
                    default:
                        return 0; // failure
                }

            }
            else
            {
                // -------------------------
                //      Equal
                // -------------------------
                memcpy(array2,array1,length);
            }
#if 1
            // Actual function to test
            TIMING_WITH_QUANTILE(timing_sample[sample_counter].timing,
                                 CC_TIMING_REPEAT,
                                 CC_TIMING_PERCENTILE,
                                 cmp_result=cc_cmp_safe(length, array1, array2),errOut);
#else
            // Reference which can be expected to fail
            TIMING_WITH_QUANTILE(timing_sample[sample_counter].timing,
                                 CC_TIMING_REPEAT,
                                 CC_TIMING_PERCENTILE,
                                 cmp_result=memcmp(array1, array2,length),errOut);
#endif
            timing_sample[sample_counter].group=sample_counter&1;
#if CC_WARMUP
            if (i>=CC_WARMUP/CC_TIMING_REPEAT)
#endif
            {
                sample_counter++;
            }
        }
        if (verbose>1) {
            char file_name[64];
            snprintf(file_name,sizeof(file_name),"corecrypto_test_cc_cmp_timings_%.2zu.csv",length);
            export_measurement_to_file(file_name,timing_sample,sample_counter);
        }
        // Process results
#if T_TEST
        // T test
        int status=T_test_isRejected(timing_sample,sample_counter);
#else
        // Wilcoxon Rank-Sum Test
        int status=WilcoxonRankSumTest(timing_sample,sample_counter);
#endif
        if (status!=0)
        {
            j++; // retry counter
            if (j>=CC_TIMING_RETRIES)
            {
                diag("Constant timing FAILED for len %d after %d attempts",length,j);
                //ok_or_fail((status==0),"Decrypt+padding constant timing");
                failure_cnt++;
                break;
            }
        }
        else
        {
            if ((verbose>1) && (j>0)) diag("Constant timing ok for len %d after %d attempts (of %d)",length,j+1,CC_TIMING_RETRIES);
            break;
        }
    } // retry

    early_abort=0;
errOut:
    if (failure_cnt || early_abort)
    {
        return 0;
    }
    return 1;
}

#define CMP_SECURITY_TEST_MAX_LENGTH 2048
static void
memcmp_secure_securityTests(void) {
    // Random for messages
    struct ccrng_state *rng = global_test_rng;
    for (size_t i=0;i<CMP_SECURITY_TEST_ITERATION;i++)
    {
        size_t r;
        ccrng_generate(rng,sizeof(r),&r);
        r=(r%CMP_SECURITY_TEST_MAX_LENGTH)+1;
        ok(cmp_secure_timeconstantTests(r,rng,TEST_FIRST_BYTE), "Time constant check, first byte difference");
        ok(cmp_secure_timeconstantTests(r,rng,TEST_LAST_BYTE), "Time constant check, last byte difference");
        ok(cmp_secure_timeconstantTests(r,rng,TEST_RANDOM), "Time constant check, random");
        ok(cmp_secure_timeconstantTests(r,rng,TEST_EQUAL), "Time constant check of equal input - if it fails, it's a test issue");
    }
}
#endif // CC_SECURITY_TEST

#ifdef CC_SECURITY_TEST
#define kPlan_ccSecurityTestNb 5
#else
#define kPlan_ccSecurityTestNb 0
#endif

int cc_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int num_tests = 36 + kPlan_ccSecurityTestNb;
    num_tests += 292 + 2 * CLZ_RANDOM_TESTS; // clz_tests
    num_tests += 292 + 2 * CTZ_RANDOM_TESTS; // ctz_tests
    num_tests += 294 + 2 * FFS_RANDOM_TESTS; // ffs_tests
    num_tests += 292 + 2 * POPCOUNT_RANDOM_TESTS; // popcount_tests
    plan_tests(num_tests);

    clz_tests();
    ctz_tests();
    ffs_tests();
    popcount_tests();

    //For Windows port, many unsigned longs have been replaced with size_t.
    //This test makes sure corecrypto is agnostic to the change.
    //This test can be removed leter on.
#if defined(_WIN64) && defined(_WIN32) 
    ok(sizeof(size_t)!=sizeof(unsigned long),
#else
    ok(sizeof(size_t)==sizeof(unsigned long),
#endif
    "Historically, corecrypto assumes size_t and long have the same size. Fon Win64, that is not the case");


    if(verbose) diag("Stack cleanup");
    ok(stack_clear_test(100)==0, "Stack clearing");

    if(verbose) diag("mux test");
    mux_Tests();

    if(verbose) diag("HEAVISIDE_STEP test");
    HEAVISIDE_STEP_Tests();

    if(verbose) diag("Rotate test");
    Rotate_Tests();

    if(verbose) diag("Secure comparison test");
    cmp_secure_functionalTests();

#ifdef CC_SECURITY_TEST
    if (!cc_is_vmm_present()) {
        if(verbose) diag("Secure comparison security test");
        memcmp_secure_securityTests();
    } else {
        diag("Running in a VM, skipping ");
    }
#endif // CC_SECURITY_TEST

    // Silence code coverage
    const char *label = "corecrypto";
    const uint8_t *buffer = (const uint8_t *)label;
    cc_print("label", strlen(label), buffer);

    return 0;
}

#endif //CC
