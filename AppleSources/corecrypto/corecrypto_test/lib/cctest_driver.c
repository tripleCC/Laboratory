/* Copyright (c) (2018-2020,2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <corecrypto/cc_priv.h>

#include "testbyteBuffer.h"
#include "cctestvector_parser.h"
#include "cctest_driver.h"
#include "cctest_runner.h"
#include "ccdict.h"

struct cctest_algorithm_driver {
    /*!
     * @abstract Name of the test runner
     */
    const char *algorithm;

    /*!
     * @function run
     * @abstract Pointer to a runner function.
     * @param test_vector_data A `ccdict_t` containing all the relevant test vector data.
     * @return True if the test passed, and false otherwise.
     */
    bool (*run)(ccdict_t vector);
};

struct cctest_driver {
    /*!
     * @abstract Name of the algorithm family in which this test should run.
     */
    const char *family;

    /*!
     * @abstract List of drivers for this particular family.
     */
    struct cctest_algorithm_driver *drivers;
    size_t drivers_len;

    /*!
     * Number of passed and failed tests for this family.
     */
    int num_tests;
    int num_fails;
};

static struct cctest_algorithm_driver ccchacha_runners[] = {
    { .algorithm = "CHACHA20-POLY1305", .run = crypto_test_chacha20poly1305_runner },
};
static const size_t ccchacha_runners_len = CC_ARRAY_LEN(ccchacha_runners);

static struct cctest_algorithm_driver ccaesmode_runners[] = {
    { .algorithm = "AES-GCM", .run = crypto_test_aes_gcm_runner },
    { .algorithm = "AES-CCM", .run = crypto_test_aes_ccm_runner },
};
static const size_t ccaesmode_runners_count = CC_ARRAY_LEN(ccaesmode_runners);

static struct cctest_algorithm_driver cccmac_runners[] = {
    { .algorithm = "AES-CMAC", .run = crypto_test_cmac_runner },
};
static const size_t cccmac_runners_count = CC_ARRAY_LEN(cccmac_runners);

static struct cctest_algorithm_driver ccec_runners[] = {
    { .algorithm = "ECDH", .run = crypto_test_ecdh_runner },
    { .algorithm = "ECDSA", .run = crypto_test_ecdsa_runner },
};
static const size_t ccec_runners_count = CC_ARRAY_LEN(ccec_runners);

static struct cctest_algorithm_driver ccec25519_runners[] = {
    { .algorithm = "XDH", .run = crypto_test_x25519_runner },
#ifndef _MSC_VER
    { .algorithm = "EDDSA", .run = crypto_test_ed25519_runner },
#endif
};
static const size_t ccec25519_runners_count = CC_ARRAY_LEN(ccec25519_runners);

static struct cctest_algorithm_driver ccec448_runners[] = {
    { .algorithm = "XDH", .run = crypto_test_x448_runner },
#ifndef _MSC_VER
    { .algorithm = "EDDSA", .run = crypto_test_ed448_runner },
#endif
};
static const size_t ccec448_runners_count = CC_ARRAY_LEN(ccec448_runners);

static struct cctest_algorithm_driver ccrsa_runners[] = {
    { .algorithm = "RSASSA-PKCS1-v1_5", .run = crypto_test_rsassa_runner },
    { .algorithm = "RSASSA-PSS", .run = crypto_test_rsassa_runner },
    { .algorithm = "RSAES-PKCS1-v1_5", .run = crypto_test_rsaes_runner },
    { .algorithm = "RSAES-OAEP", .run = crypto_test_rsaes_runner },
};
static const size_t ccrsa_runners_count = CC_ARRAY_LEN(ccrsa_runners);

static struct cctest_algorithm_driver ccprime_runners[] = {
    { .algorithm = "PrimalityTest", .run = crypto_test_primality_runner },
};
static const size_t ccprime_runners_count = CC_ARRAY_LEN(ccprime_runners);

static struct cctest_driver cctestvector_family_runners[] = {
    { .family = "ccchacha", .drivers = ccchacha_runners, .drivers_len = ccchacha_runners_len },
    { .family = "ccaes_modes", .drivers = ccaesmode_runners, .drivers_len = ccaesmode_runners_count },
    { .family = "cccmac", .drivers = cccmac_runners, .drivers_len = cccmac_runners_count },
    { .family = "ccec", .drivers = ccec_runners, .drivers_len = ccec_runners_count },
    { .family = "ccec25519", .drivers = ccec25519_runners, .drivers_len = ccec25519_runners_count },
    { .family = "ccec448", .drivers = ccec448_runners, .drivers_len = ccec448_runners_count },
    { .family = "ccrsa", .drivers = ccrsa_runners, .drivers_len = ccrsa_runners_count },
    { .family = "ccprime_rabin_miller", .drivers = ccprime_runners, .drivers_len = ccprime_runners_count },
};
static const size_t cctestvector_family_runners_count = CC_ARRAY_LEN(cctestvector_family_runners);

cctest_driver_t
cctest_driver_for_family(const char *family)
{
    size_t family_len = strlen(family);
    for (size_t i = 0; i < cctestvector_family_runners_count; i++) {
        const char *runner_family = cctestvector_family_runners[i].family;
        size_t runner_family_len = strlen(runner_family);
        if (family_len == runner_family_len && strncmp(runner_family, family, runner_family_len) == 0) {
            return &cctestvector_family_runners[i];
        }
    }
    return NULL;
}

static struct cctest_algorithm_driver *
cctest_get_algorithm_driver(cctest_driver_t driver, ccdict_t vector)
{
    size_t algorithm_len = 0;
    const char *algorithm = ccdict_get_value(vector, cctestvector_key_algorithm, &algorithm_len);
    if (algorithm != NULL) {
        for (size_t i = 0; i < driver->drivers_len; i++) {
            const char *runner_algorithm = driver->drivers[i].algorithm;
            size_t runner_algorithm_len = strlen(runner_algorithm);
            if (strncmp(algorithm, runner_algorithm, CC_MIN(algorithm_len, runner_algorithm_len)) == 0) {
                return &driver->drivers[i];
            }
        }
    }
    return NULL;
}

bool
cctest_driver_can_run(cctest_driver_t driver, ccdict_t vector)
{
    return cctest_get_algorithm_driver(driver, vector) != NULL;
}

bool
cctest_driver_run(cctest_driver_t test_driver, ccdict_t vector)
{
    struct cctest_algorithm_driver *driver = cctest_get_algorithm_driver(test_driver, vector);
    test_driver->num_tests++;
    bool result = driver->run(vector);
    if (!result) {
        test_driver->num_fails++;
    }
    return result;
}

int
cctest_driver_get_num_tests(cctest_driver_t driver)
{
    return driver->num_tests;
}

int
cctest_driver_get_num_failed_tests(cctest_driver_t driver)
{
    return driver->num_fails;
}
