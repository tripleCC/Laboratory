/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef cctest_driver_h
#define cctest_driver_h

#include <stdint.h>
#include <stdbool.h>

#include "ccdict.h"

#include <corecrypto/cc.h>

/*!
 * @abstract Abstract type for a test vector driver.
 */
struct cctest_driver;
typedef struct cctest_driver *cctest_driver_t;

/*!
 * @function cctestvector_driver_run_for_family
 * @abstract Run a test vector with the test vector data.
 * @param family Name of the test family being run.
 * @return A `cctest_driver_t` to run the test, or NULL if one is not present.
 */
CC_NONNULL((1))
cctest_driver_t
cctest_driver_for_family(const char *family);

/*!
 * @function cctest_driver_can_run
 * @abstract Determine if a given driver can run the given test vector.
 * @param driver A `cctest_driver_t`
 * @param vector A candidate test vector.
 * @return True iff driver can run vector.
 */
CC_NONNULL((1,2))
bool
cctest_driver_can_run(cctest_driver_t driver, ccdict_t vector);

/*!
 * @function cctest_driver_run
 * @abstract Run a test vector with the test vector data.
 * @param driver A `cctest_driver_t` instance to run the test vector.
 * @param test_vector_data A `ccdict_t` containing all the relevant test vector data.
 * @return True if the test passed, and false otherwise.
 */
CC_NONNULL((1))
bool
cctest_driver_run(cctest_driver_t driver, ccdict_t test_vector_data);

/*!
 * @function cctest_driver_get_num_tests
 * @abstract Get the total number of tests run.
 * @param driver A `cctest_driver_t` instance.
 * @return Number of run tests.
 */
CC_NONNULL((1))
int
cctest_driver_get_num_tests(cctest_driver_t driver);

/*!
 * @function cctest_driver_get_num_failed_tests
 * @abstract Get the total number of failed tests run.
 * @param driver A `cctest_driver_t` instance.
 * @return Number of failed run tests.
 */
CC_NONNULL((1))
int
cctest_driver_get_num_failed_tests(cctest_driver_t driver);

#endif /* cctest_driver_h */
