/* Copyright (c) (2014,2015,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_ccstats_h
#define corecrypto_ccstats_h

#include "testmore.h"
#include <inttypes.h>
#include "cc_runtime_config.h"

//#define  PRINT_IN_FILE 1
#ifndef PRINT_IN_FILE
#define PRINT_IN_FILE 0
#endif

struct standard_deviation {
    unsigned int n;       // Total
    double M;
    double S;
    unsigned int k;       // For stat computation
#if PRINT_IN_FILE
    FILE *s_file;
#endif
};

typedef struct {
    uint64_t timing;
    uint32_t group;
    double rank;
} measurement_t;

void standard_deviation_init(struct standard_deviation *sd);

void standard_deviation_add_first(struct standard_deviation *sd, double x);

void standard_deviation_add(struct standard_deviation *sd, double x);

double standard_deviation_sigma(const struct standard_deviation *sd);

int T_test_isRejected(measurement_t *samples,size_t len);

int WilcoxonRankSumTest(measurement_t *samples,size_t len);

void export_measurement_to_file(char *file_name,measurement_t *samples,size_t len);

struct units { const char *name; double scale; };
struct units dur2units(double duration);

#endif
