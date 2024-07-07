/* Copyright (c) (2011,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccperf.h"

void ccperf_family_select(struct ccperf_family *f, size_t ntests, void *tests, size_t testsz,
                          int argc CC_UNUSED, char **argv CC_UNUSED)
{
    size_t i;
    int j;

    /* alloc the maximum tests */
    f->tests = malloc(ntests*sizeof(struct ccperf_test *));

    if(argc==0) {
        f->ntests = ntests;
        for(i=0; i<ntests; i++) {
            f->tests[i]=(struct ccperf_test *)tests;
            tests = (void *)((uint8_t *)tests + testsz);
        }
    } else {
        f->ntests = 0;
        for(i=0; i<ntests; i++) {
            struct ccperf_test *t=tests;
            for(j=0; j<argc; j++) {
                if(strcmp(argv[j], t->name)==0) {
                    f->tests[f->ntests++]=t;
                }
            }
            tests = (void *)((uint8_t *)tests + testsz);
        }
    }
}
