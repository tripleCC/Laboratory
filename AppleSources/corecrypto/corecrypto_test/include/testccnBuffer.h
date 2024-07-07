/* Copyright (c) (2012,2015,2019,2020,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CCNBUFFER_H_
#define _CCNBUFFER_H_

#include <corecrypto/ccn.h>

typedef struct ccn_buf {
    cc_size  len;
    cc_unit  *units;
} ccnBufferStruct, *ccnBuffer;

ccnBuffer mallocCcnBuffer(size_t len);

ccnBuffer hexStringToCcn(const char *inhex);

int ccnAreEqual(ccnBuffer b1, ccnBuffer b2);

#endif /* _CCNBUFFER_H_ */
