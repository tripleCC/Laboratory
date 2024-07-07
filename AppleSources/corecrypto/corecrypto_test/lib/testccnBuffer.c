/* Copyright (c) (2012,2015,2016,2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "testmore.h"
#include "testccnBuffer.h"
#include "testbyteBuffer.h"
#include <stdlib.h>

ccnBuffer
mallocCcnBuffer(size_t len) {
	ccnBuffer retval;
    cc_size n = ccn_nof_size(len);
	if((retval = (ccnBuffer) malloc(sizeof(ccnBufferStruct) + n * sizeof(cc_unit))) == NULL) return NULL;
    retval->len = n;
    retval->units = (cc_unit *) (retval + 1) ; /* just past the ccnBuffer in malloc'ed space */
    return retval;
}


ccnBuffer
hexStringToCcn(const char *inhex) {
    byteBuffer value = hexStringToBytes(inhex);
    ccnBuffer retval = mallocCcnBuffer(value->len);
    int status = ccn_read_uint(retval->len, retval->units, value->len, value->bytes);
    free(value);
    if(status) {
        free(retval);
        retval = NULL;
    }
    return retval;
}

int
ccnAreEqual(ccnBuffer b1, ccnBuffer b2) {
    size_t n1 = b1->len;
    size_t n2 = b2->len;
    while(b1->units[n1-1] == 0) n1--;
    while(b2->units[n2-1] == 0) n2--;
    return ccn_cmpn(n1, b1->units, n2, b2->units) == 0;
}

