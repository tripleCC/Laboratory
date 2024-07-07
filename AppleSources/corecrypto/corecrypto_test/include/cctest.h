/* Copyright (c) (2010,2011,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCTEST_H_
#define _CORECRYPTO_CCTEST_H_

#include <stdlib.h>

/* bin is n byte buffer into which a 2n byte long hex string is converted. */
void cc_hex2bin(size_t n, unsigned char *bin, const char *hex);

/* bin is n byte buffer which is converted into 2n + 1 byte long 0 terminated
   string in hex. */
void cc_bin2hex(size_t n, char *hex, const unsigned char *bin);


#define CCTEST_MAX_MSG_SIZE   8192

struct cctest_result {
    double duration;
    const char *msg;   /* points to msg_buffer in cctest_input  */
};

struct cctest_input {
    double start;
    char msg_buffer[CCTEST_MAX_MSG_SIZE];
    struct cctest_result(*cctest_function)(const struct cctest_input *input);
};

#endif /* _CORECRYPTO_CCTEST_H_ */
