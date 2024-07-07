/* Copyright (c) (2010-2012,2014-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccaes.h>
#include "ccmode_internal.h"
#include "cc_runtime_config.h"
#include <stdio.h>
#include <stdlib.h>
#include "crypto_test_aes_modes.h"
#include "ccmode_test.h"
#include <corecrypto/cc_error.h>

/*
 * AES (Advanced Encryption Standard - FIPS 197) ecb mode test vectors.
 */

static const struct ccmode_ecb_vector aes_ecb_vectors[] = {

    {
        16,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        1,
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        "\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a"
    },
    {
        24,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17",
        1,
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        "\xdd\xa9\x7c\xa4\x86\x4c\xdf\xe0\x6e\xaf\x70\xa0\xec\x0d\x71\x91"
    },
    {
        32,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
        1,
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        "\x8e\xa2\xb7\xca\x51\x67\x45\xbf\xea\xfc\x49\x90\x4b\x49\x60\x89"
    },

#include "../test_vectors/inc/ECBGFSbox128.inc"
#include "../test_vectors/inc/ECBGFSbox192.inc"
#include "../test_vectors/inc/ECBGFSbox256.inc"
#include "../test_vectors/inc/ECBKeySbox128.inc"
#include "../test_vectors/inc/ECBKeySbox192.inc"
#include "../test_vectors/inc/ECBKeySbox256.inc"
#include "../test_vectors/inc/ECBVarKey128.inc"
#include "../test_vectors/inc/ECBVarKey192.inc"
#include "../test_vectors/inc/ECBVarKey256.inc"
#include "../test_vectors/inc/ECBVarTxt128.inc"
#include "../test_vectors/inc/ECBVarTxt192.inc"
#include "../test_vectors/inc/ECBVarTxt256.inc"
};


/*
 * AES (Advanced Encryption Standard - FIPS 197) cbc mode test vectors.
 */

static const struct ccmode_cbc_vector aes_cbc_vectors[] = {
    {
        16,
        "\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        1,
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x97\x00\x14\xd6\x34\xe2\xb7\x65\x07\x77\xe8\xe8\x4d\x03\xcc\xd8"
    },
    {
        128,
        "\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        1,
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x97\x00\x14\xd6\x34\xe2\xb7\x65\x07\x77\xe8\xe8\x4d\x03\xcc\xd8"
    },
    
    {
        16,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        NULL, /* This is identical to all zeroes IV */
        1,
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        "\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a"
    },
    {
        16,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        1,
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        "\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a"
    },
    {
        16,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        1,
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a"
    },
    {
        16,
        "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a",
        "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58",
        2,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
        "\xd2\x96\xcd\x94\xc2\xcc\xcf\x8a\x3a\x86\x30\x28\xb5\xe1\xdc\x0a\x75\x86\x60\x2d\x25\x3c\xff\xf9\x1b\x82\x66\xbe\xa6\xd6\x1a\xb1"
    },
    {
        16,
        "\x56\xe4\x7a\x38\xc5\x59\x89\x74\xbc\x46\x90\x3d\xba\x29\x03\x49",
        "\x8c\xe8\x2e\xef\xbe\xa0\xda\x3c\x44\x69\x9e\xd7\xdb\x51\xb7\xd9",
        4,
        "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf",
        "\xc3\x0e\x32\xff\xed\xc0\x77\x4e\x6a\xff\x6a\xf0\x86\x9f\x71\xaa\x0f\x3a\xf0\x7a\x9a\x31\xa9\xc6\x84\xdb\x20\x7e\xb0\xef\x8e\x4e\x35\x90\x7a\xa6\x32\xc3\xff\xdf\x86\x8b\xb7\xb2\x9d\x3d\x46\xad\x83\xce\x9f\x9a\x10\x2e\xe9\x9d\x49\xa5\x3e\x87\xf4\xc3\xda\x55"
    },

#include "../test_vectors/inc/CBCGFSbox128.inc"
#include "../test_vectors/inc/CBCGFSbox192.inc"
#include "../test_vectors/inc/CBCGFSbox256.inc"
#include "../test_vectors/inc/CBCKeySbox128.inc"
#include "../test_vectors/inc/CBCKeySbox192.inc"
#include "../test_vectors/inc/CBCKeySbox256.inc"
#include "../test_vectors/inc/CBCVarKey128.inc"
#include "../test_vectors/inc/CBCVarKey192.inc"
#include "../test_vectors/inc/CBCVarKey256.inc"
#include "../test_vectors/inc/CBCVarTxt128.inc"
#include "../test_vectors/inc/CBCVarTxt192.inc"
#include "../test_vectors/inc/CBCVarTxt256.inc"

};

static const struct ccmode_cbc_failure_vector aes_cbc_failure_vectors[] = {
    {
        {
            15,
            "\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            1,
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            "\x97\x00\x14\xd6\x34\xe2\xb7\x65\x07\x77\xe8\xe8\x4d\x03\xcc\xd8",
        },
        CCERR_PARAMETER,
    },
    {
        {
        129,
        "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        1,
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xde\x88\x5d\xc8\x7f\x5a\x92\x59\x40\x82\xd0\x2c\xc1\xe1\xb4\x2c"
        },
        CCERR_PARAMETER,

    },
    {
        {
        193,
        "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        1,
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xde\x88\x5d\xc8\x7f\x5a\x92\x59\x40\x82\xd0\x2c\xc1\xe1\xb4\x2c"
        },
        CCERR_PARAMETER,

    },
    {
        {
        257,
        "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        1,
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xde\x88\x5d\xc8\x7f\x5a\x92\x59\x40\x82\xd0\x2c\xc1\xe1\xb4\x2c"
        },
        CCERR_PARAMETER,
    },
};

/*
 * AES (Advanced Encryption Standard - FIPS 197) cbc mode test vectors.
 */

static const struct ccmode_xts_vector aes_xts_vectors[] = {
    {
        16,
        "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11",
        "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22",
        "\x33\x33\x33\x33\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        32,
        "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44",
        "\xc4\x54\x18\x5e\x6a\x16\x93\x6e\x39\x33\x40\x38\xac\xef\x83\x8b\xfb\x18\x6f\xff\x74\x80\xad\xc4\x28\x93\x82\xec\xd6\xd3\x94\xf0"
    },
    {
        16,
        "\x46\xe6\xed\x9e\xf4\x2d\xcd\xb3\xc8\x93\x09\x3c\x28\xe1\xfc\x0f",
        "\x91\xf5\xca\xa3\xb6\xe0\xbc\x5a\x14\xe7\x83\x21\x5c\x1d\x5b\x61",
        "\x72\xf3\xb0\x54\xcb\xdc\x2f\x9e\x3c\x5b\xc5\x51\xd4\x4d\xdb\xa0",
        16,
        "\xe3\x77\x8d\x68\xe7\x30\xef\x94\x5b\x4a\xe3\xbc\x5b\x93\x6b\xdd",
        "\x97\x40\x9f\x1f\x71\xae\x45\x21\xcb\x49\xa3\x29\x73\xde\x4d\x05"
    },
    /* XTS-AES-128 for non multiple of 16 bytes of data. */
    {
        16,
        "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0",
        "\xbf\xbe\xbd\xbc\xbb\xba\xb9\xb8\xb7\xb6\xb5\xb4\xb3\xb2\xb1\xb0",
        "\x9a\x78\x56\x34\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        17,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
        "\x6c\x16\x25\xdb\x46\x71\x52\x2d\x3d\x75\x99\x60\x1d\xe7\xca\x09\xed"
    },
    {
        16,
        "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0",
        "\xbf\xbe\xbd\xbc\xbb\xba\xb9\xb8\xb7\xb6\xb5\xb4\xb3\xb2\xb1\xb0",
        "\x9a\x78\x56\x34\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        18,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11",
        "\xd0\x69\x44\x4b\x7a\x7e\x0c\xab\x09\xe2\x44\x47\xd2\x4d\xeb\x1f\xed\xbf",
    },
    {
        16,
        "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0",
        "\xbf\xbe\xbd\xbc\xbb\xba\xb9\xb8\xb7\xb6\xb5\xb4\xb3\xb2\xb1\xb0",
        "\x9a\x78\x56\x34\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        19,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12",
        "\xe5\xdf\x13\x51\xc0\x54\x4b\xa1\x35\x0b\x33\x63\xcd\x8e\xf4\xbe\xed\xbf\x9d",
    },
    {
        16,
        "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0",
        "\xbf\xbe\xbd\xbc\xbb\xba\xb9\xb8\xb7\xb6\xb5\xb4\xb3\xb2\xb1\xb0",
        "\x9a\x78\x56\x34\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        20,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13",
        "\x9d\x84\xc8\x13\xf7\x19\xaa\x2c\x7b\xe3\xf6\x61\x71\xc7\xc5\xc2\xed\xbf\x9d\xac",
    },
    /* XTS-AES-128 for 128 bytes of data. */
    {
        16,
        "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef",
        "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf",
        "\x21\x43\x65\x87\xa9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        128,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
        "\x38\xb4\x58\x12\xef\x43\xa0\x5b\xd9\x57\xe5\x45\x90\x7e\x22\x3b\x95\x4a\xb4\xaa\xf0\x88\x30\x3a\xd9\x10\xea\xdf\x14\xb4\x2b\xe6\x8b\x24\x61\x14\x9d\x8c\x8b\xa8\x5f\x99\x2b\xe9\x70\xbc\x62\x1f\x1b\x06\x57\x3f\x63\xe8\x67\xbf\x58\x75\xac\xaf\xa0\x4e\x42\xcc\xbd\x7b\xd3\xc2\xa0\xfb\x1f\xff\x79\x1e\xc5\xec\x36\xc6\x6a\xe4\xac\x1e\x80\x6d\x81\xfb\xf7\x09\xdb\xe2\x9e\x47\x1f\xad\x38\x54\x9c\x8e\x66\xf5\x34\x5d\x7c\x1e\xb9\x4f\x40\x5d\x1e\xc7\x85\xcc\x6f\x6a\x68\xf6\x25\x4d\xd8\x33\x9f\x9d\x84\x05\x7e\x01\xa1\x77\x41\x99\x04\x82\x99\x95\x16\xb5\x61\x1a\x38\xf4\x1b\xb6\x47\x8e\x6f\x17\x3f\x32\x08\x05\xdd\x71\xb1\x93\x2f\xc3\x33\xcb\x9e\xe3\x99\x36\xbe\xea\x9a\xd9\x6f\xa1\x0f\xb4\x11\x2b\x90\x17\x34\xdd\xad\x40\xbc\x18\x78\x99\x5f\x8e\x11\xae\xe7\xd1\x41\xa2\xf5\xd4\x8b\x7a\x4e\x1e\x7f\x0b\x2c\x04\x83\x0e\x69\xa4\xfd\x13\x78\x41\x1c\x2f\x28\x7e\xdf\x48\xc6\xc4\xe5\xc2\x47\xa1\x96\x80\xf7\xfe\x41\xce\xfb\xd4\x9b\x58\x21\x06\xe3\x61\x6c\xbb\xe4\xdf\xb2\x34\x4b\x2a\xe9\x51\x93\x91\xf3\xe0\xfb\x49\x22\x25\x4b\x1d\x6d\x2d\x19\xc6\xd4\xd5\x37\xb3\xa2\x6f\x3b\xcc\x51\x58\x8b\x32\xf3\xec\xa0\x82\x9b\x6a\x5a\xc7\x25\x78\xfb\x81\x4f\xb4\x3c\xf8\x0d\x64\xa2\x33\xe3\xf9\x97\xa3\xf0\x26\x83\x34\x2f\x2b\x33\xd2\x5b\x49\x25\x36\xb9\x3b\xec\xb2\xf5\xe1\xa8\xb8\x2f\x5b\x88\x33\x42\x72\x9e\x8a\xe0\x9d\x16\x93\x88\x41\xa2\x1a\x97\xfb\x54\x3e\xea\x3b\xbf\xf5\x9f\x13\xc1\xa1\x84\x49\xe3\x98\x70\x1c\x1a\xd5\x16\x48\x34\x6c\xbc\x04\xc2\x7b\xb2\xda\x3b\x93\xa1\x37\x2c\xca\xe5\x48\xfb\x53\xbe\xe4\x76\xf9\xe9\xc9\x17\x73\xb1\xbb\x19\x82\x83\x94\xd5\x5d\x3e\x1a\x20\xed\x69\x11\x3a\x86\x0b\x68\x29\xff\xa8\x47\x22\x46\x04\x43\x50\x70\x22\x1b\x25\x7e\x8d\xff\x78\x36\x15\xd2\xca\xe4\x80\x3a\x93\xaa\x43\x34\xab\x48\x2a\x0a\xfa\xc9\xc0\xae\xda\x70\xb4\x5a\x48\x1d\xf5\xde\xc5\xdf\x8c\xc0\xf4\x23\xc7\x7a\x5f\xd4\x6c\xd3\x12\x02\x1d\x4b\x43\x88\x62\x41\x9a\x79\x1b\xe0\x3b\xb4\xd9\x7c\x0e\x59\x57\x85\x42\x53\x1b\xa4\x66\xa8\x3b\xaf\x92\xce\xfc\x15\x1b\x5c\xc1\x61\x1a\x16\x78\x93\x81\x9b\x63\xfb\x8a\x6b\x18\xe8\x6d\xe6\x02\x90\xfa\x72\xb7\x97\xb0\xce\x59\xf3"
    },

#include "../test_vectors/inc/XTSGenAES128.inc"
#include "../test_vectors/inc/XTSGenAES256.inc"

};

static const struct ccmode_ofb_vector aes_ofb_vectors[] = {
#include "../test_vectors/inc/OFBGFSbox128.inc"
#include "../test_vectors/inc/OFBGFSbox192.inc"
#include "../test_vectors/inc/OFBGFSbox256.inc"
#include "../test_vectors/inc/OFBKeySbox128.inc"
#include "../test_vectors/inc/OFBKeySbox192.inc"
#include "../test_vectors/inc/OFBKeySbox256.inc"
#include "../test_vectors/inc/OFBVarKey128.inc"
#include "../test_vectors/inc/OFBVarKey192.inc"
#include "../test_vectors/inc/OFBVarKey256.inc"
#include "../test_vectors/inc/OFBVarTxt128.inc"
#include "../test_vectors/inc/OFBVarTxt192.inc"
#include "../test_vectors/inc/OFBVarTxt256.inc"
};

static const struct ccmode_cfb_vector aes_cfb_vectors[] = {
#include "../test_vectors/inc/CFB128GFSbox128.inc"
#include "../test_vectors/inc/CFB128GFSbox192.inc"
#include "../test_vectors/inc/CFB128GFSbox256.inc"
#include "../test_vectors/inc/CFB128KeySbox128.inc"
#include "../test_vectors/inc/CFB128KeySbox192.inc"
#include "../test_vectors/inc/CFB128KeySbox256.inc"
#include "../test_vectors/inc/CFB128VarKey128.inc"
#include "../test_vectors/inc/CFB128VarKey192.inc"
#include "../test_vectors/inc/CFB128VarKey256.inc"
#include "../test_vectors/inc/CFB128VarTxt128.inc"
#include "../test_vectors/inc/CFB128VarTxt192.inc"
#include "../test_vectors/inc/CFB128VarTxt256.inc"
};

static const struct ccmode_cfb8_vector aes_cfb8_vectors[] = {
#include "../test_vectors/inc/CFB8GFSbox128.inc"
#include "../test_vectors/inc/CFB8GFSbox192.inc"
#include "../test_vectors/inc/CFB8GFSbox256.inc"
#include "../test_vectors/inc/CFB8KeySbox128.inc"
#include "../test_vectors/inc/CFB8KeySbox192.inc"
#include "../test_vectors/inc/CFB8KeySbox256.inc"
#include "../test_vectors/inc/CFB8VarKey128.inc"
#include "../test_vectors/inc/CFB8VarKey192.inc"
#include "../test_vectors/inc/CFB8VarKey256.inc"
#include "../test_vectors/inc/CFB8VarTxt128.inc"
#include "../test_vectors/inc/CFB8VarTxt192.inc"
#include "../test_vectors/inc/CFB8VarTxt256.inc"
};

static const struct ccmode_gcm_vector aes_gcm_vectors[] = {
#include "../test_vectors/inc/gcmEncryptExtIV128.inc"
#include "../test_vectors/inc/gcmEncryptExtIV192.inc"
#include "../test_vectors/inc/gcmEncryptExtIV256.inc"
};

static const struct ccmode_ccm_vector aes_ccm_vectors[] = {
#include "../test_vectors/inc/ccmVADT128rsp.inc"
#include "../test_vectors/inc/ccmVADT192rsp.inc"
#include "../test_vectors/inc/ccmVADT256rsp.inc"
};

static void cbc(char *name, const struct ccmode_cbc *enc, const struct ccmode_cbc * dec)
{
    unsigned int numVectors = (unsigned int)CC_ARRAY_LEN(aes_cbc_vectors);
    for(unsigned int i=0; i<numVectors; i++)
    {
        const struct ccmode_cbc_vector *v=&aes_cbc_vectors[i];

        is(ccmode_cbc_test_one_vector(enc, v, 0), 0, "Encrypt Vector %d %s", i, name);
        is(ccmode_cbc_test_one_vector(dec, v, 1), 0, "Decrypt Vector %d %s", i, name);

        is(ccmode_cbc_test_one_vector_chained(enc, v, 0), 0, "Encrypt Chained Vector %d %s", i, name);
        is(ccmode_cbc_test_one_vector_chained(dec, v, 1), 0, "Decrypt Chained Vector %d %s", i, name);

        /* Self test with 2 blocks */
        is(ccmode_cbc_test_key_self(enc, dec, 2, v->keylen, v->key, 1000), 0, "Self Test Key %d %s", i, name);

        /* Chaining test with 2 blocks */
        is(ccmode_cbc_test_chaining_self(enc, dec, 2, v->keylen, v->key, 1000), 0, "Chaining Test Key %d %s", i, name);
    }
    unsigned int numFailVectors = (unsigned int)CC_ARRAY_LEN(aes_cbc_failure_vectors);
    for(unsigned int i=0; i<numFailVectors; i++)
    {
        const struct ccmode_cbc_failure_vector *v=&aes_cbc_failure_vectors[i];

        is(ccmode_cbc_test_one_vector(enc, &v->cbc_vector, 0), v->expected_error, "Encrypt Vector %d %s", i, name);
        is(ccmode_cbc_test_one_vector(dec, &v->cbc_vector, 1), v->expected_error, "Decrypt Vector %d %s", i, name);

        is(ccmode_cbc_test_one_vector_chained(enc, &v->cbc_vector, 0), v->expected_error, "Encrypt Chained Vector %d %s", i, name);
        is(ccmode_cbc_test_one_vector_chained(dec, &v->cbc_vector, 1), v->expected_error, "Decrypt Chained Vector %d %s", i, name);

        /* Self test with 2 blocks */
        is(ccmode_cbc_test_key_self(enc, dec, 2, v->cbc_vector.keylen, v->cbc_vector.key, 1000), v->expected_error, "Self Test Key %d %s", i, name);

        /* Chaining test with 2 blocks */
        is(ccmode_cbc_test_chaining_self(enc, dec, 2, v->cbc_vector.keylen, v->cbc_vector.key, 1000), v->expected_error, "Chaining Test Key %d %s", i, name);
    }

    
}

static void testAES_CBC(void)
{
    cbc("default", ccaes_cbc_encrypt_mode(),  ccaes_cbc_decrypt_mode());
}

static void testAES_CBC_Factory(void)
{
    struct ccmode_cbc factory_enc;
    struct ccmode_cbc factory_dec;

    ccmode_factory_cbc_encrypt(&factory_enc,ccaes_ecb_encrypt_mode());
    ccmode_factory_cbc_decrypt(&factory_dec,ccaes_ecb_decrypt_mode());

    cbc("factory", &factory_enc, &factory_dec);
}

static void testAES_CBC_Gladman(void)
{
    cbc("gladman", &ccaes_gladman_cbc_encrypt_mode, &ccaes_gladman_cbc_decrypt_mode);
}

static void testAES_CBC_Intel_Opt_ASM(void)
{
#if CCAES_INTEL_ASM
    cbc("intel opt asm", &ccaes_intel_cbc_encrypt_opt_mode, &ccaes_intel_cbc_decrypt_opt_mode);
#endif
}

static void testAES_CBC_Intel_AES_NI(void)
{
#if CCAES_INTEL_ASM
    if (CC_HAS_AESNI())
    {
        cbc("intel AESNI", &ccaes_intel_cbc_encrypt_aesni_mode, &ccaes_intel_cbc_decrypt_aesni_mode);
    }
#endif /* CCAES_INTEL_ASM */

}


static void ofb(const char *name, const struct ccmode_ofb* enc)
{
    unsigned int numVectors = (unsigned int)CC_ARRAY_LEN(aes_ofb_vectors);
    for(unsigned int i=0; i<numVectors; i++)
    {
        const struct ccmode_ofb_vector *v=&aes_ofb_vectors[i];

        is(ccmode_ofb_test_one_vector(enc, v, 0), 0, "Encrypt Vector %d %s", i, name);
        is(ccmode_ofb_test_one_vector(enc, v, 1), 0, "Decrypt Vector %d %s", i, name);

        is(ccmode_ofb_test_one_vector_chained(enc, v, 0), 0, "Encrypt Chained Vector %d %s", i, name);
        is(ccmode_ofb_test_one_vector_chained(enc, v, 1), 0, "Decrypt Chained Vector %d %s", i, name);
    }
}

static void testAES_OFB(void)
{
    ofb("default", ccaes_ofb_crypt_mode());
}

static void testAES_OFB_Factory(void)
{
    struct ccmode_ofb factory_enc;
    ccmode_factory_ofb_crypt(&factory_enc, ccaes_ecb_encrypt_mode());

    ofb("factory", &factory_enc);
}

static void cfb(const char *name, const struct ccmode_cfb* enc, const struct ccmode_cfb *dec)
{
    unsigned int numVectors = (unsigned int)CC_ARRAY_LEN(aes_cfb_vectors);
    for(unsigned int i=0; i<numVectors; i++)
    {
        const struct ccmode_cfb_vector *v=&aes_cfb_vectors[i];

        is(ccmode_cfb_test_one_vector(enc, v, 0), 0, "Encrypt Vector %d %s", i, name);
        is(ccmode_cfb_test_one_vector(dec, v, 1), 0, "Decrypt Vector %d %s", i, name);

        is(ccmode_cfb_test_one_vector_chained(enc, v, 0), 0, "Encrypt Chained Vector %d %s", i, name);
        is(ccmode_cfb_test_one_vector_chained(dec, v, 1), 0, "Decrypt Chained Vector %d %s", i, name);
    }
}

static void testAES_CFB(void)
{
    cfb("default", ccaes_cfb_encrypt_mode(), ccaes_cfb_decrypt_mode());
}

static void testAES_CFB_Factory(void)
{
    struct ccmode_cfb factory_enc;
    struct ccmode_cfb factory_dec;

    ccmode_factory_cfb_encrypt(&factory_enc, ccaes_ecb_encrypt_mode());
    ccmode_factory_cfb_decrypt(&factory_dec, ccaes_ecb_encrypt_mode());
    cfb("factory", &factory_enc, &factory_dec);
}


static void cfb8(const char *name, const struct ccmode_cfb8* enc, const struct ccmode_cfb8 *dec)
{
    unsigned int numVectors = (unsigned int)CC_ARRAY_LEN(aes_cfb8_vectors);
    for(unsigned int i=0; i<numVectors; i++)
    {
        const struct ccmode_cfb8_vector *v=&aes_cfb8_vectors[i];

        is(ccmode_cfb8_test_one_vector(enc, v, 0), 0, "Encrypt Vector %d %s", i, name);
        is(ccmode_cfb8_test_one_vector(dec, v, 1), 0, "Decrypt Vector %d %s", i, name);

        is(ccmode_cfb8_test_one_vector_chained(enc, v, 0), 0, "Encrypt Chained Vector %d %s", i, name);
        is(ccmode_cfb8_test_one_vector_chained(dec, v, 1), 0, "Decrypt Chained Vector %d %s", i, name);
    }
}

static void testAES_CFB8(void)
{
    cfb8("default", ccaes_cfb8_encrypt_mode(), ccaes_cfb8_decrypt_mode());
}

static void testAES_CFB8_Factory(void)
{
    struct ccmode_cfb8 factory_enc;
    struct ccmode_cfb8 factory_dec;

    ccmode_factory_cfb8_encrypt(&factory_enc, ccaes_ecb_encrypt_mode());
    ccmode_factory_cfb8_decrypt(&factory_dec, ccaes_ecb_encrypt_mode());

    cfb8("factory", &factory_enc, &factory_dec);
}

static void gcm(const char *name, const struct ccmode_gcm* enc, const struct ccmode_gcm *dec)
{
    unsigned int numVectors = (unsigned int)CC_ARRAY_LEN(aes_gcm_vectors);
    for(unsigned int i=0; i<numVectors; i++)
    {
        const struct ccmode_gcm_vector *v=&aes_gcm_vectors[i];
        
        is(ccmode_gcm_test_one_vector(enc, v, 0), 0, "Encrypt Vector %d %s", i, name);
        is(ccmode_gcm_test_one_vector(dec, v, 1), 0, "Decrypt Vector %d %s", i, name);

        is(ccmode_gcm_test_one_vector_chained(enc, v, 0), 0, "Encrypt Chained Vector %d %s", i, name);
        is(ccmode_gcm_test_one_vector_chained(dec, v, 1), 0, "Decrypt Chained Vector %d %s", i, name);
        
    }
}

static void testAES_GCM(void)
{
    gcm("default", ccaes_gcm_encrypt_mode(), ccaes_gcm_decrypt_mode());
}

static void testAES_GCM_Factory(void)
{
    struct ccmode_gcm factory_enc;
    struct ccmode_gcm factory_dec;

    ccmode_factory_gcm_encrypt(&factory_enc, ccaes_ecb_encrypt_mode());
    ccmode_factory_gcm_decrypt(&factory_dec, ccaes_ecb_encrypt_mode());

    gcm("factory", &factory_enc, &factory_dec);
}


static void ecb(const char *name, const struct ccmode_ecb *enc, const struct ccmode_ecb *dec)
{
    unsigned int numVectors = (unsigned int)CC_ARRAY_LEN(aes_ecb_vectors);
    for(unsigned int i=0; i<numVectors; i++)
    {
        const struct ccmode_ecb_vector *v=&aes_ecb_vectors[i];

        is(ccmode_ecb_test_one_vector(enc, v, 0), 0, "Encrypt Vector %d %s", i, name);
        is(ccmode_ecb_test_one_vector(dec, v, 1), 0, "Decrypt Vector %d %s", i, name);

        /* Self test with 2 blocks */
        is(ccmode_ecb_test_key_self(enc, dec, 2, v->keylen, v->key, 1000), 0, "Self Test Key %d %s", i, name);
        /* Self test with 3 blocks */
        is(ccmode_ecb_test_key_self(enc, dec, 3, v->keylen, v->key, 100), 0, "Self Test Key %d %s", i, name);
        /* Self test with 4 blocks */
        is(ccmode_ecb_test_key_self(enc, dec, 4, v->keylen, v->key, 100), 0, "Self Test Key %d %s", i, name);
        /* Self test with 10 blocks */
        is(ccmode_ecb_test_key_self(enc, dec, 10, v->keylen, v->key, 100), 0, "Self Test Key %d %s", i, name);
    }
}

static void testAES_ECB(void)
{
    ecb("default", ccaes_ecb_encrypt_mode(), ccaes_ecb_decrypt_mode());
}

static void testAES_ECB_LTC(void)
{
    ecb("ltc", &ccaes_ltc_ecb_encrypt_mode, &ccaes_ltc_ecb_decrypt_mode);
}


#if CCAES_INTEL_ASM
static void testAES_ECB_INTEL_Opt(void)
{
    ecb("intel opt", &ccaes_intel_ecb_encrypt_opt_mode, &ccaes_intel_ecb_decrypt_opt_mode);
}

static void testAES_ECB_INTEL_NI(void)
{
    if (CC_HAS_AESNI())
    {
        ecb("intel AESNI", &ccaes_intel_ecb_encrypt_aesni_mode, &ccaes_intel_ecb_decrypt_aesni_mode);
    }
}
#endif /* CCAES_INTEL_ASM */


static void xts(const char *name, const struct ccmode_xts*enc, const struct ccmode_xts *dec)
{
    int rc;
    unsigned int numVectors = (unsigned int)CC_ARRAY_LEN(aes_xts_vectors);
    for (unsigned int i = 0; i < numVectors; ++i)
    {
        const struct ccmode_xts_vector *v = &aes_xts_vectors[i];
        uint8_t temp[v->nbytes];

        rc = ccmode_xts_test_one_vector(enc, v, temp, 0);
        is(rc, 0, "Encrypt Vector %d %s nonzero return code", i, name);
        ok_memcmp(temp, v->ct, v->nbytes,"Encrypt Vector %d %s failed comparison", i, name);

        rc = ccmode_xts_test_one_vector(dec, v, temp, 1);
        is(rc, 0, "Decrypt Vector %d %s nonzero return code", i, name);
        ok_memcmp(temp, v->pt, v->nbytes,"Decrypt Vector %d %s failed comparison", i, name);

        
        rc = ccmode_xts_test_one_vector_chained(enc, v, temp, 0);
        is(rc, 0, "Encrypt Chained Vector %d %s nonzero return code", i, name);
        ok_memcmp(temp, v->ct, v->nbytes,"Encrypt Chained Vector %d %s failed comparison", i, name);

        rc = ccmode_xts_test_one_vector_chained(dec, v, temp, 1);
        is(rc, 0, "Decrypt Chained Vector %d %s nonzero return code", i, name);
        ok_memcmp(temp, v->pt, v->nbytes,"Decrypt Chained Vector %d %s failed comparison", i, name);

#if 0
        /* Self test with 2 blocks */
        XCAssertEquals(0, ccmode_xts_test_key_self(enc, dec, 2, v->keylen, v->key, 1000)==0, "Self Test Key %d %s", i, name);

        /* Chaining test with 2 blocks */
        XCAssertEquals(0, ccmode_xts_test_chaining_self(enc, dec, 2, v->keylen, v->key, 1000)==0, "Chaining Test Key %d %s", i, name);
#endif
    }
}

static void testAES_XTS(void)
{
    xts("default", ccaes_xts_encrypt_mode(), ccaes_xts_decrypt_mode());
}

static void testAES_XTS_Factory(void)
{
    struct ccmode_xts factory_enc;
    struct ccmode_xts factory_dec;

    ccmode_factory_xts_encrypt(&factory_enc, ccaes_ecb_encrypt_mode(), ccaes_ecb_encrypt_mode());
    ccmode_factory_xts_decrypt(&factory_dec, ccaes_ecb_decrypt_mode(), ccaes_ecb_encrypt_mode());

    xts("factory", &factory_enc, &factory_dec);
}


#if CCAES_INTEL_ASM
static void testAES_XTS_INTEL_Opt(void)
{
    xts("intel opt", &ccaes_intel_xts_encrypt_opt_mode, &ccaes_intel_xts_decrypt_opt_mode);
}

static void testAES_XTS_INTEL_NI(void)
{
    if (CC_HAS_AESNI())
    {
        xts("intel AESNI", &ccaes_intel_xts_encrypt_aesni_mode, &ccaes_intel_xts_decrypt_aesni_mode);
    }
}
#endif /* CCAES_INTEL_ASM */

static void ccm(const char*name, const struct ccmode_ccm *enc, const struct ccmode_ccm *dec)
{
    unsigned int i;
    unsigned int numVectors = (unsigned int)CC_ARRAY_LEN(aes_ccm_vectors);
    
    // Testing for different sizes of adata in ccm mode using AES128.
    struct iterated_adata_ccm_test_vector large_adata_vec_array[] = {
#include "../../ccmode/test_vectors/ccm_aes_128_long_adata_test_vectors.inc"
        
    };
    unsigned int large_adata_vec_array_length = CC_ARRAY_LEN(large_adata_vec_array);

    for (i = 0; i < large_adata_vec_array_length; i++)
    {
        struct iterated_adata_ccm_test_vector *tmp_lvec=&(large_adata_vec_array[i]);
        struct ccmode_ccm_vector v;
        
        v.key = tmp_lvec->key;
        v.keylen = tmp_lvec->key_n;
        v.nonce = tmp_lvec->nonce;
        v.noncelen = tmp_lvec->nonce_n;
        v.ct = tmp_lvec->full_ciphertext;
        v.ctlen = tmp_lvec->full_ciphertext_n;
        v.pt = tmp_lvec->pdata;
        v.ptlen = tmp_lvec-> pdata_n;
        v.adalen = tmp_lvec->aData_iterated_string_n * tmp_lvec->aData_num_of_iterations;
        
        // Generate adata by concatenating string appropriate number of times.
        char *tmp_adata = malloc(v.adalen);
        for (size_t j = 0; j < tmp_lvec->aData_num_of_iterations; j++) {
            memcpy(&tmp_adata[j*tmp_lvec->aData_iterated_string_n], tmp_lvec->iterated_string, tmp_lvec->aData_iterated_string_n);
        }
        v.ada = tmp_adata;
        
        // Perform tests.
        is(ccmode_ccm_test_one_vector(enc, &v, 0, 0), 0, "Encrypt Vector %d %s\nKeyLength is : %zu\n Size is %zu", i, "Long authenticated Data test",v.keylen, enc->size);
        is(ccmode_ccm_test_one_vector(dec, &v, 1, 0), 0, "Decrypt Vector %d %s\nKey Length is : %zu\n Size is %zu", i, "Long authenticated Data test", v.keylen,dec->size);
        free(tmp_adata);
    }
    
    for(i=0; i<numVectors; i++) {
        const struct ccmode_ccm_vector *v = &aes_ccm_vectors[i];

        is(ccmode_ccm_test_one_vector(enc, v, 0, 0), 0, "Encrypt Vector %d %s", i, name);
        is(ccmode_ccm_test_one_vector(dec, v, 1, 0), 0, "Decrypt Vector %d %s", i, name);

        is(ccmode_ccm_test_one_vector(enc, v, 0, 1), 0, "Encrypt Chained Vector %d %s", i, name);
        is(ccmode_ccm_test_one_vector(dec, v, 1, 1), 0, "Decrypt Chained Vector %d %s", i, name);
    }
}

static void testAES_CCM(void)
{
    ccm("default", ccaes_ccm_encrypt_mode(), ccaes_ccm_decrypt_mode());
}

static void testAES_CCM_Factory(void)
{
    struct ccmode_ccm generic_enc;
    struct ccmode_ccm generic_dec;

    ccmode_factory_ccm_encrypt(&generic_enc,ccaes_ecb_encrypt_mode());
    ccmode_factory_ccm_decrypt(&generic_dec,ccaes_ecb_encrypt_mode());

    ccm("factory", &generic_enc, &generic_dec);
}

void aes_validation_test(void)
{
    testAES_OFB();
    testAES_OFB_Factory();
    testAES_CFB();
    testAES_CFB_Factory();
    testAES_CFB8();
    testAES_CFB8_Factory();
    testAES_GCM();
    testAES_GCM_Factory();
    testAES_ECB();
    testAES_ECB_LTC();
    testAES_XTS();
    testAES_XTS_Factory();
    testAES_CCM();
    testAES_CCM_Factory();
    testAES_CBC();
    testAES_CBC_Factory();
    testAES_CBC_Gladman();
    testAES_CBC_Intel_Opt_ASM();
    testAES_CBC_Intel_AES_NI();
#if CCAES_INTEL_ASM
    testAES_ECB_INTEL_Opt();
    testAES_ECB_INTEL_NI();
    testAES_XTS_INTEL_Opt();
    testAES_XTS_INTEL_NI();
#endif
}
