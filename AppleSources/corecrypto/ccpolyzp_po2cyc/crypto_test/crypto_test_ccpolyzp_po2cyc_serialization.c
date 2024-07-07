/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "crypto_test_ccpolyzp_po2cyc.h"
#include "testmore.h"
#include "testbyteBuffer.h"
#include "ccpolyzp_po2cyc_serialization.h"
#include "ccpolyzp_po2cyc_random.h"
#include "ccpolyzp_po2cyc_debug.h"

static void test_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_error(void)
{
    uint8_t bytes[] = { 3, 24, 95, 141, 179, 34, 113 };
    ccrns_int coeffs[] = { 0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1 };
    const static size_t bits_per_coeff = 4;
    // ok
    is(ccpolyzp_po2cyc_bytes_to_coeffs(CC_ARRAY_LEN(coeffs), coeffs, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, 0),
       CCERR_OK,
       "bytes_to_coeffs error");

    // bits_per_coeff = 0
    is(ccpolyzp_po2cyc_bytes_to_coeffs(CC_ARRAY_LEN(coeffs), coeffs, CC_ARRAY_LEN(bytes), bytes, 0, 0),
       CCERR_PARAMETER,
       "bytes_to_coeffs bits_per_coeff = 0");

    // wrong nbytes
    is(ccpolyzp_po2cyc_bytes_to_coeffs(CC_ARRAY_LEN(coeffs), coeffs, CC_ARRAY_LEN(bytes) - 1, bytes, bits_per_coeff, 0),
       CCERR_PARAMETER,
       "bytes_to_coeffs wrong nbytes");

    // wrong nskip_lsbs too large
    is(ccpolyzp_po2cyc_bytes_to_coeffs(CC_ARRAY_LEN(coeffs), coeffs, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, bits_per_coeff),
       CCERR_PARAMETER,
       "bytes_to_coeffs nskip_lsbs too large");
}

static void run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(size_t ncoeffs,
                                                                   ccrns_int coeffs_expected[],
                                                                   size_t nbytes,
                                                                   uint8_t bytes[],
                                                                   size_t bits_per_coeff,
                                                                   size_t nskip_lsbs)
{
    ccrns_int coeffs[ncoeffs];
    is(ccpolyzp_po2cyc_bytes_to_coeffs(ncoeffs, coeffs, nbytes, bytes, bits_per_coeff, nskip_lsbs),
       CCERR_OK,
       "bytes_to_coeffs bits_per_coeff=%zu, nskip_lsbs=%zu",
       bits_per_coeff,
       nskip_lsbs);
    is(memcmp(coeffs, coeffs_expected, sizeof(ccrns_int) * CC_ARRAY_LEN(coeffs)),
       0,
       "bytes_to_coeffs memcmp bits_per_coeff=%zu, nskip_lsbs=%zu",
       bits_per_coeff,
       nskip_lsbs);
}

static void test_ccpolyzp_po2cyc_serialization_bytes_to_coeffs(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // bits_per_coeff = 4
    {
        const size_t bits_per_coeff = 4;
        // nskip_lsbs = 0
        {
            uint32_t nskip_lsbs = 0;
            uint8_t bytes[] = { 3, 24, 95, 141, 179, 34, 113 };
            ccrns_int coeffs_expected[] = { 0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1 };
            run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
                CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, nskip_lsbs);
        }
        // nskip_lsbs = 1
        {
            uint32_t nskip_lsbs = 1;
            uint8_t bytes[] = { 4, 69, 230, 164, 150, 0 };
            ccrns_int coeffs_expected[] = { 0, 2, 0, 8, 4, 14, 8, 12, 10, 2, 2, 2, 6, 0, 0, 0 };
            run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
                CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, nskip_lsbs);
        }
        // nskip_lsbs = 2
        {
            uint32_t nskip_lsbs = 2;
            uint8_t bytes[] = { 2, 123, 128, 64 };
            ccrns_int coeffs_expected[] = { 0, 0, 0, 8, 4, 12, 8, 12, 8, 0, 0, 0, 4, 0, 0, 0 };
            run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
                CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, nskip_lsbs);
        }
        // nskip_lsbs = 3
        {
            uint32_t nskip_lsbs = 3;
            uint8_t bytes[] = { 23, 128 };
            ccrns_int coeffs_expected[] = { 0, 0, 0, 8, 0, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0 };
            run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
                CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, nskip_lsbs);
        }
    }
    // bits_per_coeff = 5
    {
        const size_t bits_per_coeff = 5;
        // nskip_lsbs = 0
        {
            uint32_t nskip_lsbs = 0;
            uint8_t bytes[] = { 3, 24, 95, 141, 179, 34, 113 };
            ccrns_int coeffs_expected[] = { 0, 12, 12, 5, 31, 3, 13, 19, 4, 9, 24 };
            run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
                CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, nskip_lsbs);
        }
        // nskip_lsbs = 1
        {
            uint32_t nskip_lsbs = 1;
            uint8_t bytes[] = { 3, 24, 95, 141, 179, 34, 113 };
            ccrns_int coeffs_expected[] = { 0, 6, 2, 16, 10, 30, 16, 26, 22, 6, 4, 4, 14, 2 };
            run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
                CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, nskip_lsbs);
        }
        // nskip_lsbs = 2
        {
            uint32_t nskip_lsbs = 2;
            uint8_t bytes[] = { 3, 24, 95, 141, 179, 34, 113 };
            ccrns_int coeffs_expected[] = { 0, 0, 24, 4, 16, 4, 12, 28, 16, 12, 12, 12, 4, 16, 16, 8, 12, 16, 8 };
            run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
                CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, nskip_lsbs);
        }
        // nskip_lsbs = 3
        {
            uint32_t nskip_lsbs = 3;
            uint8_t bytes[] = { 3, 24, 95, 141, 179, 34, 113 };
            ccrns_int coeffs_expected[] = { 0,  0, 0,  24, 0, 8,  16, 0,  8, 8,  24, 24, 16, 0,
                                            24, 8, 16, 24, 0, 24, 0,  16, 0, 16, 8,  24, 0,  8 };
            run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
                CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, nskip_lsbs);
        }
        // nskip_lsbs = 3
        {
            uint32_t nskip_lsbs = 4;
            uint8_t bytes[] = { 3, 24, 95, 141, 179, 34, 113 };
            ccrns_int coeffs_expected[] = { 0,  0,  0,  0,  0,  0,  16, 16, 0,  0,  0,  16, 16, 0,  0, 0,  0,  16, 0,
                                            16, 16, 16, 16, 16, 16, 0,  0,  0,  16, 16, 0,  16, 16, 0, 16, 16, 0,  0,
                                            16, 16, 0,  0,  16, 0,  0,  0,  16, 0,  0,  16, 16, 16, 0, 0,  0,  16 };
            run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
                CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, nskip_lsbs);
        }
    }
    // bits_per_coeff = 8
    {
        const static size_t bits_per_coeff = 8;
        uint8_t bytes[256];
        ccrns_int coeffs_expected[256];
        for (uint32_t i = 0; i < 256; ++i) {
            bytes[i] = (uint8_t)i;
            coeffs_expected[i] = i;
        }
        run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
            CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, 0);
    }
    // bits_per_coeff = 21
    {
        // arbitrary byte array
        const static size_t bits_per_coeff = 21;
        uint8_t bytes[] = { 194, 72,  195, 188, 183, 81,  23,  27,  207, 151, 3,   93,  44,  8,   39,  162, 91,  219,
                            110, 16,  31,  84,  108, 39,  76,  163, 211, 51,  136, 77,  195, 237, 164, 62,  169, 217,
                            110, 222, 131, 5,   43,  23,  43,  153, 221, 228, 130, 35,  31,  156, 117, 119, 61,  174,
                            47,  65,  70,  13,  246, 113, 63,  58,  174, 251, 96,  240, 138, 97,  158, 236, 124, 38,
                            63,  135, 144, 94,  116, 86,  120, 101, 237, 40,  14,  151, 133, 187, 112, 20,  114, 134,
                            202, 146, 66,  64,  139, 244, 255, 66,  37,  145, 240, 244, 137, 74,  231, 253, 81,  142,
                            70,  62,  63,  250, 134, 49,  33,  224, 117, 235, 233, 215, 243, 163, 159, 201, 128 };
        // expected coefficients
        ccrns_int coeffs_expected[] = { 1591576, 979677,  560013,  1898864, 440920,  133608,  1236699, 921631,  691588,  1913487,
                                        629188,  318526,  1788029, 685659,  1504280, 338711,  357179,  1544712, 1150926, 481139,
                                        1793118, 1069443, 1029001, 2046638, 2059294, 141702,  1013310, 156664,  991420,  1906078,
                                        208745,  528023,  1095534, 20938,   222537,  271368,  1567230, 1083748, 1017764, 608999,
                                        2075185, 1644792, 2096451, 201246,  60375,   1734140, 1907966, 622592 };
        run_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_test(
            CC_ARRAY_LEN(coeffs_expected), coeffs_expected, CC_ARRAY_LEN(bytes), bytes, bits_per_coeff, 0);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_error(void)
{
    uint8_t bytes[] = { 3, 24, 95, 141, 179, 34, 113 };
    ccrns_int coeffs[] = { 0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1 };
    const static size_t bits_per_coeff = 4;
    // ok
    is(ccpolyzp_po2cyc_coeffs_to_bytes(CC_ARRAY_LEN(bytes), bytes, CC_ARRAY_LEN(coeffs), coeffs, bits_per_coeff, 0),
       CCERR_OK,
       "coeffs_to_bytes error");

    // bits_per_coeff = 0
    is(ccpolyzp_po2cyc_coeffs_to_bytes(CC_ARRAY_LEN(bytes), bytes, CC_ARRAY_LEN(coeffs), coeffs, 0, 0),
       CCERR_PARAMETER,
       "coeffs_to_bytes bits_per_coeff = 0");

    // wrong nbytes
    is(ccpolyzp_po2cyc_coeffs_to_bytes(CC_ARRAY_LEN(bytes) - 1, bytes, CC_ARRAY_LEN(coeffs), coeffs, bits_per_coeff, 0),
       CCERR_PARAMETER,
       "coeffs_to_bytes wrong nbytes");

    // wrong nskip_lsbs
    is(ccpolyzp_po2cyc_coeffs_to_bytes(CC_ARRAY_LEN(bytes), bytes, CC_ARRAY_LEN(coeffs), coeffs, bits_per_coeff, bits_per_coeff),
       CCERR_PARAMETER,
       "coeffs_to_bytes wrong nskip_lsbs");
}

static void run_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_test(size_t ncoeffs,
                                                                   ccrns_int coeffs[],
                                                                   size_t bits_per_coeff,
                                                                   size_t nskip_lsbs,
                                                                   size_t nbytes_expected,
                                                                   uint8_t bytes_expected[])
{
    uint8_t bytes[nbytes_expected];
    is(ccpolyzp_po2cyc_coeffs_to_bytes(CC_ARRAY_LEN(bytes), bytes, ncoeffs, coeffs, bits_per_coeff, nskip_lsbs),
       CCERR_OK,
       "coeffs_to_bytes bits_per_coeff=%zu, nskip_lsbs=%zu",
       bits_per_coeff,
       nskip_lsbs);
    is(memcmp(bytes, bytes_expected, CC_ARRAY_LEN(bytes)),
       0,
       "coeffs_to_bytes memcmp bits_per_coeff=%zu, nskip_lsbs=%zu",
       bits_per_coeff,
       nskip_lsbs);
}

static void test_ccpolyzp_po2cyc_serialization_coeffs_to_bytes(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // bits_per_coeff = 4
    {
        uint32_t bits_per_coeff = 4;
        ccrns_int coeffs[] = { 0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1 };
        {
            uint32_t nskip_lsbs = 0;
            uint8_t bytes_expected[] = { 3, 24, 95, 141, 179, 34, 113 };
            run_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_test(
                CC_ARRAY_LEN(coeffs), coeffs, bits_per_coeff, nskip_lsbs, CC_ARRAY_LEN(bytes_expected), bytes_expected);
        }
        {
            uint32_t nskip_lsbs = 1;
            uint8_t bytes_expected[] = { 4, 69, 230, 164, 150, 0 };
            run_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_test(
                CC_ARRAY_LEN(coeffs), coeffs, bits_per_coeff, nskip_lsbs, CC_ARRAY_LEN(bytes_expected), bytes_expected);
        }
        {
            uint32_t nskip_lsbs = 2;
            uint8_t bytes_expected[] = { 2, 123, 128, 64 };
            run_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_test(
                CC_ARRAY_LEN(coeffs), coeffs, bits_per_coeff, nskip_lsbs, CC_ARRAY_LEN(bytes_expected), bytes_expected);
        }
        {
            uint32_t nskip_lsbs = 3;
            uint8_t bytes_expected[] = { 23, 128 };
            run_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_test(
                CC_ARRAY_LEN(coeffs), coeffs, bits_per_coeff, nskip_lsbs, CC_ARRAY_LEN(bytes_expected), bytes_expected);
        }
    }
    // bits_per_coeff = 5
    {
        uint32_t bits_per_coeff = 5;
        ccrns_int coeffs[] = { 0, 3, 1, 8, 5, 15, 8, 13, 11, 3, 2, 2, 7, 1 };
        {
            uint32_t nskip_lsbs = 0;
            uint8_t bytes_expected[] = { 0, 194, 130, 189, 13, 88, 196, 35, 132 };
            run_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_test(
                CC_ARRAY_LEN(coeffs), coeffs, bits_per_coeff, nskip_lsbs, CC_ARRAY_LEN(bytes_expected), bytes_expected);
        }
        {
            uint32_t nskip_lsbs = 1;
            uint8_t bytes_expected[] = { 1, 4, 39, 70, 81, 17, 48 };
            run_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_test(
                CC_ARRAY_LEN(coeffs), coeffs, bits_per_coeff, nskip_lsbs, CC_ARRAY_LEN(bytes_expected), bytes_expected);
        }
        {
            uint32_t nskip_lsbs = 2;
            uint8_t bytes_expected[] = { 0, 34, 211, 64, 2, 0 };
            run_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_test(
                CC_ARRAY_LEN(coeffs), coeffs, bits_per_coeff, nskip_lsbs, CC_ARRAY_LEN(bytes_expected), bytes_expected);
        }
    }
    // bits_per_coeff = 8
    {
        uint8_t bytes_expected[256];
        ccrns_int coeffs[256];
        for (uint32_t i = 0; i < 256; ++i) {
            bytes_expected[i] = (uint8_t)i;
            coeffs[i] = i;
        }
        run_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_test(
            CC_ARRAY_LEN(coeffs), coeffs, 8, 0, CC_ARRAY_LEN(bytes_expected), bytes_expected);
    }
    // bits_per_coeff = 21
    {
        // arbitrary byte array
        uint8_t bytes_expected[] = { 194, 72,  195, 188, 183, 81,  23,  27,  207, 151, 3,   93,  44,  8,   39,  162, 91,  219,
                                     110, 16,  31,  84,  108, 39,  76,  163, 211, 51,  136, 77,  195, 237, 164, 62,  169, 217,
                                     110, 222, 131, 5,   43,  23,  43,  153, 221, 228, 130, 35,  31,  156, 117, 119, 61,  174,
                                     47,  65,  70,  13,  246, 113, 63,  58,  174, 251, 96,  240, 138, 97,  158, 236, 124, 38,
                                     63,  135, 144, 94,  116, 86,  120, 101, 237, 40,  14,  151, 133, 187, 112, 20,  114, 134,
                                     202, 146, 66,  64,  139, 244, 255, 66,  37,  145, 240, 244, 137, 74,  231, 253, 81,  142,
                                     70,  62,  63,  250, 134, 49,  33,  224, 117, 235, 233, 215, 243, 163, 159, 201, 128, 0 };
        // expected coefficients
        ccrns_int coeffs[] = { 1591576, 979677,  560013,  1898864, 440920,  133608,  1236699, 921631,  691588,  1913487,
                               629188,  318526,  1788029, 685659,  1504280, 338711,  357179,  1544712, 1150926, 481139,
                               1793118, 1069443, 1029001, 2046638, 2059294, 141702,  1013310, 156664,  991420,  1906078,
                               208745,  528023,  1095534, 20938,   222537,  271368,  1567230, 1083748, 1017764, 608999,
                               2075185, 1644792, 2096451, 201246,  60375,   1734140, 1907966, 622592 };
        run_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_test(
            CC_ARRAY_LEN(coeffs), coeffs, 21, 0, CC_ARRAY_LEN(bytes_expected), bytes_expected);
    }
    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_encode_coeffs_roundtrip_helper(const size_t ncoeffs, const size_t bits_per_coeff)
{
    const size_t nbytes = cc_ceiling(ncoeffs * bits_per_coeff, 8);
    ccrns_int coeffs_initial[ncoeffs];
    ccrns_int coeffs[ncoeffs];
    uint8_t bytes[nbytes];

    int rv = CCERR_OK;
    for (uint32_t coeff_idx = 0; coeff_idx < ncoeffs; ++coeff_idx) {
        rv |= ccrng_uniform(global_test_rng, UINT64_C(1) << bits_per_coeff, &coeffs_initial[coeff_idx]);
    }

    is(rv, CCERR_OK, "ccrng_uniform (ncoeffs = %zu, bits_per_coeff = %zu)", ncoeffs, bits_per_coeff);
    is(ccpolyzp_po2cyc_coeffs_to_bytes(nbytes, bytes, ncoeffs, coeffs_initial, bits_per_coeff, 0),
       CCERR_OK,
       "ccpolyzp_po2cyc_coeffs_to_bytes (ncoeffs = %zu, bits_per_coeff = %zu)",
       ncoeffs,
       bits_per_coeff);
    is(ccpolyzp_po2cyc_bytes_to_coeffs(ncoeffs, coeffs, nbytes, bytes, bits_per_coeff, 0),
       CCERR_OK,
       "ccpolyzp_po2cyc_bytes_to_coeffs (ncoeffs = %zu, bits_per_coeff = %zu)",
       ncoeffs,
       bits_per_coeff);
    is(memcmp(coeffs, coeffs_initial, ncoeffs),
       0,
       "coeffs != initial coeffs (ncoeffs = %zu, bits_per_coeff = %zu)",
       ncoeffs,
       bits_per_coeff);
}

static void test_ccpolyzp_po2cyc_encode_coeffs_roundtrip(void)
{
    const size_t ncoeffs[] = { 8, 20, 50, 100, 128 };
    const size_t bits_per_coeff[] = { 8, 11, 20, 21, 37, 61 };
    for (uint32_t i = 0; i < CC_ARRAY_LEN(ncoeffs); ++i) {
        for (uint32_t j = 0; j < CC_ARRAY_LEN(bits_per_coeff); ++j) {
            test_ccpolyzp_po2cyc_encode_coeffs_roundtrip_helper(ncoeffs[i], bits_per_coeff[j]);
        }
    }
}

static void test_ccpolyzp_po2cyc_encode_bytes_roundtrip_helper(const size_t nbytes, const size_t bits_per_coeff)
{
    const size_t ncoeffs = cc_ceiling(nbytes * 8, bits_per_coeff);
    ccrns_int coeffs[ncoeffs];
    uint8_t bytes_initial[nbytes];
    uint8_t bytes[nbytes];

    is(ccrng_generate(global_test_rng, nbytes, bytes_initial),
       CCERR_OK,
       "ccrng_generate (nbytes = %zu, bits_per_coeff = %zu)",
       nbytes,
       bits_per_coeff);
    is(ccpolyzp_po2cyc_bytes_to_coeffs(ncoeffs, coeffs, nbytes, bytes_initial, bits_per_coeff, 0),
       CCERR_OK,
       "ccpolyzp_po2cyc_bytes_to_coeffs (nbytes = %zu, bits_per_coeff = %zu)",
       nbytes,
       bits_per_coeff);
    is(ccpolyzp_po2cyc_coeffs_to_bytes(nbytes, bytes, ncoeffs, coeffs, bits_per_coeff, 0),
       CCERR_OK,
       "ccpolyzp_po2cyc_coeffs_to_bytes (nbytes = %zu, bits_per_coeff = %zu)",
       nbytes,
       bits_per_coeff);
    is(memcmp(bytes, bytes_initial, nbytes),
       0,
       "bytes != initial bytes (nbytes = %zu, bits_per_coeff = %zu)",
       nbytes,
       bits_per_coeff);
}

static void test_ccpolyzp_po2cyc_encode_bytes_roundtrip(void)
{
    const size_t nbytes[] = { 8, 20, 50, 100, 128 };
    const size_t bits_per_coeff[] = { 8, 11, 20, 21, 37, 61 };
    for (uint32_t i = 0; i < CC_ARRAY_LEN(nbytes); ++i) {
        for (uint32_t j = 0; j < CC_ARRAY_LEN(bits_per_coeff); ++j) {
            test_ccpolyzp_po2cyc_encode_bytes_roundtrip_helper(nbytes[i], bits_per_coeff[j]);
        }
    }
}

static void test_ccpolyzp_po2cyc_serialize_poly_roundtrip_helper(cc_ws_t ws,
                                                                 uint32_t degree,
                                                                 uint32_t nmoduli,
                                                                 ccrns_int *cc_counted_by(nmoduli) moduli)
{
    struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = nmoduli };
    ccrns_int coeffs[degree * nmoduli];
    ccpolyzp_po2cyc_t poly = (ccpolyzp_po2cyc_t)ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, coeffs);
    ccpolyzp_po2cyc_t poly_deserialized = (ccpolyzp_po2cyc_t)ccpolyzp_po2cyc_coeff_init_helper(ws, &dims, moduli, coeffs);
    ccpolyzp_po2cyc_ctx_const_t ctx = ((ccpolyzp_po2cyc_coeff_const_t)poly)->context;
    ccpolyzp_po2cyc_random_uniform_ws(ws, poly, global_test_rng);
    cc_size nbytes = ccpolyzp_po2cyc_serialize_poly_nbytes(ctx, 0);
    uint8_t bytes[nbytes];
    is(ccpolyzp_po2cyc_serialize_poly_ws(ws, nbytes, bytes, 0, poly),
       CCERR_OK,
       "serialize poly, degree = %" PRIu32 ", nmoduli = %" PRIu32,
       degree,
       nmoduli);
    is(ccpolyzp_po2cyc_deserialize_poly_ws(ws, poly_deserialized, 0, nbytes, bytes),
       CCERR_OK,
       "deserialize, degree = %" PRIu32 ", nmoduli = %" PRIu32,
       degree,
       nmoduli);
    is(ccpolyzp_po2cyc_coeff_eq((ccpolyzp_po2cyc_coeff_t)poly, (ccpolyzp_po2cyc_coeff_t)poly_deserialized),
       true,
       "deserialized poly != original poly, degree = %" PRIu32 ", nmoduli = %" PRIu32,
       degree,
       nmoduli);
}

static void test_ccpolyzp_po2cyc_serialize_poly_roundtrip(void)
{
    CC_DECL_WORKSPACE_TEST(ws);
    {
        ccrns_int moduli[] = { 521, (1ULL << 60) - (1ULL << 18) + 1 };
        test_ccpolyzp_po2cyc_serialize_poly_roundtrip_helper(ws, 4, CC_ARRAY_LEN(moduli), moduli);
    }
    {
        ccrns_int moduli[] = { 40961, 59393, 61441, 65537 };
        test_ccpolyzp_po2cyc_serialize_poly_roundtrip_helper(ws, 1024, CC_ARRAY_LEN(moduli), moduli);
    }
    CC_FREE_WORKSPACE(ws);
}

void test_ccpolyzp_po2cyc_serialization(void)
{
    test_ccpolyzp_po2cyc_serialization_bytes_to_coeffs_error();
    test_ccpolyzp_po2cyc_serialization_bytes_to_coeffs();
    test_ccpolyzp_po2cyc_serialization_coeffs_to_bytes_error();
    test_ccpolyzp_po2cyc_serialization_coeffs_to_bytes();
    test_ccpolyzp_po2cyc_encode_coeffs_roundtrip();
    test_ccpolyzp_po2cyc_encode_bytes_roundtrip();
    test_ccpolyzp_po2cyc_serialize_poly_roundtrip();
}
