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
#include "ccpolyzp_po2cyc_debug.h"
#include "ccpolyzp_po2cyc_galois.h"
#include "ccpolyzp_po2cyc_random.h"
#include "testmore.h"
#include <corecrypto/ccrng.h>

static void test_ccpolyzp_po2cyc_apply_galois_error(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // Invalid galois element
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli[] = { 17 };

        // coefficient format
        {
            ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
            ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);

            is(ccpolyzp_po2cyc_coeff_apply_galois(poly_out, poly_in, 3), CCERR_OK, "ccpolyzp_po2cyc_coeff_apply_galois ok");
            is(ccpolyzp_po2cyc_coeff_apply_galois(poly_out, poly_in, 1),
               CCERR_PARAMETER,
               "ccpolyzp_po2cyc_coeff_apply_galois galois_elt 1");
            is(ccpolyzp_po2cyc_coeff_apply_galois(poly_out, poly_in, 2),
               CCERR_PARAMETER,
               "ccpolyzp_po2cyc_coeff_apply_galois even galois_elt");
            is(ccpolyzp_po2cyc_coeff_apply_galois(poly_out, poly_in, 9),
               CCERR_PARAMETER,
               "ccpolyzp_po2cyc_coeff_apply_galois galois_elt too large");
        }
        // evaluation format
        {
            ccpolyzp_po2cyc_eval_t poly_in = ccpolyzp_po2cyc_eval_init_zero_helper(ws, &dims, moduli);
            ccpolyzp_po2cyc_eval_t poly_out = ccpolyzp_po2cyc_eval_init_zero_helper(ws, &dims, moduli);

            is(ccpolyzp_po2cyc_eval_apply_galois(poly_out, poly_in, 3), CCERR_OK, "ccpolyzp_po2cyc_eval_apply_galois ok");
            is(ccpolyzp_po2cyc_eval_apply_galois(poly_out, poly_in, 1),
               CCERR_PARAMETER,
               "ccpolyzp_po2cyc_eval_apply_galois galois_elt 1");
            is(ccpolyzp_po2cyc_eval_apply_galois(poly_out, poly_in, 2),
               CCERR_PARAMETER,
               "ccpolyzp_po2cyc_eval_apply_galois even galois_elt");
            is(ccpolyzp_po2cyc_eval_apply_galois(poly_out, poly_in, 9),
               CCERR_PARAMETER,
               "ccpolyzp_po2cyc_eval_apply_galois galois_elt too large");
        }
    }
    // Mismatched context
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli[] = { 17 };
        ccrns_int moduli_diff[] = { 31 };
        // coefficient format
        {
            ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
            ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli_diff);

            is(ccpolyzp_po2cyc_coeff_apply_galois(poly_out, poly_in, 3),
               CCERR_PARAMETER,
               "ccpolyzp_po2cyc_coeff_apply_galois context mismatch");
        }
        // evaluation format
        {
            ccpolyzp_po2cyc_eval_t poly_in = ccpolyzp_po2cyc_eval_init_zero_helper(ws, &dims, moduli);
            ccpolyzp_po2cyc_eval_t poly_out = ccpolyzp_po2cyc_eval_init_zero_helper(ws, &dims, moduli_diff);

            is(ccpolyzp_po2cyc_eval_apply_galois(poly_out, poly_in, 3),
               CCERR_PARAMETER,
               "ccpolyzp_po2cyc_eval_apply_galois context mismatch");
        }
    }
    // In-place
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli[] = { 17 };
        // coefficient format
        {
            ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
            is(ccpolyzp_po2cyc_coeff_apply_galois(poly_in, poly_in, 3),
               CCERR_PARAMETER,
               "ccpolyzp_po2cyc_coeff_apply_galois in-place");
        }
        // evaluation format
        {
            ccpolyzp_po2cyc_eval_t poly_in = ccpolyzp_po2cyc_eval_init_zero_helper(ws, &dims, moduli);
            is(ccpolyzp_po2cyc_eval_apply_galois(poly_in, poly_in, 3),
               CCERR_PARAMETER,
               "ccpolyzp_po2cyc_eval_apply_galois in-place");
        }
    }

    CC_FREE_WORKSPACE(ws);
}

static void run_galois_test_case(ccpolyzp_po2cyc_dims_const_t dims,
                                 const ccrns_int *moduli,
                                 const ccrns_int *poly_in_data,
                                 const ccrns_int *exp_out_data,
                                 uint32_t galois_elt,
                                 const char *test_name)
{
    CC_DECL_WORKSPACE_TEST(ws);

    // coeff_apply_galois
    {
        ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_helper(ws, dims, moduli, poly_in_data);
        ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, dims, moduli);
        ccpolyzp_po2cyc_coeff_t exp_poly = ccpolyzp_po2cyc_coeff_init_helper(ws, dims, moduli, exp_out_data);

        is(ccpolyzp_po2cyc_coeff_apply_galois(poly_out, poly_in, galois_elt),
           CCERR_OK,
           "ccpolyzp_po2cyc_coeff_apply_galois != CCERR_OK");
        is(ccpolyzp_po2cyc_coeff_eq(poly_out, exp_poly), true, "test_ccpolyzp_po2cyc_coeff_apply_galois %s failed", test_name);
    }
    // eval_apply_galois
    {
        ccpolyzp_po2cyc_coeff_t poly_in = ccpolyzp_po2cyc_coeff_init_helper(ws, dims, moduli, poly_in_data);
        ccpolyzp_po2cyc_coeff_t poly_out = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, dims, moduli);
        ccpolyzp_po2cyc_coeff_t exp_poly = ccpolyzp_po2cyc_coeff_init_helper(ws, dims, moduli, exp_out_data);
        is(ccpolyzp_po2cyc_fwd_ntt(exp_poly), CCERR_OK, "ccpolyzp_po2cyc_fwd_ntt != CCERR_OK");

        is(ccpolyzp_po2cyc_fwd_ntt(poly_in), CCERR_OK, "ccpolyzp_po2cyc_fwd_ntt != CCERR_OK");
        is(ccpolyzp_po2cyc_eval_apply_galois((ccpolyzp_po2cyc_eval_t)poly_out, (ccpolyzp_po2cyc_eval_const_t)poly_in, galois_elt),
           CCERR_OK,
           "ccpolyzp_po2cyc_eval_apply_galois != CCERR_OK");
        is(ccpolyzp_po2cyc_eval_eq((ccpolyzp_po2cyc_eval_t)poly_out, (ccpolyzp_po2cyc_eval_t)exp_poly),
           true,
           "test_ccpolyzp_po2cyc_eval_apply_galois %s failed",
           test_name);
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccpolyzp_po2cyc_apply_galois(void)
{
    // 1 modulus, N=4
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 4, .nmoduli = 1 };
        ccrns_int moduli[] = { 17 };
        // f(x)   = 0 + x   + 2x^2    + 3x^3
        ccrns_int poly_in_data[] = { 0, 1, 2, 3 };

        // galois_elt = 3
        {
            // f(x^3) = 0 + x^3 + 2x^6    + 3x^9. Using x^4 = -1 =>
            //        = 0 + x^3 + (-2)x^2 + 3x
            //        = 0 + 3x  + 15x^2    + x^3
            ccrns_int exp_out_data[] = { 0, 3, 15, 1 };
            run_galois_test_case(&dims, moduli, poly_in_data, exp_out_data, 3, "N=4/L=1/galois_elt=3");
        }
        // galois_elt = 5
        {
            // f(x^5) = 0 + x^5 + 2x^10 + 3x^15. Using x^4 = -1 =>
            //        = 0 - x   + 2x^2  - 3x^3
            //        = 0 + 16x + 2x^2  + 14x^3
            ccrns_int exp_out_data[] = { 0, 16, 2, 14 };
            run_galois_test_case(&dims, moduli, poly_in_data, exp_out_data, 5, "N=4/L=1/galois_elt=5");
        }
        // galois_elt = 7
        {
            // f(x^7) = 0 + x^7 + 2x^14 + 3x^21. Using x^4 = -1 =>
            //        = 0 - x^3 - 2x^2  - 3x
            //        = 0 + 14x + 15x^2 + 16x^3
            ccrns_int exp_out_data[] = { 0, 14, 15, 16 };
            run_galois_test_case(&dims, moduli, poly_in_data, exp_out_data, 7, "N=4/L=1/galois_elt=7");
        }
    }
    // 1 modulus, N=8
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 8, .nmoduli = 1 };
        ccrns_int moduli[] = { 17 };
        // f(x)   =  0 + 1x   + 2x^2 + 3x^3  + 4x^4    + 5x^5    + 6x^6 + 7x^7
        ccrns_int poly_in_data[] = { 0, 1, 2, 3, 4, 5, 6, 7 };

        // galois_elt = 3
        {
            // f(x^3) =  0 + 1x^3 + 2x^6 + 3x^9  + 4x^12   + 5x^15   + 6^18 + 7x^21. Using x^8 = -1 =>
            //        =  0 + 1x^3 + 2x^6 + (-3)x + (-4)x^4 + (-5)x^7 + 6x^2 + 7x^5 mod 17 =>
            //        =  0 + 14x  + 6x^2 + 1x^3  + 13x^4   + 7x^5    + 2x^6 + 12x^7
            ccrns_int exp_out_data[] = { 0, 14, 6, 1, 13, 7, 2, 12 };
            run_galois_test_case(&dims, moduli, poly_in_data, exp_out_data, 3, "N=8/L=1/galois_elt=3");
        }
        // galois_elt = 13
        {
            // f(x^13) = 0 + 1x^13 + 2x^26 + 3x^39 + 4x^52 + 5x^65 + 6^78  + 7x^91. Using x^8 = -1 =>
            //        =  0 - 1x^5  - 2x^2  + 3x^7  + 4x^4  + 5x    - 6x^6  - 7x^3 mod 17 =>
            //        =  0 + 5x    + 15x^2 + 10x^3 + 4x^4  + 16x^5 + 11x^6 + 3x^7
            ccrns_int exp_out_data[] = { 0, 5, 15, 10, 4, 16, 11, 3 };
            run_galois_test_case(&dims, moduli, poly_in_data, exp_out_data, 13, "N=8/L=1/galois_elt=13");
        }
    }
    // 2 moduli, N=8
    {
        struct ccpolyzp_po2cyc_dims dims = { .degree = 8, .nmoduli = 2 };
        ccrns_int moduli[] = { 17, 97 };
        // f(x)   = 7 + 6x   + 5x^2 + 4x^3 + 3x^4  + 2x^5  + x^6
        ccrns_int poly_in_data[] = { 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0 };

        // f(x^3) = 7 + 6x^6 + 5x^6 + 4x^9 + 3x^12 + 2x^15 + x^18. Using x^8 = -1, and reducing mod 97 =>
        //        = 7 + 93x  + x^2  + 6x^3 + 94x^4 + 0x^5  + 5x^6 + 95x^7
        ccrns_int exp_out_data[] = { 0, 14, 6, 1, 13, 7, 2, 12, 7, 93, 1, 6, 94, 0, 5, 95 };
        run_galois_test_case(&dims, moduli, poly_in_data, exp_out_data, 3, "N=8/L=2/galois_elt=3");
    }
    // Check apply_galois_{coeff/eval} are related by NTT
    {
        CC_DECL_WORKSPACE_TEST(ws);

        ccrns_int moduli[] = { 40961, (1ULL << 60) - (1ULL << 18) + 1 };
        uint32_t nmoduli = CC_ARRAY_LEN(moduli);
        for (uint32_t degree = 4; degree <= 1024; degree <<= 1) {
            struct ccpolyzp_po2cyc_dims dims = { .degree = degree, .nmoduli = nmoduli };

            uint64_t galois_elt_u64;
            is(ccrng_uniform(global_test_rng, degree - 1, &galois_elt_u64), CCERR_OK, "ccrng_uniform != CCERR_OK");
            uint32_t galois_elt = 2 * (uint32_t)galois_elt_u64 + 3; // in [3, 2N - 1]

            struct ccrng_state *rng = ccrng(NULL);
            ccpolyzp_po2cyc_coeff_t poly_coeff_in = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
            is(ccpolyzp_po2cyc_random_uniform_ws(ws, (ccpolyzp_po2cyc_t)poly_coeff_in, rng),
               CCERR_OK,
               "ccpolyzp_po2cyc_random_uniform != CCERR_OK");

            ccpolyzp_po2cyc_coeff_t poly_coeff_galois = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);
            is(ccpolyzp_po2cyc_coeff_apply_galois(poly_coeff_galois, poly_coeff_in, galois_elt),
               CCERR_OK,
               "ccpolyzp_po2cyc_coeff_apply_galois != CCERR_OK");

            ccpolyzp_po2cyc_coeff_t poly_coeff_galois_roundtrip = ccpolyzp_po2cyc_coeff_init_zero_helper(ws, &dims, moduli);

            is(ccpolyzp_po2cyc_fwd_ntt(poly_coeff_in), CCERR_OK, "ccpolyzp_po2cyc_fwd_ntt != CCERR_OK");
            is(ccpolyzp_po2cyc_eval_apply_galois(
                   (ccpolyzp_po2cyc_eval_t)poly_coeff_galois_roundtrip, (ccpolyzp_po2cyc_eval_const_t)poly_coeff_in, galois_elt),
               CCERR_OK,
               "ccpolyzp_po2cyc_eval_apply_galois != CCERR_OK");
            is(ccpolyzp_po2cyc_inv_ntt((ccpolyzp_po2cyc_eval_t)poly_coeff_galois_roundtrip),
               CCERR_OK,
               "ccpolyzp_po2cyc_inv_ntt != CCERR_OK");

            is(ccpolyzp_po2cyc_coeff_eq(poly_coeff_galois_roundtrip, poly_coeff_galois), true, "apply_galois roundtrip");
        }
        CC_FREE_WORKSPACE(ws);
    }
}

void test_ccpolyzp_po2cyc_galois(void)
{
    test_ccpolyzp_po2cyc_apply_galois_error();
    test_ccpolyzp_po2cyc_apply_galois();
}
