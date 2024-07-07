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

#include "cche_debug.h"
#include "ccpolyzp_po2cyc_debug.h"
#include "cche_galois_key.h"

void cche_plaintext_lprint(cche_plaintext_const_t ptext, const char *cc_cstring label)
{
    cc_printf("Plaintext: %s - ", label);
    ccpolyzp_po2cyc_coeff_const_t ptext_poly = cche_plaintext_polynomial_const(ptext);
    ccpolyzp_po2cyc_coeff_lprint(ptext_poly, NULL);
}

void cche_ciphertext_coeff_lprint(cche_ciphertext_coeff_const_t ctext, const char *cc_cstring label)
{
    cc_printf("Ciphertext: %s - ", label);
    for (uint32_t poly_idx = 0; poly_idx < ctext->npolys; ++poly_idx) {
        ccpolyzp_po2cyc_coeff_const_t ctext_poly = cche_ciphertext_coeff_polynomial_const(ctext, poly_idx);
        ccpolyzp_po2cyc_coeff_lprint(ctext_poly, NULL);
    }
}

void cche_ciphertext_eval_lprint(cche_ciphertext_eval_const_t ctext, const char *cc_cstring label)
{
    cc_printf("Ciphertext: %s - ", label);
    for (uint32_t poly_idx = 0; poly_idx < ctext->npolys; ++poly_idx) {
        ccpolyzp_po2cyc_eval_const_t ctext_poly = cche_ciphertext_eval_polynomial_const(ctext, poly_idx);
        ccpolyzp_po2cyc_eval_lprint(ctext_poly, NULL);
    }
}

void cche_galois_key_lprint(cche_galois_key_const_t galois_key, const char *cc_cstring label)
{
    cc_printf("Galois key: %s {", label);

    const uint32_t *galois_elts = CCHE_GALOIS_KEY_GALOIS_ELTS_CONST(galois_key);
    for (uint32_t galois_elt_idx = 0; galois_elt_idx < galois_key->ngalois_elts; ++galois_elt_idx) {
        cc_printf("Galois element: %" PRIu32 "{", galois_elts[galois_elt_idx]);
        uint32_t nmoduli = cche_param_ctx_encrypt_key_context(galois_key->param_ctx)->dims.nmoduli - 1;

        for (uint32_t cipher_idx = 0; cipher_idx < nmoduli; ++cipher_idx) {
            cche_ciphertext_eval_const_t ctext = cche_galois_key_ciphertext_const(galois_key, galois_elt_idx, cipher_idx);
            cche_ciphertext_eval_lprint(ctext, NULL);
        }
        cc_printf("}");
    }
    cc_printf("}\n");
}

void cche_relin_key_lprint(cche_relin_key_const_t relin_key, const char *cc_cstring label)
{
    cc_printf("Relinearization key: %s {\n", label);
    uint32_t nmoduli = cche_param_ctx_encrypt_key_context(relin_key->param_ctx)->dims.nmoduli - 1;
    cc_printf("nmoduli %" PRIu32 "\n", nmoduli);
    for (uint32_t cipher_idx = 0; cipher_idx < nmoduli; ++cipher_idx) {
        cc_printf("cipher_idx %" PRIu32 "\n", cipher_idx);
        cche_ciphertext_eval_const_t ctext = cche_relin_key_ciphertext_const(relin_key, cipher_idx);
        cche_ciphertext_eval_lprint(ctext, NULL);
    }
    cc_printf("}");
    cc_printf("}\n");
}
