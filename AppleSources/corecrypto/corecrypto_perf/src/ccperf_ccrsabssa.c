/* Copyright (c) (2021,2023) Apple Inc. All rights reserved.
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
#include "cc_priv.h"
#include <corecrypto/ccrsabssa.h>

ccrsa_full_ctx_decl_nbits(2048, full_key_2048);
ccrsa_full_ctx_decl_nbits(3072, full_key_3072);
ccrsa_full_ctx_decl_nbits(4096, full_key_4096);
static bool keys_generated = false;

static const struct ccrsabssa_ciphersuite* ciphersuite_for_keysize(cc_size nbits)
{
    if (nbits == 2048) {
        return &ccrsabssa_ciphersuite_rsa2048_sha384;
    }

    if (nbits == 3072) {
        return &ccrsabssa_ciphersuite_rsa3072_sha384;
    }

    if (nbits == 4096) {
        return &ccrsabssa_ciphersuite_rsa4096_sha384;
    }

    cc_abort("Unsupported RSA key size");
    return NULL;
}

static void generate_key(cc_size bits, ccrsa_full_ctx_t privatekey)
{
    const uint8_t e[] = { 0x1, 0x00, 0x01 };
    if (ccrsa_generate_key(bits, privatekey, sizeof(e), e, rng)) { abort(); }
}

static void generate_rsabssa_full_keys(void)
{
    generate_key(2048, full_key_2048);
    generate_key(3072, full_key_3072);
    generate_key(4096, full_key_4096);
}

static ccrsa_full_ctx_t full_key_for_size(cc_size nbits){
    switch (nbits) {
        case 2048:
            return full_key_2048;
        case 3072:
            return full_key_3072;
        case 4096:
            return full_key_4096;
        default:
            abort();
    }
}

static double perf_ccrsabssa_test_blind(size_t loops, cc_size nbits)
{
    ccrsa_full_ctx_t full_key = full_key_for_size(nbits);
    size_t nbytes = CC_BITLEN_TO_BYTELEN(nbits);
    ccrsa_pub_ctx_t public_key = ccrsa_ctx_public(full_key);
    const struct ccrsabssa_ciphersuite *ciphersuite = ciphersuite_for_keysize(nbits);

    uint8_t msg[32];
    ccrng_generate(rng, sizeof(msg), msg);

    uint8_t blinding_inverse[nbytes];
    uint8_t blinded_msg[nbytes];

    double t;

    perf_start();
    do {
        if (ccrsabssa_blind_message(ciphersuite,
                                    public_key, msg, sizeof(msg),
                                    blinding_inverse, sizeof(blinding_inverse),
                                    blinded_msg, sizeof(blinded_msg), rng)) {
            abort();
        }
    } while (--loops != 0);
    t = perf_seconds();

    return t;
}

static double perf_ccrsabssa_test_unblind(size_t loops, cc_size nbits)
{
    ccrsa_full_ctx_t full_key = full_key_for_size(nbits);
    size_t nbytes = CC_BITLEN_TO_BYTELEN(nbits);
    ccrsa_pub_ctx_t public_key = ccrsa_ctx_public(full_key);
    const struct ccrsabssa_ciphersuite *ciphersuite = ciphersuite_for_keysize(nbits);

    uint8_t msg[32];
    ccrng_generate(rng, sizeof(msg), msg);

    uint8_t blinding_inverse[nbytes];
    uint8_t blinded_msg[nbytes];
    uint8_t blinded_sig[nbytes];
    uint8_t unblinded_sig[nbytes];

    if (ccrsabssa_blind_message(ciphersuite,
                                public_key, msg, sizeof(msg),
                                blinding_inverse, sizeof(blinding_inverse),
                                blinded_msg, sizeof(blinded_msg), rng)) {
        abort();
    }

    if (ccrsabssa_sign_blinded_message(ciphersuite, full_key,
                                       blinded_msg, sizeof(blinded_msg),
                                       blinded_sig, sizeof(blinded_sig),
                                       rng)) {
        abort();
    }


    double t;

    perf_start();
    do {
        if (ccrsabssa_unblind_signature(ciphersuite, public_key,
                                        blinded_sig, sizeof(blinded_sig),
                                        blinding_inverse, sizeof(blinding_inverse),
                                        msg, sizeof(msg),
                                        unblinded_sig, sizeof(unblinded_sig))) {
            abort();
        }
    } while (--loops != 0);
    t = perf_seconds();

    return t;
}

#define _TEST(_x)                      \
    {                                  \
        .name = #_x, .func = perf_##_x \
    }
static struct ccrsabssa_perf_test {
    const char *name;
    double (*func)(size_t loops, cc_size nbits);
} ccrsabssa_perf_tests[] = {
    _TEST(ccrsabssa_test_blind),
    _TEST(ccrsabssa_test_unblind)
};

static double perf_ccrsabssa(size_t loops, size_t *psize, const void *arg)
{
    if (!keys_generated) {
        generate_rsabssa_full_keys();
        keys_generated = true;
    }
    const struct ccrsabssa_perf_test *test = arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccrsabssa(int argc, char *argv[])
{
    F_GET_ALL(family, ccrsabssa);
    static const size_t keysize_nbits[] = { 2048, 3072, 4096};
    F_SIZES_FROM_ARRAY(family, keysize_nbits);
    family.size_kind = ccperf_size_bits;
    return &family;
}
