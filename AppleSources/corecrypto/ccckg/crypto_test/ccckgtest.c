/* Copyright (c) (2019-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccckg.h>
#include "ccckg_internal.h"

#include "cc_priv.h"
#include "testmore.h"

#include <corecrypto/ccsha2.h>

static int test_full_run(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    struct ccrng_state *rng = global_test_rng;

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    uint8_t sk_a[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, 0, "Opened commitment");

    uint8_t sk_b[32];
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, 0, "Owner finished");

    ok_ccn_cmp(ccec_cp_n(cp), ccec_ctx_x(P_contrib), ccec_ctx_x(P_owner), "Ps don't match");
    ok_memcmp_or_fail(sk_a, sk_b, sizeof(sk_a), "SKs don't match");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_inputs(void)
{
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();
    ccec_const_cp_t cp = ccec_cp_256();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_full_ctx_decl_cp(ccec_cp_384(), P_bogus_full);
    ccec_pub_ctx_decl_cp(ccec_cp_384(), P_bogus);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];

    // Passing the wrong commitment size must fail.
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment) + 1, commitment);
    is(rv, CCERR_PARAMETER, "Generated commitment");

    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    uint8_t share[ccckg_sizeof_share(cp, di)];

    // Passing the wrong commitment size must fail.
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment) + 1, commitment, sizeof(share), share);
    is(rv, CCERR_PARAMETER, "ccckg_owner_generate_share should fail");

    // Passing the wrong share size must fail.
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share) + 1, share);
    is(rv, CCERR_PARAMETER, "ccckg_owner_generate_share should fail");

    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    uint8_t sk_a[32], sk_b[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];

    // Passing the wrong share size must fail.
    rv = ccckg_contributor_finish(ctx_a, sizeof(share) + 1, share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, CCERR_PARAMETER, "ccckg_contributor_finish should fail");

    // Passing the wrong opening size must fail.
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening) + 1, opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, CCERR_PARAMETER, "ccckg_contributor_finish should fail");

    // Passing a point on the wrong curve must fail.
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_bogus, sizeof(sk_a), sk_a);
    isnt(rv, CCERR_OK, "ccckg_contributor_finish should fail");

    // Passing a share with the wrong format must fail.
    share[0] = 0x02;
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    isnt(rv, CCERR_OK, "ccckg_contributor_finish should fail");

    share[0] = 0x04;
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, 0, "Opened commitment");

    // Passing the wrong opening size must fail.
    rv = ccckg_owner_finish(ctx_b, sizeof(opening) + 1, opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_PARAMETER, "ccckg_owner_finish should fail");

    // Passing a point on the wrong curve must fail.
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_bogus_full, sizeof(sk_b), sk_b);
    is(rv, CCERR_PARAMETER, "ccckg_owner_finish should fail");

    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, 0, "Owner finished");

    ok_ccn_cmp(ccec_cp_n(cp), ccec_ctx_x(P_contrib), ccec_ctx_x(P_owner), "Ps don't match");
    ok_memcmp_or_fail(sk_a, sk_b, sizeof(sk_a), "SKs don't match");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_commitment(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    // Corrupt the commitment.
    commitment[0] ^= 0x01;

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    uint8_t sk_a[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, 0, "Opened commitment");

    uint8_t sk_b[32];
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_INTEGRITY, "Invalid commitment");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_scalar(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_ctx_init(cp, P_owner);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_b);
    ccckg_init(ctx_b, cp, di, rng);

    // Assemble commitment data with an invalid scalar.
    uint8_t commitment_data[ccckg_sizeof_opening(cp, di)];
    ccn_write_uint_padded(ccec_cp_n(cp), cczp_prime(ccec_cp_zq(cp)), ccec_cp_order_size(cp), commitment_data);

    // Build the commitment.
    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    ccdigest(di, sizeof(commitment_data), commitment_data, commitment);

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    uint8_t sk_b[32];
    rv = ccckg_owner_finish(ctx_b, sizeof(commitment_data), commitment_data, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_PARAMETER, "Invalid scalar");

    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_share(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_pub_ctx_decl_cp(cp, P_contrib);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    // Corrupt the share.
    share[ccec_export_pub_size(P_contrib) - 1] ^= 0x55;

    uint8_t sk_a[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    isnt(rv, 0, "Invalid share");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_share_infinity(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_pub_ctx_decl_cp(cp, P_contrib);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    // Turn the share into the point at infinity.
    cc_clear(ccec_export_pub_size(P_contrib) - 1, share + 1);

    uint8_t sk_a[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    isnt(rv, 0, "Invalid share");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_bogus_opening(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");

    uint8_t share[ccckg_sizeof_share(cp, di)];
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    uint8_t sk_a[32];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, 0, "Opened commitment");

    // Corrupt the opening.
    opening[0] ^= 0x01;

    uint8_t sk_b[32];
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_INTEGRITY, "Invalid commitment");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_state_machine(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();

    ccec_full_ctx_decl_cp(cp, P_owner);
    ccec_pub_ctx_decl_cp(cp, P_contrib);

    ccec_ctx_init(cp, P_owner);
    ccec_ctx_init(cp, P_contrib);

    int rv;

    ccckg_ctx_decl(cp, di, ctx_a);
    ccckg_ctx_decl(cp, di, ctx_b);

    ccckg_init(ctx_a, cp, di, rng);
    ccckg_init(ctx_b, cp, di, rng);

    uint8_t commitment[ccckg_sizeof_commitment(cp, di)];
    uint8_t share[ccckg_sizeof_share(cp, di)];
    uint8_t opening[ccckg_sizeof_opening(cp, di)];

    // A=STATE_INIT, B=STATE_INIT

    uint8_t sk_a[32], sk_b[32];
    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish yet");
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish yet");

    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, 0, "Generated commitment");
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, 0, "Generated share");

    // A=STATE_COMMIT, B=STATE_SHARE

    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to commit twice");
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to share twice");

    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, 0, "Opened commitment");
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, 0, "Owner finished");

    // A=STATE_FINISH, B=STATE_FINISH

    rv = ccckg_contributor_commit(ctx_a, sizeof(commitment), commitment);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to commit twice");
    rv = ccckg_owner_generate_share(ctx_b, sizeof(commitment), commitment, sizeof(share), share);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to share twice");

    rv = ccckg_contributor_finish(ctx_a, sizeof(share), share, sizeof(opening), opening, P_contrib, sizeof(sk_a), sk_a);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish twice");
    rv = ccckg_owner_finish(ctx_b, sizeof(opening), opening, P_owner, sizeof(sk_b), sk_b);
    is(rv, CCERR_CALL_SEQUENCE, "Shouldn't be able to finish twice");

    ok_ccn_cmp(ccec_cp_n(cp), ccec_ctx_x(P_contrib), ccec_ctx_x(P_owner), "Ps don't match");
    ok_memcmp_or_fail(sk_a, sk_b, sizeof(sk_a), "SKs don't match");

    ccckg_ctx_clear(cp, di, ctx_a);
    ccckg_ctx_clear(cp, di, ctx_b);

    return 0;
}

static int test_ccckg_derive_sk_kat(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha256_di();
    
    ccckg_ctx_decl(cp, di, ctx);
    ccckg_init(ctx, cp, di, rng);
    
    cc_unit x[ccn_nof_size(32)];
    ccn_seti(ccn_nof_size(32), x, 42);
    
    uint8_t r1[CCSHA256_OUTPUT_SIZE] = {0};
    uint8_t r2[CCSHA256_OUTPUT_SIZE] = {1,};
    
    uint8_t key[33];
    uint8_t key_result[33] = {0x89, 0x36, 0x79, 0x5e, 0x0b, 0x49, 0xcf, 0xfe, 0x78, 0x65, 0xd4, 0xf0, 0x51, 0x1b, 0x9d, 0xf9, 0xd6, 0x1d, 0x9e, 0x49, 0x66, 0xc6, 0x79, 0x13, 0x8e, 0xe9, 0xba, 0x11, 0x43, 0xb4, 0xc2, 0x95, 0xfe};
    
    int status = ccckg_derive_sk(ctx, x, r1, r2, sizeof(key), key);
    ok_memcmp_or_fail(key, key_result, sizeof(key), "SK derivation doesn't match");

    return status;
}

int ccckg_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    ccec_const_cp_t curves[] = { ccec_cp_192(), ccec_cp_224(), ccec_cp_256(), ccec_cp_384(), ccec_cp_521() };
    const struct ccdigest_info *hashes[] = { ccsha256_di(), ccsha384_di(), ccsha512_di() };

    int num_tests = 0;
    num_tests += 7; // full run tests
    num_tests *= CC_ARRAY_LEN(curves) * CC_ARRAY_LEN(hashes);
    num_tests += 16; // bogus inputs
    num_tests += 5;  // bogus commitment
    num_tests += 3;  // bogus scalar
    num_tests += 8;  // bogus shares
    num_tests += 5;  // bogus opening
    num_tests += 15; // state machine
    num_tests += 2;  // SK derivation
    plan_tests(num_tests);

    for (size_t i = 0; i < CC_ARRAY_LEN(curves); i++) {
        ccec_const_cp_t cp = curves[i];

        for (size_t j = 0; j < CC_ARRAY_LEN(hashes); j++) {
            const struct ccdigest_info *di = hashes[j];

            is(test_full_run(cp, di), 0, "Full run test");
        }
    }

    is(test_bogus_inputs(), 0, "Bogus input test");
    is(test_bogus_commitment(), 0, "Bogus commitment test");
    is(test_bogus_scalar(), 0, "Bogus scalar test");
    is(test_bogus_share(), 0, "Bogus share test");
    is(test_bogus_share_infinity(), 0, "Bogus share test");
    is(test_bogus_opening(), 0, "Bogus opening test");
    is(test_state_machine(), 0, "State machine test");
    is(test_ccckg_derive_sk_kat(), 0, "SK derivation test");

    return 0;
}
