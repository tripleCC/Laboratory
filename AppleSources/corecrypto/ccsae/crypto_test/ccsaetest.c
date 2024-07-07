/* Copyright (c) (2018-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccsha2.h>
#include "ccrng_sequence_non_repeat.h"
#include "ccsae.h"
#include "ccsae_priv.h"
#include "ccec_internal.h"
#include "ccsae_internal.h"
#include "cc_priv.h"
#include "ccsaetest.h"

#include "cczp_internal.h"

#include "testmore.h"
#include "testccnBuffer.h"
#include "testbyteBuffer.h"

#include "cc_debug.h"

#define CCSAE_RAND_GEN_INDEX 1
#define CCSAE_MASK_GEN_INDEX 2

// Defines a buffer containing uniformly random data.
// Buffer size is random between 1 and 16 bytes.
#define DEF_RANDOM_BYTE_BUF(_name_)                                \
    uint64_t _name_##_len_pre;                                     \
    is(ccrng_uniform(rng, 16, &_name_##_len_pre), 0, "RNG error"); \
    size_t _name_##_len = (size_t)_name_##_len_pre + 1;            \
    uint8_t _name_[_name_##_len];                                  \
    is(ccrng_generate(rng, _name_##_len, _name_), 0, "RNG error");

const struct ccsae_test_vector ccsae_test_vectors[] = {
#include "../test_vectors/ccsae_vectors.inc"
    // End
    {
        .di = NULL,
    }
};

const struct ccsae_test_vector ccsae_3_loop_vector[] = {
#include "../test_vectors/ccsae_3_loop_vector.inc"
    // End
    {
        .di = NULL,
    }
};

const struct ccsae_h2c_test_vector ccsae_h2c_test_vectors[] = {
#include "../test_vectors/ccsae_h2c_vectors.inc"
    // End
    {
        .di = NULL,
    }
};

/*
 This rng allows generation of specific scalars based on how many RNG calls have been made.
*/
struct ccrng_sae_scalar {
    size_t index;
    const uint8_t *scalar;
    size_t scalar_nbytes;
    struct ccrng_sae_scalar *next;
};

struct ccrng_sae_test {
    CCRNG_STATE_COMMON
    cc_size n;
    size_t index;
    struct ccrng_sae_scalar *scalars;
};

static int ccrng_sae_generate(struct ccrng_state *rng, size_t entropy_size, void *entropy)
{
    struct ccrng_sae_test *irng = (struct ccrng_sae_test *)rng;
    struct ccrng_sae_scalar *scalar = irng->scalars;

    while (scalar != NULL && scalar->index != irng->index) {
        scalar = scalar->next;
    }

    if (scalar == NULL) {
        struct ccrng_state *grng = global_test_rng;
        irng->index += 1;
        return ccrng_generate(grng, entropy_size, entropy);
    }

    cc_unit s[irng->n];
    if (ccn_read_uint(irng->n, s, scalar->scalar_nbytes, scalar->scalar) != CCERR_OK) {
        return CCERR_PARAMETER;
    }
    ccn_sub1(irng->n, s, s, 1);
    ccn_swap(irng->n, s);

    if (ccn_write_uint_padded(irng->n, s, entropy_size, entropy) < 0) {
        return CCERR_OUT_OF_ENTROPY;
    }

    irng->index += 1;
    return CCERR_OK;
}

static void ccrng_sae_init(struct ccrng_sae_test *rng, ccec_const_cp_t cp)
{
    rng->generate = ccrng_sae_generate;
    rng->index = 0;
    rng->n = ccec_cp_n(cp);

    struct ccrng_sae_scalar *sentinel = malloc(sizeof(struct ccrng_sae_scalar));
    sentinel->index = SIZE_MAX;
    sentinel->scalar = NULL;
    sentinel->scalar_nbytes = 0;
    sentinel->next = NULL;

    rng->scalars = sentinel;
}

static void ccrng_sae_free(struct ccrng_sae_test *rng)
{
    struct ccrng_sae_scalar *scalar = rng->scalars;
    while (scalar != NULL) {
        struct ccrng_sae_scalar *next = scalar->next;
        free(scalar);
        scalar = next;
    }
}

static int ccrng_sae_generate_scalar(struct ccrng_sae_test *rng, size_t scalar_nbytes, const uint8_t *scalar_bytes, size_t index)
{
    struct ccrng_sae_scalar *scalar = malloc(sizeof(struct ccrng_sae_scalar));
    if (scalar == NULL) {
        return CCERR_INTERNAL;
    }
    scalar->index = index;
    scalar->scalar = scalar_bytes;
    scalar->scalar_nbytes = scalar_nbytes;
    scalar->next = NULL;

    struct ccrng_sae_scalar *parent = rng->scalars;
    while (parent->next != NULL) {
        parent = parent->next;
    }

    parent->next = scalar;
    return CCERR_OK;
}

static int ccsae_test_pwe_not_found(const struct ccsae_test_vector *vector)
{
    int status = 0;
    byteBuffer password = hexStringToBytes(vector->password);
    byteBuffer password_identifier = hexStringToBytes(vector->password_identifier);
    byteBuffer A_name = hexStringToBytes(vector->A);
    byteBuffer B_name = hexStringToBytes(vector->B);
    byteBuffer rand = hexStringToBytes(vector->rand);
    byteBuffer mask = hexStringToBytes(vector->mask);

    ccec_const_cp_t cp = vector->curve();
    const struct ccdigest_info *di = vector->di;

    struct ccrng_sae_test rng;
    ccrng_sae_init(&rng, cp);
    ccrng_sae_generate_scalar(&rng, rand->len, rand->bytes, CCSAE_RAND_GEN_INDEX);
    ccrng_sae_generate_scalar(&rng, mask->len, mask->bytes, CCSAE_MASK_GEN_INDEX);

    ccsae_ctx_decl(cp, A);
    int init_status = ccsae_init(A, cp, (struct ccrng_state *)&rng, di);
    size_t commit_size = 1;
    if (init_status == CCERR_OK) {
        commit_size = ccsae_sizeof_commitment(A);
    }
    uint8_t commitment[commit_size];

    is_or_goto(init_status, CCERR_OK, "Error during initilization", errout);

    // Now artificially limit the number of hunting and pecking loops
    is_or_goto(ccsae_generate_commitment_init(A), CCERR_OK, "commit init failure", errout);
    A->iterations = 2;

    is_or_goto(ccsae_generate_commitment_partial(A,
                                                 A_name->bytes,
                                                 A_name->len,
                                                 B_name->bytes,
                                                 B_name->len,
                                                 password->bytes,
                                                 password->len,
                                                 password_identifier->bytes,
                                                 password_identifier->len,
                                                 2),
               CCERR_OK,
               "commit partial failure",
               errout);

    is_or_goto(ccsae_generate_commitment_finalize(A, commitment),
               CCSAE_HUNTPECK_EXCEEDED_MAX_TRIALS,
               "Hunting and Pecking phase should fail",
               errout);

    status = 1;
errout:
    free(password);
    free(password_identifier);
    free(A_name);
    free(B_name);
    free(rand);
    free(mask);
    ccrng_sae_free(&rng);
    return status;
}

static int ccsae_test_vector(const struct ccsae_test_vector *vector)
{
    int status = 0;
    byteBuffer password = hexStringToBytes(vector->password);
    byteBuffer password_identifier = hexStringToBytes(vector->password_identifier);
    byteBuffer A_name = hexStringToBytes(vector->A);
    byteBuffer B_name = hexStringToBytes(vector->B);
    byteBuffer rand = hexStringToBytes(vector->rand);
    byteBuffer mask = hexStringToBytes(vector->mask);
    byteBuffer commit_vector = hexStringToBytes(vector->commit);
    byteBuffer peer_commitment = hexStringToBytes(vector->peer_commit);
    byteBuffer send_confirm = hexStringToBytes(vector->send_confirm);
    byteBuffer confirm_vector = hexStringToBytes(vector->confirm);
    byteBuffer peer_send_confirm = hexStringToBytes(vector->peer_send_confirm);
    byteBuffer peer_confirmation = hexStringToBytes(vector->peer_confirm);
    byteBuffer kck_vector = hexStringToBytes(vector->kck);
    byteBuffer pmk_vector = hexStringToBytes(vector->pmk);
    byteBuffer pmkid_vector = hexStringToBytes(vector->pmkid);

    uint8_t kck[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t pmk[CCSAE_PMK_SIZE];
    uint8_t pmkid[CCSAE_PMKID_SIZE];
    uint8_t kck_iuf[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t pmk_iuf[CCSAE_PMK_SIZE];
    uint8_t pmkid_iuf[CCSAE_PMKID_SIZE];

    ccec_const_cp_t cp = vector->curve();
    const struct ccdigest_info *di = vector->di;

    struct ccrng_sae_test rng;
    struct ccrng_sae_test rng_iuf;
    ccrng_sae_init(&rng, cp);
    ccrng_sae_init(&rng_iuf, cp);

    ccsae_ctx_decl(cp, A);
    ccsae_ctx_decl(cp, A_iuf);
    int init_status = ccsae_init(A, cp, (struct ccrng_state *)&rng, di);
    size_t commit_size = 1;
    size_t confirm_size = 1;
    if (init_status == CCERR_OK) {
        commit_size = ccsae_sizeof_commitment(A);
        confirm_size = ccsae_sizeof_confirmation(A);
    }
    int init_status_iuf = ccsae_init(A_iuf, cp, (struct ccrng_state *)&rng_iuf, di);
    uint8_t commitment[commit_size];
    uint8_t commitment_iuf[commit_size];
    uint8_t confirmation[confirm_size];
    uint8_t confirmation_iuf[confirm_size];

    ccrng_sae_generate_scalar(&rng, rand->len, rand->bytes, CCSAE_RAND_GEN_INDEX);
    ccrng_sae_generate_scalar(&rng, mask->len, mask->bytes, CCSAE_MASK_GEN_INDEX);
    ccrng_sae_generate_scalar(&rng_iuf, rand->len, rand->bytes, CCSAE_RAND_GEN_INDEX);
    ccrng_sae_generate_scalar(&rng_iuf, mask->len, mask->bytes, CCSAE_MASK_GEN_INDEX);

    is_or_goto(init_status, CCERR_OK, "Error during initilization", errout);
    is_or_goto(init_status_iuf, CCERR_OK, "Error during initilization", errout);
    is_or_goto(commit_size, commit_vector->len, "Wrong Commitmment Size", errout);
    is_or_goto(confirm_size, confirm_vector->len, "Wrong Confirmation Size", errout);

    // Generate Commitment
    is_or_goto(ccsae_generate_commitment(A,
                                         A_name->bytes,
                                         A_name->len,
                                         B_name->bytes,
                                         B_name->len,
                                         password->bytes,
                                         password->len,
                                         password_identifier->bytes,
                                         password_identifier->len,
                                         commitment),
               CCERR_OK,
               "Generate Commit Failure",
               errout);
    ok_memcmp_or_goto(commitment, commit_vector->bytes, commit_size, errout, "Incorrect Commitment");

    is_or_goto(ccsae_generate_commitment_init(A_iuf), CCERR_OK, "Commitment Init Failure", errout);
    for (int i = 0; i < 40; i++) {
        int gen_commit_ret = ccsae_generate_commitment_partial(A_iuf,
                                                               A_name->bytes,
                                                               A_name->len,
                                                               B_name->bytes,
                                                               B_name->len,
                                                               password->bytes,
                                                               password->len,
                                                               password_identifier->bytes,
                                                               password_identifier->len,
                                                               1);
        ok_or_goto(gen_commit_ret == CCERR_OK || gen_commit_ret == CCSAE_GENERATE_COMMIT_CALL_AGAIN,
                   "Commitment partial Failure",
                   errout);
    }
    is_or_goto(ccsae_generate_commitment_finalize(A_iuf, commitment_iuf), CCERR_OK, "Commitment Finalize Failure", errout);
    ok_memcmp_or_goto(commitment_iuf, commit_vector->bytes, commit_size, errout, "Incorrect Commitment IUF");

    // Verify commitment
    is_or_goto(ccsae_verify_commitment(A, peer_commitment->bytes), CCERR_OK, "Verification error", errout);
    is_or_goto(ccsae_verify_commitment(A_iuf, peer_commitment->bytes), CCERR_OK, "Verification error IUF", errout);

    // Generate confirmation
    is_or_goto(
        ccsae_generate_confirmation(A, send_confirm->bytes, confirmation), CCERR_OK, "Generate confirmation error", errout);
    ok_memcmp_or_goto(confirmation, confirm_vector->bytes, confirm_size, errout, "Incorrect confirmation");
    is_or_goto(ccsae_generate_confirmation(A_iuf, send_confirm->bytes, confirmation_iuf),
               CCERR_OK,
               "Generate confirmation error IUF",
               errout);
    ok_memcmp_or_goto(confirmation_iuf, confirm_vector->bytes, confirm_size, errout, "Incorrect confirmation IUF");

    is_or_goto(ccsae_verify_confirmation(A, peer_send_confirm->bytes, peer_confirmation->bytes),
               CCERR_OK,
               "Incorrect Peer Confirmation",
               errout);
    is_or_goto(ccsae_verify_confirmation(A_iuf, peer_send_confirm->bytes, peer_confirmation->bytes),
               CCERR_OK,
               "Incorrect Peer Confirmation IUF",
               errout);

    size_t kck_nbytes = ccsae_sizeof_kck(A);

    is_or_goto(ccsae_get_keys(A, kck, pmk, pmkid), CCERR_OK, "Key Grab Error", errout);
    is_or_goto(kck_nbytes, kck_vector->len, "Incorrect kck length", errout);
    ok_memcmp_or_goto(kck, kck_vector->bytes, kck_vector->len, errout, "Incorrect kck");
    ok_memcmp_or_goto(pmk, pmk_vector->bytes, pmk_vector->len, errout, "Incorrect pmk");
    ok_memcmp_or_goto(pmkid, pmkid_vector->bytes, pmkid_vector->len, errout, "Incorrect pmkid");

    is_or_goto(ccsae_get_keys(A_iuf, kck_iuf, pmk_iuf, pmkid_iuf), CCERR_OK, "Key Grab Error IUF", errout);
    ok_memcmp_or_goto(kck_iuf, kck_vector->bytes, kck_vector->len, errout, "Incorrect kck IUF");
    ok_memcmp_or_goto(pmk_iuf, pmk_vector->bytes, pmk_vector->len, errout, "Incorrect pmk IUF");
    ok_memcmp_or_goto(pmkid_iuf, pmkid_vector->bytes, pmkid_vector->len, errout, "Incorrect pmkid IUF");
    status = 1;
errout:
    if (status != 1) {
        cc_printf("Failed test: %s\n", vector->test_desc);
    }
    ccrng_sae_free(&rng);
    ccrng_sae_free(&rng_iuf);
    free(password);
    free(password_identifier);
    free(A_name);
    free(B_name);
    free(rand);
    free(mask);
    free(commit_vector);
    free(peer_commitment);
    free(send_confirm);
    free(confirm_vector);
    free(peer_send_confirm);
    free(peer_confirmation);
    free(kck_vector);
    free(pmk_vector);
    free(pmkid_vector);
    return status;
}

static int ccsae_vector_tests(const struct ccsae_test_vector *vectors)
{
    size_t test_counter = 0;
    int test_status = 1;
    const struct ccsae_test_vector *current_vector = &vectors[test_counter++];

    while (current_vector->di != NULL && test_status) {
        test_status = ccsae_test_vector(current_vector);
        current_vector = &vectors[test_counter++];
    }
    return test_status;
}

static int ccsae_h2c_test_vector(const struct ccsae_h2c_test_vector *vector)
{
    int status = 0;
    byteBuffer password = hexStringToBytes(vector->password);
    byteBuffer ssid = hexStringToBytes(vector->ssid);
    byteBuffer identifier = hexStringToBytes(vector->identifier);
    byteBuffer A_name = hexStringToBytes(vector->A);
    byteBuffer B_name = hexStringToBytes(vector->B);
    byteBuffer PTx = hexStringToBytes(vector->PTx);
    byteBuffer PTy = hexStringToBytes(vector->PTy);
    byteBuffer rand = hexStringToBytes(vector->rand);
    byteBuffer mask = hexStringToBytes(vector->mask);
    byteBuffer commit_vector = hexStringToBytes(vector->commit);
    byteBuffer peer_commitment = hexStringToBytes(vector->peer_commit);
    byteBuffer send_confirm = hexStringToBytes(vector->send_confirm);
    byteBuffer confirm_vector = hexStringToBytes(vector->confirm);
    byteBuffer peer_send_confirm = hexStringToBytes(vector->peer_send_confirm);
    byteBuffer peer_confirmation = hexStringToBytes(vector->peer_confirm);
    byteBuffer kck_vector = hexStringToBytes(vector->kck);
    byteBuffer pmk_vector = hexStringToBytes(vector->pmk);
    byteBuffer pmkid_vector = hexStringToBytes(vector->pmkid);

    uint8_t kck[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t pmk[CCSAE_PMK_SIZE];
    uint8_t pmkid[CCSAE_PMKID_SIZE];

    ccec_const_cp_t cp = vector->curve();
    const struct ccdigest_info *di = vector->di;

    struct ccrng_sae_test rng;
    ccrng_sae_init(&rng, cp);

    ccsae_ctx_decl(cp, A);
    int init_status = ccsae_init(A, cp, (struct ccrng_state *)&rng, di);
    size_t commit_size = 1;
    size_t confirm_size = 1;
    if (init_status == CCERR_OK) {
        commit_size = ccsae_sizeof_commitment(A);
        confirm_size = ccsae_sizeof_confirmation(A);
    }
    uint8_t commitment[commit_size];
    uint8_t confirmation[confirm_size];

    size_t pt_size = ccsae_sizeof_pt(vector->h2c);
    uint8_t pt[pt_size];

    ccrng_sae_generate_scalar(&rng, rand->len, rand->bytes, 2);
    ccrng_sae_generate_scalar(&rng, mask->len, mask->bytes, 3);

    is_or_goto(init_status, CCERR_OK, "Error during initilization", errout);
    is_or_goto(commit_size, commit_vector->len, "Wrong Commitmment Size", errout);
    is_or_goto(confirm_size, confirm_vector->len, "Wrong Confirmation Size", errout);

    is_or_goto(ccsae_generate_h2c_pt(
                   vector->h2c, ssid->bytes, ssid->len, password->bytes, password->len, identifier->bytes, identifier->len, pt),
               CCERR_OK,
               "Generate PT Failure",
               errout);
    ok_memcmp_or_goto(pt + 1, PTx->bytes, PTx->len, errout, "Incorrect PTx");
    ok_memcmp_or_goto(pt + 1 + PTx->len, PTy->bytes, PTy->len, errout, "Incorrect PTy");

    is_or_goto(ccsae_generate_h2c_commit(A, A_name->bytes, A_name->len, B_name->bytes, B_name->len, pt, pt_size, commitment),
               CCERR_OK,
               "Generate Commit Failure",
               errout);
    ok_memcmp_or_goto(commitment, commit_vector->bytes, commit_size, errout, "Incorrect Commitment");

    // Verify commitment
    is_or_goto(ccsae_verify_commitment(A, peer_commitment->bytes), CCERR_OK, "Verification error", errout);

    // Generate confirmation
    is_or_goto(
        ccsae_generate_confirmation(A, send_confirm->bytes, confirmation), CCERR_OK, "Generate confirmation error", errout);
    ok_memcmp_or_goto(confirmation, confirm_vector->bytes, confirm_size, errout, "Incorrect confirmation");

    is_or_goto(ccsae_verify_confirmation(A, peer_send_confirm->bytes, peer_confirmation->bytes),
               CCERR_OK,
               "Incorrect Peer Confirmation",
               errout);

    size_t kck_nbytes = ccsae_sizeof_kck_h2c(A);

    is_or_goto(ccsae_get_keys(A, kck, pmk, pmkid), CCERR_OK, "Key Grab Error", errout);
    is_or_goto(kck_nbytes, kck_vector->len, "Incorrect kck length", errout);
    ok_memcmp_or_goto(kck, kck_vector->bytes, kck_vector->len, errout, "Incorrect kck");
    ok_memcmp_or_goto(pmk, pmk_vector->bytes, pmk_vector->len, errout, "Incorrect pmk");
    ok_memcmp_or_goto(pmkid, pmkid_vector->bytes, pmkid_vector->len, errout, "Incorrect pmkid");
    status = 1;
errout:
    if (status != 1) {
        cc_printf("Failed h2c test: %s\n", vector->test_desc);
    }
    ccrng_sae_free(&rng);
    free(password);
    free(ssid);
    free(identifier);
    free(A_name);
    free(B_name);
    free(PTx);
    free(PTy);
    free(rand);
    free(mask);
    free(commit_vector);
    free(peer_commitment);
    free(send_confirm);
    free(confirm_vector);
    free(peer_send_confirm);
    free(peer_confirmation);
    free(kck_vector);
    free(pmk_vector);
    free(pmkid_vector);
    return status;
}

static int ccsae_h2c_vector_tests(const struct ccsae_h2c_test_vector *vectors)
{
    size_t test_counter = 0;
    int test_status = 1;
    const struct ccsae_h2c_test_vector *current_vector = &vectors[test_counter++];

    while (current_vector->di != NULL && test_status) {
        test_status = ccsae_h2c_test_vector(current_vector);
        current_vector = &vectors[test_counter++];
    }
    return test_status;
}

static int ccsae_test_invalid_peer_values(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    struct ccrng_state *rng = global_test_rng;
    cc_size n = ccec_cp_n(cp);
    cc_size tn = ccec_cp_prime_size(cp);

    ccsae_ctx_decl(cp, ctxA);
    is(ccsae_init(ctxA, cp, rng, di), 0, "Initialize Error");

    DEF_RANDOM_BYTE_BUF(A);
    DEF_RANDOM_BYTE_BUF(B);
    DEF_RANDOM_BYTE_BUF(password);
    DEF_RANDOM_BYTE_BUF(password_identifier);
    cc_size A_commit_size = ccsae_sizeof_commitment(ctxA);
    uint8_t A_commit[A_commit_size];

    uint8_t test_commitment[A_commit_size];
    memset(test_commitment, 0, A_commit_size);

    ccn_write_uint_padded(n, ccec_const_point_x(ccec_cp_g(cp), cp), tn, test_commitment + tn);
    ccn_write_uint_padded(n, ccec_const_point_y(ccec_cp_g(cp), cp), tn, test_commitment + tn + tn);

    is(ccsae_generate_commitment(
           ctxA, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, A_commit),
       0,
       "A generate commitment failure");
    isnt(ccsae_verify_commitment(ctxA, test_commitment), CCERR_OK, "Failure - accepted cs = 0");

    test_commitment[A_commit_size - 1] = 1;
    isnt(ccsae_verify_commitment(ctxA, test_commitment), CCERR_OK, "Failure - accepted cs = 1");

    ccn_write_uint(n, cczp_prime(ccec_cp_zq(cp)), tn, test_commitment);
    isnt(ccsae_verify_commitment(ctxA, test_commitment), CCERR_OK, "Failure - accepted cs = q");

    memcpy(test_commitment, A_commit, tn);
    isnt(ccsae_verify_commitment(ctxA, test_commitment), CCERR_OK, "Failure - peerCS = myCS");

    memcpy(test_commitment, A_commit + tn, tn); // Set the commit scalar to something "random" so we hit the following cases
    memcpy(test_commitment + tn, A_commit + tn, tn);
    isnt(ccsae_verify_commitment(ctxA, test_commitment), CCERR_OK, "Failure - peerX = myX");

    memset(test_commitment + tn, 0xff, tn);
    memcpy(test_commitment + tn + tn, A_commit + 2 * tn, tn);
    isnt(ccsae_verify_commitment(ctxA, test_commitment), CCERR_OK, "Failure - peerY = myY");

    return 0;
}

static int ccsae_test_curves_and_hashes(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    struct ccrng_state *rng = global_test_rng;
    cc_size n_bytes = ccec_cp_prime_size(cp);

    ccsae_ctx_decl(cp, ctxA);
    ccsae_ctx_decl(cp, ctxB);

    is(ccsae_init(ctxA, cp, rng, di), 0, "Initialize Error");
    is(ccsae_init(ctxB, cp, rng, di), 0, "Initialize Error");

    // Generate random names...
    DEF_RANDOM_BYTE_BUF(A);
    DEF_RANDOM_BYTE_BUF(B);
    DEF_RANDOM_BYTE_BUF(password);
    DEF_RANDOM_BYTE_BUF(password_identifier);
    uint8_t A_send_confirmation[2] = { 0, 1 };
    uint8_t B_send_confirmation[2] = { 0, 1 };
    ccrng_generate(rng, 2, A_send_confirmation);
    ccrng_generate(rng, 2, B_send_confirmation);

    cc_size A_commit_size = ccsae_sizeof_commitment(ctxA);
    cc_size B_commit_size = ccsae_sizeof_commitment(ctxB);
    cmp_ok(A_commit_size, ==, B_commit_size, "Commit size mismatch");
    uint8_t A_commit[A_commit_size];
    uint8_t B_commit[B_commit_size];

    is(ccsae_generate_commitment(
           ctxA, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, A_commit),
       0,
       "A generate commitment failure");
    is(ccsae_generate_commitment(
           ctxB, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, B_commit),
       0,
       "B generate commitment failure");
    isnt(memcmp(A_commit, B_commit, A_commit_size), 0, "Generated commits are the same");

    uint8_t AB_scalar[n_bytes];
    uint8_t AB_CE[2 * n_bytes];

    memcpy(AB_scalar, B_commit, n_bytes);
    memcpy(AB_CE, B_commit + n_bytes, 2 * n_bytes);
    is(ccsae_verify_commitment(ctxA, B_commit),
       CCERR_OK,
       "A->B Commitment Verification Error: curve%zu",
       ccec_cp_prime_bitlen(cp));
    memcpy(AB_scalar, A_commit, n_bytes);
    memcpy(AB_CE, A_commit + n_bytes, 2 * n_bytes);
    is(ccsae_verify_commitment(ctxB, A_commit), CCERR_OK, "B->A Commitment Verification Error");

    uint8_t A_confirmation[di->output_size];
    uint8_t B_confirmation[di->output_size];

    is(ccsae_generate_confirmation(ctxA, A_send_confirmation, A_confirmation), CCERR_OK, "A confirmation generation error");
    is(ccsae_generate_confirmation(ctxB, B_send_confirmation, B_confirmation), CCERR_OK, "A confirmation generation error");
    isnt(memcmp(A_confirmation, B_confirmation, di->output_size), 0, "Generated confirmations are the same...");

    ok_memcmp(ccsae_ctx_KCK(ctxA), ccsae_ctx_KCK(ctxB), 32, "KCK comparison failure");
    ok_memcmp(ccsae_ctx_PMK(ctxA), ccsae_ctx_PMK(ctxB), 32, "PMK comparison failure");

    is(ccsae_verify_confirmation(ctxA, B_send_confirmation, B_confirmation), 0, "A->B Confirmation Verification Error");
    is(ccsae_verify_confirmation(ctxB, A_send_confirmation, A_confirmation), 0, "B->A Confirmation Verification Error");

    size_t kck_nbytes = ccsae_sizeof_kck(ctxA);
    is(kck_nbytes, ccsae_sizeof_kck(ctxB), "Invalid contexts");

    uint8_t Akck[MAX_DIGEST_OUTPUT_SIZE], Bkck[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t Apmk[CCSAE_PMK_SIZE], Bpmk[CCSAE_PMK_SIZE];
    uint8_t Apmkid[CCSAE_PMKID_SIZE], Bpmkid[CCSAE_PMKID_SIZE];

    is(ccsae_get_keys(ctxA, Akck, Apmk, Apmkid), 0, "A Get Keys Failure");
    is(ccsae_get_keys(ctxB, Bkck, Bpmk, Bpmkid), 0, "B Get Keys Failure");
    ok_memcmp(Akck, Bkck, kck_nbytes, "Akck != Bkck");
    ok_memcmp(Apmk, Bpmk, 32, "Apmk != Bpmk");
    ok_memcmp(Apmkid, Bpmkid, 16, "Apmkid != Bpmlkid");

    return 0;
}

static int compute_path(uint8_t pathA[5], uint8_t pathB[5])
{
    uint8_t paths[2][5];
    memcpy(paths[0], pathA, 5);
    memcpy(paths[1], pathB, 5);

    int result = 0;
    struct ccrng_state *rng = global_test_rng;
    struct ccsae_ctx ctxs[2][CCSAE_SIZE_P256_SHA256];
    ccsae_init_p256_sha256(ctxs[0], rng);
    ccsae_init_p256_sha256(ctxs[1], rng);

    DEF_RANDOM_BYTE_BUF(A);
    DEF_RANDOM_BYTE_BUF(B);
    DEF_RANDOM_BYTE_BUF(password);
    DEF_RANDOM_BYTE_BUF(password_identifier);
    uint8_t send_confirmation[2] = { 0, 1 };

    uint8_t commits[2][ccsae_sizeof_commitment(ctxs[0])];
    uint8_t confirmations[2][ccsae_sizeof_confirmation(ctxs[0])];
    uint8_t kck[MAX_DIGEST_OUTPUT_SIZE];
    uint8_t pmk[CCSAE_PMK_SIZE];
    uint8_t pmkid[CCSAE_PMKID_SIZE];

    int cc, occ;

    for (int i = 0; i < 5; i++) {
        cc = (pathA[i] <= pathB[i]) ? 0 : 1;
        occ = (pathA[i] <= pathB[i]) ? 1 : 0;

        for (int j = 0; j < 2; j++) {
            if (paths[cc][i] == 1) {
                result = ccsae_generate_commitment(ctxs[cc],
                                                   A,
                                                   A_len,
                                                   B,
                                                   B_len,
                                                   password,
                                                   password_len,
                                                   password_identifier,
                                                   password_identifier_len,
                                                   commits[cc]);
            } else if (paths[cc][i] == 2) {
                result = ccsae_verify_commitment(ctxs[cc], commits[occ]);
            } else if (paths[cc][i] == 3) {
                result = ccsae_generate_confirmation(ctxs[cc], send_confirmation, confirmations[cc]);
            } else if (paths[cc][i] == 4) {
                result = ccsae_verify_confirmation(ctxs[cc], send_confirmation, confirmations[occ]);
            } else if (paths[cc][i] == 5) {
                result = ccsae_get_keys(ctxs[cc], kck, pmk, pmkid);
            } else {
                cc_assert(false);
            }
            if (result != CCERR_OK)
                return result;

            result = cc;
            cc = occ;
            occ = result;
        }
    }
    return CCERR_OK;
}

static int permute(uint8_t arr[5])
{
    int k = -1;
    int l = 0;
    int s = 0;
    for (s = 0; s < 4; s++) {
        if (arr[s] < arr[s + 1]) {
            k = s;
        }
    }
    if (k == -1)
        return 0;

    for (s = 0; s < 5; s++) {
        if (arr[k] < arr[s]) {
            l = s;
        }
    }
    CC_SWAP(arr[k], arr[l]);
    int numswaps = (4 - k) / 2;
    for (s = 0; s < numswaps; s++) {
        CC_SWAP(arr[k + 1 + s], arr[4 - s]);
    }
    return 1;
}

static int ccsae_test_state_machine(void)
{
    /*  Valid state transitions:
        Init ->
        Commit generate ->
        Commit Verify ->
            Generate Confirmation ->
          OR
            Verify Confirmation ->
        -> Get Keys
         Valid paths are [0,1,2,3,4,5] & [0,1,2,4,3,5]
     */
    uint8_t pathA[5] = { 1, 2, 3, 4, 5 };
    uint8_t pathB[5] = { 1, 2, 3, 4, 5 };
    int valid_paths = 0;

    do {
        if (compute_path(pathA, pathB) == CCERR_OK) {
            valid_paths += 1;
        }
    } while (permute(pathA));
    return valid_paths == 2;
}

static int ccsae_test_commit_scalar_conditions(void)
{
    /*
        The commit scalar needs to be > 1. We'll force it to be 0 and 1 in the tests below.
     */
    int result;
    struct ccsae_ctx ctx[CCSAE_SIZE_P256_SHA256];
    ccec_const_cp_t cp = ccec_cp_256();
    struct ccrng_sae_test rng;
    const uint8_t password[5] = { 0, 1, 2, 3, 4 };

    // q - 1 + 1 == 0
    uint8_t target_rand[32] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50 };
    uint8_t target_mask[1] = { 0x01 };
    ccrng_sae_init(&rng, cp);
    ccrng_sae_generate_scalar(&rng, sizeof(target_rand), target_rand, CCSAE_RAND_GEN_INDEX);
    ccrng_sae_generate_scalar(&rng, sizeof(target_mask), target_mask, CCSAE_MASK_GEN_INDEX);

    ccsae_init_p256_sha256(ctx, (struct ccrng_state *)&rng);
    uint8_t commit[ccsae_sizeof_commitment(ctx)];

    result = ccsae_generate_commitment(ctx, password, 5, password, 5, password, 5, NULL, 0, commit);
    isnt(result, CCERR_OK, "Error: CS == 0 should fail!");
    ccrng_sae_free(&rng);
    ccsae_ctx_clear(cp, ctx);

    // q - 1 + 2 == 1
    target_mask[0] = 0x02;
    ccrng_sae_init(&rng, cp);
    ccrng_sae_generate_scalar(&rng, sizeof(target_rand), target_rand, CCSAE_RAND_GEN_INDEX);
    ccrng_sae_generate_scalar(&rng, sizeof(target_mask), target_mask, CCSAE_MASK_GEN_INDEX);

    ccsae_init_p256_sha256(ctx, (struct ccrng_state *)&rng);
    result = ccsae_generate_commitment(ctx, password, 5, password, 5, password, 5, NULL, 0, commit);
    isnt(result, CCERR_OK, "Error: CS == 1 should fail!");
    ccrng_sae_free(&rng);

    return 1;
}

#define y2_vs_ap_test_trials 1000
static int ccsae_test_y2_vs_affine_point(ccec_const_cp_t cp)
{
    cc_size n = ccec_cp_n(cp);
    struct ccrng_state *rng = global_test_rng;

    int ret = CCERR_OK;
    int y2_res;
    int affine_res;
    cc_unit x[n];
    cc_unit y[n];
    cc_unit y2[n];
    ccec_point_decl_cp(cp, result);

    CC_DECL_WORKSPACE_TEST(ws);

    // Make sure that we correctly tolerate inputs larger than p (and fail)
    ccn_set(n, x, ccec_cp_p(cp));
    ccn_add1_ws(ws, n, x, x, 1);
    y2_res = ccsae_y2_from_x_ws(ws, cp, y, x);
    is(y2_res, 0, "x = p + 1 should never succeed ccsae_y2_from_x_ws");

    for (int t = 0; t < y2_vs_ap_test_trials; t++) {
        // Quickly find a potential x-coordinate in GF(p)
        ccrng_generate(rng, ccn_sizeof_n(n), x);
        cc_size lbits = ccec_cp_prime_bitlen(cp) & (CCN_UNIT_BITS - 1);
        if (lbits) {
            cc_unit msuMask = (~CC_UNIT_C(0)) >> (CCN_UNIT_BITS - lbits);
            x[n - 1] &= msuMask;
        }

        // Returns 0 on success (found a sqrt), "random" on failure
        affine_res = ccec_affine_point_from_x_ws(ws, cp, (ccec_affine_point_t)result, x);

        // Returns 1 on success (its a qr), 0 on failure (not a qr)
        y2_res = ccsae_y2_from_x_ws(ws, cp, y, x);

        cczp_sqrt_ws(ws, (cczp_const_t)ccec_cp_zp(cp), y2, y);
        cczp_from_ws(ws, (cczp_const_t)ccec_cp_zp(cp), y2, y2);
        ccn_sub_ws(ws, n, y, ccec_cp_p(cp), y2);

        // Either the result is no sqrt or it's valid and the sqrt roots match
        ok((y2_res == 0 && affine_res != 0) ||
               (y2_res == 1 && affine_res == 0 &&
                ((ccn_cmp(n, y, ccec_const_point_y(result, cp)) == 0) || (ccn_cmp(n, y2, ccec_const_point_y(result, cp)) == 0))),
           "Error: sqrt of ccsae_y2_from_x is incorrect!");
    }

    CC_FREE_WORKSPACE(ws);
    return ret;
}

static int ccsae_test_CCSAE_SIZE_P256_SHA256_size(void)
{
    ccec_const_cp_t cp = ccec_cp_256();

    size_t ctx_actual_size = ccsae_sizeof_ctx(cp);
    size_t ctx_macro_size = CCSAE_SIZE_P256_SHA256 * sizeof(struct ccsae_ctx);

    cmp_ok(ctx_macro_size, >=, ctx_actual_size, "CCSAE_SIZE_P256_SHA256 context size < necessary size");
    cmp_ok(ctx_macro_size,
           <
           , ctx_actual_size + sizeof(struct ccsae_ctx), "CCSAE_SIZE_P256_SHA256 size should be close to actual size");
    return 1;
}

static int ccsae_test_CCSAE_SIZE_P384_SHA384_size(void)
{
    ccec_const_cp_t cp = ccec_cp_384();

    size_t ctx_actual_size = ccsae_sizeof_ctx(cp);
    size_t ctx_macro_size = CCSAE_SIZE_P384_SHA384 * sizeof(struct ccsae_ctx);

    cmp_ok(ctx_macro_size, >=, ctx_actual_size, "CCSAE_SIZE_P384_SHA384 context size < necessary size");
    cmp_ok(ctx_macro_size,
           <
           , ctx_actual_size + sizeof(struct ccsae_ctx), "CCSAE_SIZE_P384_SHA384 size should be close to actual size");
    return 1;
}

static int ccsae_test_iuf_generate_commitment(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    struct ccrng_state *rng = global_test_rng;
    uint8_t rng_ss[2048];
    ccrng_generate(rng, sizeof(rng_ss), rng_ss);

    struct ccrng_sequence_state sequence_ctx;
    int err = ccrng_sequence_init(&sequence_ctx, sizeof(rng_ss), rng_ss);
    ok_or_fail(err == 0, "ccrng_sequence_init failure");

    DEF_RANDOM_BYTE_BUF(A);
    DEF_RANDOM_BYTE_BUF(B);
    DEF_RANDOM_BYTE_BUF(password);
    DEF_RANDOM_BYTE_BUF(password_identifier);

    ccsae_ctx_decl(cp, ctx);
    ccsae_ctx_decl(cp, ctx_iuf);

    // Generate first commitment
    ok_or_fail(ccsae_init(ctx, cp, (struct ccrng_state *)&sequence_ctx, di) == CCERR_OK, "Init Failure");
    size_t ctx_csz = ccsae_sizeof_commitment(ctx);
    uint8_t ctx_commitment[ctx_csz];

    err = ccsae_generate_commitment(
        ctx, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, ctx_commitment);
    ok_or_fail(err == CCERR_OK, "ctx generate commitment failure");

    err = ccrng_sequence_init(&sequence_ctx, sizeof(rng_ss), rng_ss);
    ok_or_fail(err == 0, "ccrng_sequence_init failure");

    // Generate second commitment
    ok_or_fail(ccsae_init(ctx_iuf, cp, (struct ccrng_state *)&sequence_ctx, di) == CCERR_OK, "Init Failure");
    size_t ctx_iuf_csz = ccsae_sizeof_commitment(ctx);
    ok_or_fail(ctx_csz == ctx_iuf_csz, "Context commitment sizes differ !");
    uint8_t ctx_iuf_commitment[ctx_iuf_csz];

    ok_or_fail(ccsae_generate_commitment_init(ctx_iuf) == CCERR_OK, "gen commit init failure");
    ok_or_fail(ccsae_generate_commitment_partial(
                   ctx_iuf, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, 10) ==
                   CCSAE_GENERATE_COMMIT_CALL_AGAIN,
               "gen commit partial error");
    ok_or_fail(ccsae_generate_commitment_partial(
                   ctx_iuf, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, 10) ==
                   CCSAE_GENERATE_COMMIT_CALL_AGAIN,
               "gen commit partial error");
    ok_or_fail(ccsae_generate_commitment_partial(
                   ctx_iuf, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, 10) ==
                   CCSAE_GENERATE_COMMIT_CALL_AGAIN,
               "gen commit partial error");
    ok_or_fail(ccsae_generate_commitment_partial(
                   ctx_iuf, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, 10) ==
                   CCERR_OK,
               "gen commit partial error");

    err = ccsae_generate_commitment_finalize(ctx_iuf, ctx_iuf_commitment);
    ok_or_fail(err == CCERR_OK, "gen commit finalize failure");

    ok_memcmp_or_fail(ctx_commitment, ctx_iuf_commitment, ctx_csz, "ctx commitment differs");

    return 1;
}

static int ccsae_test_iuf_state_tests(void)
{
    struct ccrng_state *rng = global_test_rng;
    ccec_const_cp_t cp = ccec_cp_256();
    const struct ccdigest_info *di = ccsha256_di();

    DEF_RANDOM_BYTE_BUF(A);
    DEF_RANDOM_BYTE_BUF(B);
    DEF_RANDOM_BYTE_BUF(password);
    DEF_RANDOM_BYTE_BUF(password_identifier);

    ccsae_ctx_decl(cp, ctx);
    ok_or_fail(ccsae_init(ctx, cp, rng, di) == CCERR_OK, "Init Failure");

    size_t ctx_csz = ccsae_sizeof_commitment(ctx);
    uint8_t ctx_commitment[ctx_csz];

    // Need to commitment_init before partial (and definitely before finalize)
    ok_or_fail(ccsae_generate_commitment_partial(
                   ctx, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, 10) ==
                   CCERR_CALL_SEQUENCE,
               "gen commit partial error");
    ok_or_fail(ccsae_generate_commitment_finalize(ctx, ctx_commitment) == CCERR_CALL_SEQUENCE, "gen commit finalize should fail");

    ok_or_fail(ccsae_generate_commitment_init(ctx) == CCERR_OK, "Init Commit Failure");

    // Need to have called update and have performed the proper amount of calls
    ok_or_fail(ccsae_generate_commitment_finalize(ctx, ctx_commitment) == CCERR_CALL_SEQUENCE, "gen commit finalize should fail");

    // Zero iterations
    ok_or_fail(ccsae_generate_commitment_partial(
                   ctx, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, 0) ==
                   CCERR_PARAMETER,
               "gen commit partial error");

    ok_or_fail(ccsae_generate_commitment_partial(ctx,
                                                 A,
                                                 A_len,
                                                 B,
                                                 B_len,
                                                 password,
                                                 password_len,
                                                 password_identifier,
                                                 password_identifier_len,
                                                 SAE_HUNT_AND_PECK_ITERATIONS - 1) == CCSAE_GENERATE_COMMIT_CALL_AGAIN,
               "gen commit partial error");

    // Need to have called partial and have performed the proper amount of calls
    ok_or_fail(ccsae_generate_commitment_finalize(ctx, ctx_commitment) == CCSAE_NOT_ENOUGH_COMMIT_PARTIAL_CALLS,
               "gen commit partial error");

    ok_or_fail(ccsae_generate_commitment_partial(
                   ctx, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, 253) ==
                   CCERR_OK,
               "gen commit partial error");

    int resy = ccsae_generate_commitment_partial(
        ctx, A, A_len, B, B_len, password, password_len, password_identifier, password_identifier_len, 1);
    ok_or_fail(resy == CCERR_OK, "gen commit partial error");

    ok_or_fail(ccsae_generate_commitment_finalize(ctx, ctx_commitment) == CCERR_OK, "gen commit finalize failure");

    return 1;
}

int ccsae_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    ccec_const_cp_t curves[] = { ccec_cp_192(), ccec_cp_224(), ccec_cp_256(), ccec_cp_384(), ccec_cp_521() };
    const struct ccdigest_info *digests[] = { ccsha224_di(), ccsha256_di(), ccsha384_di(), ccsha512_di() };

    int num_test_vectors = CC_ARRAY_LEN(ccsae_test_vectors) - 1;
    int num_h2c_test_vectors = CC_ARRAY_LEN(ccsae_h2c_test_vectors) - 1;
    int num_tests = 0;

    num_tests += (30 * (CC_ARRAY_LEN(curves) * CC_ARRAY_LEN(digests))); // # tests of test_curves_and_hashes, # curves, # hashes
    num_tests += 1 + (num_test_vectors * 66);                           // ccsae_vector_tests
    num_tests += (17 * (CC_ARRAY_LEN(curves) * CC_ARRAY_LEN(digests))); // invalid_peer_values
    num_tests += 5;                                                     // Hunting and Peck Loop Failure
    num_tests += (120 * 8) + 1;                                         // ccsae_test_state_machine (# permutations x # of tests)
    num_tests += 3;                                                     // ccsae_test_commit_scalar_conditions
    num_tests += ((y2_vs_ap_test_trials + 1) * CC_ARRAY_LEN(curves));   // ccsae_test_y2_vs_affine_point
    num_tests += 1 + 2;                                                 // ccsae_test_CCSAE_SIZE_P256_SHA256_size
    num_tests += 1 + 2;                                                 // ccsae_test_CCSAE_SIZE_P384_SHA384_size
    num_tests += (22 * (CC_ARRAY_LEN(curves) * CC_ARRAY_LEN(digests))); // ccsae_test_iuf_generate_commitment
    num_tests += 20;                                                    // ccsae_test_iuf_state_tests
    num_tests += 1 + (17 * num_h2c_test_vectors);                       // ccsae_h2c_vector_tests
    plan_tests(num_tests);

    for (size_t i = 0; i < CC_ARRAY_LEN(curves); i++) {
        ccec_const_cp_t cp = curves[i];
        for (size_t j = 0; j < CC_ARRAY_LEN(digests); j++) {
            const struct ccdigest_info *di = digests[j];
            is(ccsae_test_curves_and_hashes(cp, di), 0, "Curves & Hashes Failure: curve = %zu, digest = %zu", i, j);
            is(ccsae_test_invalid_peer_values(cp, di), 0, "Invalid peer curves Failure: curve = %zu, digest = %zu", i, j);
            is(ccsae_test_iuf_generate_commitment(cp, di),
               1,
               "Init / Update / Finalize Commitment Failure: curve = %zu, digest = %zu",
               i,
               j);
        }
    }

    ok(ccsae_test_pwe_not_found(&ccsae_3_loop_vector[0]), "Hunting and Peck Loop Failure");
    ok(ccsae_test_state_machine(), "State Machine");
    ok(ccsae_test_commit_scalar_conditions(), "Commit Scalar Conditions");

    ok(ccsae_vector_tests(ccsae_test_vectors), "Test Vectors");
    ok(ccsae_h2c_vector_tests(ccsae_h2c_test_vectors), "H2C Test Vectors");

    for (size_t i = 0; i < CC_ARRAY_LEN(curves); i++) {
        ccec_const_cp_t cp = curves[i];
        ccsae_test_y2_vs_affine_point(cp);
    }

    ok(ccsae_test_CCSAE_SIZE_P256_SHA256_size(), "CCSAE_SIZE_P256_SHA256 Size Tests");
    ok(ccsae_test_CCSAE_SIZE_P384_SHA384_size(), "CCSAE_SIZE_P384_SHA384 Size Tests");
    ok(ccsae_test_iuf_state_tests(), "IUF state tests failure");

    return 0;
}
