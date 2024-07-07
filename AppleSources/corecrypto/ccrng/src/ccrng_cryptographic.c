/* Copyright (c) (2016-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccaes.h>
#include "cc_debug.h"
#include <corecrypto/cc_priv.h>
#include "ccrng_internal.h"
#include "cc_absolute_time.h"
#include "cc_macros.h"
#include "ccrng_cryptographic_priv.h"
#include <corecrypto/ccrng.h>
#include "ccrng_cryptographic.h"
#include "cc_memory.h"
#include "cc_lock.h"

#if !CC_DARWIN || CC_BUILT_FOR_TESTING

#define CC_PREDICTION_BREAK_TIMER 1

#if CC_PREDICTION_BREAK_TIMER

static uint64_t cc_uptime_nsec(void)
{
    return cc_absolute_time_to_nsec(cc_absolute_time());
}

#endif /* CC_PREDICTION_BREAK_TIMER */


/*
 This file maintains the state of a static and thread safe cryto random number generator.
 The random number generator is reseeded upon fork, so that child and parent random number genetators have different states.
 This file exports the single function ccrng().
*/

// Security/Performance configuration

// To prevent looping forever.
#define RNG_MAX_SEED_RETRY 100

// FIPS 140-2 states that this value must be equal to the block size
// of the underlying source of entropy or the random number generator.
// It is not modifiable. The bigger the better for security.
#define ENTROPY_SOURCE_BLOCK_SIZE 32

// Time elapsed in nanoseconds beyond which a reseed is requested,
// i.e. Maximum time a compromised state leads to predictable output
#define RNG_RESEED_PERIOD_NSEC (5 * CC_NSEC_PER_SEC)

#define RNG_MAGIC_INIT (0xD1D)

// Flip this bit to enable debug
#define RNG_CRYPTO_DEBUG 0
#define rng_debug_cc_printf(x...)

//==============================================================================
//
//          Internal state
//
//==============================================================================

// This value depends on the data structures of supported AES
// implementations and of the DRBG itself. It may require periodic
// tuning.
#define DRBG_STATE_MAX_SIZE ((size_t)1280)
#define RANDOM_BUF_SIZE ((size_t)256)
#define RANDOM_POS_END ((ptrdiff_t)RANDOM_BUF_SIZE)
#define MAX_REQUEST_SIZE ((size_t)4096)

struct ccrng_cryptographic_internal_state {
    uint8_t drbg_state_buf[DRBG_STATE_MAX_SIZE];
    struct {
        uint8_t buf[RANDOM_BUF_SIZE];
        ptrdiff_t pos;
    } random;
    struct {
        int status;
        int complete;
    } init_readonly;
    struct {
        int status; // status of asynchronous prediction break
#if CC_PREDICTION_BREAK_TIMER
        uint64_t timer;
#endif
    } predictionbreak;
    cc_lock_ctx_t lock;
};

// the g_ccrng_cryptographic_state state is static to the library and available in this file only
// this variable is the one that ccrng_cryptographic.c work with
static struct ccrng_cryptographic_internal_state g_ccrng_cryptographic_state = {
    .random.pos = RANDOM_POS_END,
    .init_readonly.status = CCERR_INTERNAL,
    .init_readonly.complete = 0, // init once
    .predictionbreak.status = CCDRBG_STATUS_NEED_RESEED,
};

// This is the variable that we return upon calls to ccrng().
// It contains only a pointer to the generate() function, that users can call.
static CC_READ_ONLY_LATE(struct ccrng_state) g_ccrng_generator;
static CC_READ_ONLY_LATE(struct ccdrbg_info) g_ccrng_drbg_info;
static CC_READ_ONLY_LATE(struct ccdrbg_nistctr_custom) g_ccrng_drbg_custom;
static CC_READ_ONLY_LATE(ccdrbg_df_bc_ctx_t) g_ccrng_drbg_df_ctx;

//==============================================================================
//
//      Prediction Break
//
//==============================================================================

// Before we fork, we acquire the lock and set the prediction-break
// flag to request a reseed. This will propagate down to both parent
// and child processes after the fork.
void ccrng_cryptographic_atfork_prepare(void)
{
#if CC_RNG_MULTITHREAD_USER || CC_RNG_MULTITHREAD_POSIX
    CC_LOCK_LOCK(&g_ccrng_cryptographic_state.lock);

    rng_debug_cc_printf("Fork prepare! Force prediction break on next generate\n");
    if (g_ccrng_cryptographic_state.predictionbreak.status == CCDRBG_STATUS_OK) {
        g_ccrng_cryptographic_state.predictionbreak.status = CCDRBG_STATUS_NEED_RESEED;
    }
#endif
}

// After the fork, the parent needn't do anything other than release
// the lock. Our prediction-break flag is already set, so we'll reseed
// on the next call to the generate() function.
void ccrng_cryptographic_atfork_parent(void)
{
#if CC_RNG_MULTITHREAD_USER || CC_RNG_MULTITHREAD_POSIX
    rng_debug_cc_printf("Fork parent! Prediction break status: %d\n", g_ccrng_cryptographic_state.predictionbreak.status);

    CC_LOCK_UNLOCK(&g_ccrng_cryptographic_state.lock);
#endif
}

// After the fork, the child needs to initialize a new lock. Our
// prediction-break flag is already set, so we'll reseed on the next
// call to the generate function().
void ccrng_cryptographic_atfork_child(void)
{
    rng_debug_cc_printf("Fork child! Prediction break status: %d\n", g_ccrng_cryptographic_state.predictionbreak.status);
    cc_lock_init(&g_ccrng_cryptographic_state.lock, "ccrng_cryptographic");
}

// Get a nonce. NIST recommends using the time it's called
// as a nonce. We use timing information from the OS as additional
// Input. Inside the DRBG, the pointers are all just
// concatenated together, so it doesn't really matter how
// we do it. It's one big nonce.
static uint64_t cc_get_nonce(void)
{
    return cc_absolute_time();
}


// applies continuous random number generator test, per FIPS 140-2 §4.9.2 Conditional Tests
// Generate three blocks of entropy (each block of size ENTROPY_SOURCE_BLOCK_SIZE).
// Throw away the first block(instead of saving the last generated block for the next time that the function is invoked)
// and return the last two blocks.
static int get_two_blocks_entropy(uint8_t *entropy)
{
    int status;
    uint8_t entropy_ref[ENTROPY_SOURCE_BLOCK_SIZE];
    size_t blk_len = sizeof(entropy_ref);

    status = cc_get_entropy(blk_len, entropy_ref);
    cc_require(status == CCERR_OK, errOut);

    // Generate another two blocks of entropy.
    status = cc_get_entropy(2 * blk_len, entropy);
    cc_require(status == CCERR_OK, errOut);

    // Compare each block to the previous block.
    if (0 == cc_cmp_safe(blk_len, entropy, entropy_ref) || (0 == cc_cmp_safe(blk_len, entropy, &entropy[blk_len]))) {
        status = CCERR_OUT_OF_ENTROPY;
    }

errOut:
    return status;
}

// We need to reseed if any of the following is true:
// - The status flag (from the DRBG) requires it
// - The prediction break flag is nonzero, meaning:
//   - We failed a prediction break, or
//   - We just forked
// - The timer requires it
static bool needreseed_locked(int drbg_status)
{
    struct ccrng_cryptographic_internal_state *rng = &g_ccrng_cryptographic_state;

    CC_LOCK_ASSERT(&rng->lock);

    if (drbg_status == CCDRBG_STATUS_NEED_RESEED) {
        return true;
    }

    if (rng->predictionbreak.status != CCDRBG_STATUS_OK) {
        return true;
    }

#if CC_PREDICTION_BREAK_TIMER
    int64_t time_delta = (int64_t)(cc_uptime_nsec() - rng->predictionbreak.timer);
    if (time_delta >= (int64_t)RNG_RESEED_PERIOD_NSEC) {
        return true;
    }
#endif

    return false;
}

// Make a single attempt to reseed.
static int predictionbreak_locked(struct ccrng_cryptographic_internal_state *rng)
{
    uint8_t entropy[2 * ENTROPY_SOURCE_BLOCK_SIZE];
    int status;
    struct ccdrbg_state *drbg_state = (struct ccdrbg_state *)rng->drbg_state_buf;

    CC_LOCK_ASSERT(&rng->lock);

    status = get_two_blocks_entropy(entropy);
    cc_require(status == CCERR_OK, errOut);

    uint64_t nonce = cc_get_nonce();
    status = ccdrbg_reseed(&g_ccrng_drbg_info, drbg_state, sizeof(entropy), entropy, sizeof(nonce), &nonce);
    cc_require(status == CCDRBG_STATUS_OK, errOut);

    rng->random.pos = RANDOM_POS_END;

#if CC_PREDICTION_BREAK_TIMER
    rng->predictionbreak.timer = cc_uptime_nsec();
#endif

 errOut:
    cc_clear(sizeof(entropy), entropy);
    rng->predictionbreak.status = status;

    rng_debug_cc_printf("Prediction break status (%d)\n", rng->predictionbreak.status);

    return status;
}

static int reseed_locked(int drbg_status)
{
    struct ccrng_cryptographic_internal_state *rng = &g_ccrng_cryptographic_state;

    CC_LOCK_ASSERT(&rng->lock);

    // In normal conditions, we will only perform one iteration of
    // this loop. We limit the number of retries to avoid looping
    // forever.
    for (size_t i = 0; i < RNG_MAX_SEED_RETRY; i++) {
        rng_debug_cc_printf("Entering prediction break in generate: gen_status (%d), Pred Break (%d), timer (%lld)\n",
                            drbg_status,
                            rng->predictionbreak.status,
                            time_delta);
        // Get entropy and reseed the drbg
        if (predictionbreak_locked(rng) == CCDRBG_STATUS_OK) {
            return CCDRBG_STATUS_OK;
        }
    }

    // If we failed to reseed, we leave the DRBG status as it is.
    return drbg_status;
}

//==============================================================================
//
//      Generate function
//
//==============================================================================

/*
    g_ccrng_cryptographic_state - overall structure
    g_ccrng_generator - generate function

 */
static int ccrng_cryptographic_generate(struct ccrng_state *input_rng, size_t nbytes, void *bytes)
{
    if (input_rng == NULL) {
        cc_try_abort("NULL ccrng_state");
        return CCERR_CRYPTO_CONFIG;
    }

    if (bytes == NULL) {
        cc_try_abort("NULL output buffer");
        return CCERR_PARAMETER;
    }

    struct ccrng_cryptographic_internal_state *rng = &g_ccrng_cryptographic_state;
    struct ccdrbg_state *drbg_state = (struct ccdrbg_state *)rng->drbg_state_buf;

    // Although it is overloaded to be a general error flag, the
    // primary purpose of this variable is to track the status of the
    // underlying DRBG.
    int drbg_status = CCDRBG_STATUS_OK;

    // This is just a sanity check to make sure corecrypto functions
    // have been used correctly.
    cc_require_action(input_rng->generate == ccrng_cryptographic_generate,
                      errOut,
                      drbg_status = CCERR_PERMS);

    // bytes should be uint8_t*.
    uint8_t *out = bytes;
    bytes = NULL;

    // Two reasons to loop:
    // - to break down generation into MAX_REQUEST_SIZE byte chunks, to allow for contention
    // - to reseed when needed
    while ((nbytes > 0) && ((drbg_status == CCDRBG_STATUS_OK) || (drbg_status == CCDRBG_STATUS_NEED_RESEED))) {

        CC_LOCK_LOCK(&rng->lock);

        // See comments in needreseed_locked()
        if (needreseed_locked(drbg_status)) {
            drbg_status = reseed_locked(drbg_status);
        }

        // If we hit this condition, it means the DRBG seed is
        // end-of-life. Since this PRNG reseeds much more aggressively
        // than the underlying DRBG demands, this implies we have
        // failed countless reseeds. Our only remaining option is to
        // abort.
        if (drbg_status == CCDRBG_STATUS_NEED_RESEED) {
            cc_try_abort("Fatal error with prediction break, cannot reseed");

            drbg_status = rng->predictionbreak.status;
            CC_LOCK_UNLOCK(&rng->lock);
            goto errOut;
        }

        // Otherwise, whether or not we failed a reseed, we generate
        // random output as long as the DRBG is willing. This is safer
        // than not writing values or crashing our clients right away.

        // Catch prediction break failures in debug builds
        cc_assert(rng->predictionbreak.status == CCDRBG_STATUS_OK);

        if (nbytes <= sizeof(rng->random.buf)) {
            uint8_t *p = rng->random.buf + rng->random.pos;
            uint8_t *end = rng->random.buf + RANDOM_POS_END;
            size_t left = (size_t)(end - p);
            size_t take = CC_MIN(nbytes, left);

            cc_memcpy(out, p, take);
            cc_clear(take, p);
            rng->random.pos += take;
            out += take;
            nbytes -= take;

            if (nbytes > 0) {
                rng_debug_cc_printf("Generate %zu bytes (%d)\n", sizeof(rng->random.buf), drbg_status);
                drbg_status = ccdrbg_generate(&g_ccrng_drbg_info, drbg_state, sizeof(rng->random.buf), rng->random.buf, 0, NULL);

                if (drbg_status == CCDRBG_STATUS_OK) {
                    cc_memcpy(out, rng->random.buf, nbytes);
                    cc_clear(nbytes, rng->random.buf);
                    rng->random.pos = (ptrdiff_t)nbytes;
                    nbytes = 0;
                }
            }
        } else {
            size_t req_size = CC_MIN(nbytes, MAX_REQUEST_SIZE);

            rng_debug_cc_printf("Generate %zu bytes (%d)\n", req_size, drbg_status);
            drbg_status = ccdrbg_generate(&g_ccrng_drbg_info, drbg_state, req_size, out, 0, NULL);

            if (drbg_status == CCDRBG_STATUS_OK) {
                // Move forward in output buffer only if the generation was successful
                // That can happen if last ccdrbg_generate requested reseeding for example
                out += req_size;
                nbytes -= req_size;
            }
        }

        CC_LOCK_UNLOCK(&rng->lock);
    }

    // If we exited the previous loop prematurily, something is really wrong.
    // Abort so that we get crash reports.
    if (nbytes > 0 || drbg_status != CCDRBG_STATUS_OK) {
        cc_try_abort("Unexpected error in ccrng_cryptographic generation");
        goto errOut;
    }

errOut:
    return drbg_status;
}

//==============================================================================
//
//      Init
//
//==============================================================================

// One time initialization of the global structure
// To be called within a thread-safe environment.
int ccrng_cryptographic_init_once(void)
{
    int err = CCERR_INTERNAL;
    uint8_t entropy[2 * ENTROPY_SOURCE_BLOCK_SIZE];
    struct ccrng_cryptographic_internal_state *rng = &g_ccrng_cryptographic_state;
    struct ccdrbg_nistctr_custom *drbg_custom = &g_ccrng_drbg_custom;
    struct ccdrbg_info *drbg_info = &g_ccrng_drbg_info;
    ccdrbg_df_bc_ctx_t *df_ctx = &g_ccrng_drbg_df_ctx;

    cc_require_action((rng->init_readonly.complete != RNG_MAGIC_INIT), errOut, err = CCERR_INTERNAL);

    rng_debug_cc_printf("Cryptographic rng initialization\n");

    err = ccdrbg_df_bc_init(df_ctx,
                            ccaes_cbc_encrypt_mode(),
                            32);
    cc_require(err == CCERR_OK, errOut);

    drbg_custom->ctr_info = ccaes_ctr_crypt_mode();
    drbg_custom->keylen = 32;
    drbg_custom->strictFIPS = 1;
    drbg_custom->df_ctx = (ccdrbg_df_ctx_t *)df_ctx;
    ccdrbg_factory_nistctr(drbg_info, drbg_custom);

    if (sizeof(rng->drbg_state_buf) < drbg_info->size) {
#if CORECRYPTO_DEBUG
        cc_printf("Cryptographic DRBG state is too small. Need %d, Got %d,",
                  (int)drbg_info->size,
                  (int)sizeof(rng->drbg_state_buf));
#endif
        cc_try_abort("Insufficient space for DRBG state; review DRBG_STATE_MAX_SIZE");
        err = CCERR_INTERNAL;
        goto errOut;
    }

#if CC_PREDICTION_BREAK_TIMER
    rng->predictionbreak.timer = cc_uptime_nsec();
#endif

    err = get_two_blocks_entropy(entropy);
    cc_require(err == CCERR_OK, errOut);

    uint64_t nonce = cc_get_nonce();
    err = ccdrbg_init(drbg_info, (struct ccdrbg_state *)rng->drbg_state_buf, sizeof(entropy), entropy, sizeof(nonce), &nonce, 0, NULL);
    cc_require(err == CCDRBG_STATUS_OK, errOut);

    err = cc_lock_init(&rng->lock, "ccrng_cryptographic");
    cc_require(err == CCERR_OK, errOut);

#if CC_RNG_MULTITHREAD_POSIX
    err = pthread_atfork(ccrng_cryptographic_atfork_prepare, ccrng_cryptographic_atfork_parent, ccrng_cryptographic_atfork_child);
    cc_require_action(err == 0, errOut, err = CCERR_ATFORK);
#endif

 errOut:
    cc_clear(sizeof(entropy), entropy);

    rng->init_readonly.status = err;
    rng->init_readonly.complete = RNG_MAGIC_INIT;
    rng->predictionbreak.status = err;
    g_ccrng_generator.generate = err == CCERR_OK ? ccrng_cryptographic_generate : NULL;

    return err;
}

#if CC_RNG_MULTITHREAD_USER
static void ccrng_cryptographic_init_once_user(CC_UNUSED void *arg)
{
    ccrng_cryptographic_init_once();
}

#elif CC_RNG_MULTITHREAD_WIN
BOOL CALLBACK ccrng_cryptographic_init_once_win(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *lpContext)
{
    return ccrng_cryptographic_init_once() == CCERR_OK ? TRUE : FALSE;
}
#endif

struct ccrng_state *ccrng(int *error)
{
    CC_INIT_ONCE(ccrng_cryptographic_init_once);

    int status = g_ccrng_cryptographic_state.init_readonly.status;
    if (error != NULL)
        *error = status;

    return status == CCERR_OK ? &g_ccrng_generator : NULL;
}

#endif // !CC_DARWIN || CC_BUILT_FOR_TESTING
