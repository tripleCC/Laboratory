/* Copyright (c) (2017-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_absolute_time.h"
#include <corecrypto/cc_priv.h>

#include <corecrypto/cc_priv.h>
#include "fipspost.h"
#include "module_id.h"
#include "fipspost_priv.h"

#include "fipspost_get_hmac.h"

#include "fipspost_trace.h"
#include "fipspost_trace_priv.h"

#include "fipspost_post_indicator.h"
#include "fipspost_post_integrity.h"
#include "fipspost_post_hmac.h"
#include "fipspost_post_aes_ecb.h"
#include "fipspost_post_aes_cbc.h"
#include "fipspost_post_rsa_sig.h"
#include "fipspost_post_ecdsa.h"
#include "fipspost_post_drbg_ctr.h"
#include "fipspost_post_ecdh.h"
#include "fipspost_post_aes_ccm.h"
#include "fipspost_post_aes_cmac.h"
#include "fipspost_post_hkdf.h"
#include "fipspost_post_pbkdf.h"
#include "fipspost_post_drbg_hmac.h"
#include "fipspost_post_shake.h"

#if !CC_USE_L4
#include "fipspost_post_ffdh.h"
#include "fipspost_post_kdf_ctr.h"
#include "fipspost_post_kdf_ctr_cmac.h"
#include "fipspost_post_aes_gcm.h"
#include "fipspost_post_aes_xts.h"
#include "fipspost_post_tdes_ecb.h"
#if !CC_KERNEL
#include "fipspost_post_rsa_enc_dec.h"
#endif
#else /* CC_USE_L4 */
#endif

/* Dylib is not transitioned over to 'normal' mechanisms yet. */
#if !CC_USE_L4 && !CC_KERNEL
int fipspost_post_dylib_integrity(int fips_mode);
#endif

/*
 * The pre-calculated SHA256 HMAC gets placed here for integrity testing.  The
 * current value is a random number, but it is replaced by hmacfiletool during
 * the build process.
 */
FIPSPOST_DECLARE_PRECALC_HMAC;

#if CC_FIPSPOST_TRACE
/*
 * Log tracing to the screen if it's enabled but no logger is configured.
 */
CC_WARN_RESULT
static int fipspost_trace_noop_writer(CC_UNUSED void *ctx, CC_UNUSED const uint8_t *buf, CC_UNUSED size_t len)
{
    return 0;
}
#endif

/*
 * Exercise the required post tests.
 */
int fipspost_post(uint32_t fips_mode, struct mach_header *pmach_header)
{
    uint64_t post_time = cc_absolute_time();
    uint64_t start_time;
    uint64_t end_time;
    int result = CCERR_OK;
    int test_counter = 0;

#if CC_FIPSPOST_TRACE
    int local_trace = 0;
    fipspost_trace_vtable_t vtab = fipspost_trace_vtable;
    /* If tracing is enabled but hasn't been configured, log to console. */
    if (vtab->fipspost_trace_start != NULL && FIPS_MODE_IS_TRACE(fips_mode) && !fipspost_trace_is_active()) {
        local_trace = 1;
        (*vtab->fipspost_trace_start)(fips_mode, fipspost_trace_noop_writer, NULL);
    }
#endif

#if CC_KERNEL
    /*
     * The FIPS testing kext will repeatedly call this function, but lacks the
     * mach_header.  Save it so that subsequent calls don't need to do a
     * lookup.
     *
     * The dylib should always supply the header.
     */
    static struct mach_header *corecrypto_kext_pmach_header = NULL;

    if (pmach_header != NULL) {
        corecrypto_kext_pmach_header = pmach_header;
    } else if (corecrypto_kext_pmach_header != NULL) {
        pmach_header = corecrypto_kext_pmach_header;
    } else {
        failf("unable to acquire mach header");
        return CCPOST_GENERIC_FAILURE;
    }
#endif

#define run_post(post_test, ...)                                        \
    do {                                                                \
        test_counter--;                                                 \
        FIPSPOST_TRACE_MESSAGE(FIPSPOST_TRACE_TEST_STR);                \
        FIPSPOST_TRACE_MESSAGE(#post_test);                             \
        start_time = cc_absolute_time();                                \
        int rc = post_test(fips_mode, ##__VA_ARGS__);                   \
        if (rc != CCERR_OK) {                                           \
            failf(#post_test ": %d", rc);                               \
            if (result == CCERR_OK) {                                   \
                result = test_counter * 1000 + rc;                      \
            }                                                           \
        } else {                                                        \
            end_time = cc_absolute_time();                              \
            debugf("PASSED: (%u ms) - " #post_test, (uint32_t)cc_absolute_time_to_msec((double)(end_time - start_time))); \
        }                                                               \
    } while (0);

    FIPSPOST_TRACE_EVENT;

    /*
     * Identify the Cryptography Module by logging the Module ID
     */
    debugf("[FIPSPOST][Module-ID] %s", cc_module_id(cc_module_id_Full));

    if (FIPS_MODE_IS_DISABLE(fips_mode)) {
        return CCERR_OK;
    }

    /* FIPS 140-3 */
    /* Integrity test must be performed after KAT for integrity mechanism  */
    run_post(fipspost_post_hmac);

    /* Module Integrity test */
    if (!FIPS_MODE_IS_NOINTEG(fips_mode)) {
        run_post(fipspost_post_integrity, pmach_header);
    }

    /* Run each supported POST test. */
    run_post(fipspost_post_indicator);
    run_post(fipspost_post_aes_ecb);
    run_post(fipspost_post_aes_cbc);
    run_post(fipspost_post_rsa_sig);
    run_post(fipspost_post_ecdsa);
    run_post(fipspost_post_ecdh);
    run_post(fipspost_post_aes_ccm);
    run_post(fipspost_post_aes_cmac);
    run_post(fipspost_post_hkdf);
    run_post(fipspost_post_pbkdf);
    run_post(fipspost_post_drbg_hmac);
#if !CC_USE_L4
    run_post(fipspost_post_kdf_ctr);
    run_post(fipspost_post_kdf_ctr_cmac);
    run_post(fipspost_post_aes_gcm);
    run_post(fipspost_post_aes_xts);
    run_post(fipspost_post_tdes_ecb);
    run_post(fipspost_post_drbg_ctr);
#if !CC_KERNEL
    run_post(fipspost_post_ffdh);
    run_post(fipspost_post_rsa_enc_dec);
    run_post(fipspost_post_shake);
#endif
#else
#endif

    end_time = cc_absolute_time();

    if (result == CCERR_OK) {
        debugf("all tests PASSED (%u ms)", (uint32_t)cc_absolute_time_to_msec((double)(end_time - post_time)));
    }

#if CC_FIPSPOST_TRACE
    if (local_trace) {
        (*vtab->fipspost_trace_end)((uint32_t)result);
    }
#endif

    /* Consume failures and return success when NOPANIC is set. */
    return FIPS_MODE_IS_NOPANIC(fips_mode) ? CCERR_OK : result;
}
