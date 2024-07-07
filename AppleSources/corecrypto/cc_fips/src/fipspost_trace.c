/* Copyright (c) (2017-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"
#include <corecrypto/ccsha2.h>

/* CC_KERNEL requires a corecrypto include to use. */
#if CC_KERNEL
#include <libkern/libkern.h>
#endif

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_get_hmac.h"
#include "fipspost_trace.h"
#include "fipspost_trace_priv.h"

#if CC_FIPSPOST_TRACE

static struct fipspost_trace_vtable _fipspost_trace_vtable = {
    .fipspost_trace_start = &fipspost_trace_start,
    .fipspost_trace_end = &fipspost_trace_end,
    .fipspost_trace_clear = &fipspost_trace_clear,
};

const void *fipspost_trace_vtable = &_fipspost_trace_vtable;

/* Expose the precalculated HMAC for output in the results buffer. */
FIPSPOST_EXTERN_PRECALC_HMAC;

/*
 * Record the specified mode and the current test.
 */
static uint32_t fipspost_trace_fips_mode = 0;

/*
 * Save a pointer to the caller-supplied writer for use when serializing
 * output, and a supplied ctx token used by the writer.
 */
static fipspost_trace_writer_t fipspost_trace_writer;
static void *fipspost_trace_writer_ctx;

/*
 * A couple of utility macro's for writing 'plain old data' types (really
 * anything with a valid 'sizeof()' operation) and buffers.
 */
#define TRACE_POD(pod)                                                  \
    if ((*fipspost_trace_writer)(fipspost_trace_writer_ctx,             \
                (const uint8_t *)&pod, sizeof(pod))) {                  \
        goto err;                                                       \
    }

#define TRACE_BUF(buf, len)                                             \
    if ((*fipspost_trace_writer)(fipspost_trace_writer_ctx,             \
                (const uint8_t *)buf, len)) {                           \
        goto err;                                                       \
    }

/*
 * There are many, many faster ways of doing this.  But there's not many
 * simpler ways.
 *
 * For each call, look in a list for the matching string.  The current length
 * of the formal set is ~32, which would matter if this code was remotely
 * performance sensitive.  Since it's not, a O(n) search is fine.
 *
 * More sophisticated versions of this might use hash map, for example.
 */
static const char *fipspost_trace_hooks[FIPSPOST_TRACE_MAX_HOOKS];
static fipspost_trace_id_t fipspost_trace_hook_cnt = 0;

/* Local utility functions. */
static fipspost_trace_id_t fipspost_trace_hook_idx(const char *fname);

/*
 * Initialize the environment and record the preamble.  The 'ctx' is passed in
 * to the 'trace_writer' to be used as context.
 *
 * Return non-zero when tracing is not enabled.
 */
int fipspost_trace_start(uint32_t fips_mode, fipspost_trace_writer_t trace_writer, void *ctx)
{
    struct fipspost_trace_hdr hdr;

    fipspost_trace_clear();

    fipspost_trace_fips_mode = fips_mode;
    fipspost_trace_writer = trace_writer;
    fipspost_trace_writer_ctx = ctx;

    if (!fipspost_trace_is_active()) {
        goto err;
    }

    /*
     * Write out a header containing some basic pieces of information to  help
     * avoid 'sea of files all alike' syndrome.
     *
     * Note: this must be changed in sync with the userland tool for reading
     * the tracing buffer.
     */
    hdr.magic = FIPSPOST_TRACE_MAGIC;
    hdr.version = FIPSPOST_TRACE_PROTOCOL_VERSION;
    hdr.fips_mode = fipspost_trace_fips_mode;
    memcpy(hdr.integ_hmac, fipspost_precalc_hmac, FIPSPOST_PRECALC_HMAC_SIZE);
    hdr.system_flags = 0;
#if TARGET_OS_IPHONE
    hdr.system_flags |= FIPSPOST_TRACE_SYSFLAG_IPHONE;
#endif
#if TARGET_OS_OSX
    hdr.system_flags |= FIPSPOST_TRACE_SYSFLAG_OSX;
#endif
#if CC_USE_L4
    hdr.system_flags |= FIPSPOST_TRACE_SYSFLAG_L4;
#endif
#if CC_KERNEL
    hdr.system_flags |= FIPSPOST_TRACE_SYSFLAG_KERNEL;
#endif
    TRACE_BUF(&hdr, sizeof(hdr));

    debugf("TRACE: magic: %x", hdr.magic);
    debugf("TRACE: version: %x", hdr.version);
    debugf("TRACE: fips_mode: %x", hdr.fips_mode);
    bufferf(hdr.integ_hmac, FIPSPOST_PRECALC_HMAC_SIZE, "TRACE: integ_mac");
    debugf("TRACE: system_flags: %llx", hdr.system_flags);

    /* Add a '-' at the front to reserve '0'. */
    fipspost_trace_hook_idx("-");
    /* Use '?' to indicate the end of the test sets. */
    fipspost_trace_hook_idx(FIPSPOST_TRACE_TEST_STR);

    return 0;

err:
    /* Cleanly reset to a non-impactful state. */
    fipspost_trace_clear();

    return -1;
}

/*
 * Returns non-zero if tracing has been requested for this POST run.
 */
int fipspost_trace_is_active(void)
{
    return FIPS_MODE_IS_TRACE(fipspost_trace_fips_mode) && fipspost_trace_writer != NULL;
}

/*
 * Take the unique string supplied by the caller and record in the trace
 * buffer that the event was hit.  Expects that the string is a global
 * constant, and only takes a reference.
 *
 * On error, reset the environment, discard the tracing data, and stop tracing.
 */
void fipspost_trace_call(const char *test_name)
{
    fipspost_trace_id_t id;

    if (!fipspost_trace_is_active()) {
        goto err;
    }

    debugf("TRACE: event: %s", test_name);
    id = fipspost_trace_hook_idx(test_name);
    if (id < FIPSPOST_TRACE_MAX_HOOKS) {
        TRACE_POD(id);
        return;
    }

err:
    fipspost_trace_clear();
}

/*
 * Finish the tracing process by writing out the closing string buffers.
 *
 * Returns 0 if successful, or -1 if unsuccessful and the output should be
 * discarded.
 */
int fipspost_trace_end(uint32_t result)
{
    size_t len = 0;
    fipspost_trace_id_t n;

    /*
     * Must be enough space for 0xDEADBEEF + terminating null.
     */
    char status_str[FIPSPOST_TRACE_FAILURE_STR_LEN + 10 + 1];
    const size_t status_len = sizeof(status_str);

    if (!fipspost_trace_is_active()) {
        goto err;
    }

    debugf("TRACE: end: %d", result);

    /* Add one final event that encodes the exit code from the POST. */
    if (result == 0) {
        fipspost_trace_call(FIPSPOST_TRACE_SUCCESS_STR);
    } else {
        snprintf(status_str, status_len, FIPSPOST_TRACE_FAILURE_STR "%08X", result);
        fipspost_trace_call(status_str);
    }

    /*
     * Without this the analyzer complains, but I am not smart enough to
     * understand why.
     */
    if (!fipspost_trace_is_active()) {
        goto err;
    }

    n = FIPSPOST_TRACE_TABLE_ID;
    TRACE_POD(n);                           /* Indicate the string table is coming next. */
    TRACE_POD(fipspost_trace_hook_cnt);     /* Record the number of table entries. */

    /* Write out the string table in pascal string format. */
    for (fipspost_trace_id_t i = 0; i < fipspost_trace_hook_cnt; i++) {
        len = strlen(fipspost_trace_hooks[i]) + 1;
        if (len > FIPSPOST_TRACE_MAX_EVENT_LEN) {
            goto err;
        }
        n = (fipspost_trace_id_t)len;

        /* Write the pascal string out. */
        TRACE_POD(n);
        TRACE_BUF(fipspost_trace_hooks[i], len);
    }

    fipspost_trace_clear();
    return 0;

err:
    fipspost_trace_clear();
    return -1;
}

/*
 * Find the supplied string in the lookup table.  The table as a whole
 * gets serialized during the output phase.
 *
 * This is also used to register individual tests and provide an
 * id-to-string mapping for them.
 */
static fipspost_trace_id_t fipspost_trace_hook_idx(const char *fname)
{
    if (fname == NULL) {
        return FIPSPOST_TRACE_MAX_HOOKS;
    }

    for (int i = 0; i < fipspost_trace_hook_cnt; i++) {
        if (fipspost_trace_hooks[i] == NULL) {
            /* Shouldn't be any NULLs; somethings gone wrong. */
            return FIPSPOST_TRACE_MAX_HOOKS;
        }

        /*
         * Because the strings are required to be constant, we can cheat
         * and compare the address instead of comparing the entire string.
         */
        if (fname == fipspost_trace_hooks[i]) {
            return (fipspost_trace_id_t)i;
        }
    }
    if (fipspost_trace_hook_cnt == FIPSPOST_TRACE_MAX_HOOKS) {
        return FIPSPOST_TRACE_MAX_HOOKS;
    }

    fipspost_trace_hooks[fipspost_trace_hook_cnt] = fname;
    return fipspost_trace_hook_cnt++;
}

/*
 * General utility function to reset the context back to empty.
 */
void fipspost_trace_clear(void)
{
    fipspost_trace_fips_mode = 0;
    fipspost_trace_writer = NULL;
    fipspost_trace_hook_cnt = 0;
}

#else

/*
 * Tracing is disabled in this binary.
 */
const void *fipspost_trace_vtable = NULL;

#endif
