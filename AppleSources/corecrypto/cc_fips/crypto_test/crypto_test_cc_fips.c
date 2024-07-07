/* Copyright (c) (2017,2019,2021) Apple Inc. All rights reserved.
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
#include "testbyteBuffer.h"
#include "cc_runtime_config.h"

#include "fipspost.h"
#include "fipspost_trace.h"
#include "fipspost_get_hmac.h"

#include "fipspost_trace_priv.h"

FIPSPOST_DECLARE_PRECALC_HMAC;

/*
 * Need a whole bunch of constant string for testing purposes.
 */
#define CCFIPS_TRACE_TEST_STRING_LEN 10
static char ccfips_trace_test_strings[FIPSPOST_TRACE_MAX_HOOKS + 1][CCFIPS_TRACE_TEST_STRING_LEN];

int ccfips_trace_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv);

/*
 * Context passed to the writer on each function call.
 */
struct ccfips_trace_test_write_ctx {
    uint8_t *buf;
    size_t len;
    size_t max_len;
};

/*
 * Convienence structure to parse the results of the accumulated buffer into
 * for easy testing.
 */
struct ccfips_trace_test_parse_ctx {
    struct fipspost_trace_hdr *hdr;
    const char *hooks[FIPSPOST_TRACE_MAX_HOOKS];
    fipspost_trace_id_t trace[16*1024];
    size_t trace_len;
};

/*
 * Test writer that records each value into the buffer supplied via the context
 * parameter.
 */
CC_WARN_RESULT
static int ccfips_trace_test_writer(void *c, const uint8_t *buf, size_t len)
{
    struct ccfips_trace_test_write_ctx *ctx = (struct ccfips_trace_test_write_ctx *)c;

    /* Test against the arbitrary maximum specified in the ccfips_trace_test_write_ctx. */
    if (ctx->max_len > 0 && (ctx->len + len) >= ctx->max_len) {
        return -1;
    }

    memcpy(ctx->buf + ctx->len, buf, len);
    ctx->len += len;

    return 0;
}

/*
 * Parse the supplied buffer into the ccfips_trace_test_parse_ctx.
 */
static void ccfips_trace_test_parse(struct ccfips_trace_test_parse_ctx *ctx, uint8_t *buf, size_t len)
{
    /* The header is the fist value in the buffer. */
    ctx->hdr = (struct fipspost_trace_hdr *)buf;
    fipspost_trace_id_t nstr;
    fipspost_trace_id_t slen;
    fipspost_trace_id_t *wlk = (fipspost_trace_id_t *)(ctx->hdr + 1);

    /* Walk through the samples until the string table starts. */
    while (*wlk != FIPSPOST_TRACE_TABLE_ID) {
        wlk++;
        isnt(wlk, (fipspost_trace_id_t *)(buf + len), "off the end");
    }

    /* Copy into the ctx->trace buffer for later analysis. */
    ctx->trace_len = (size_t)(wlk - (fipspost_trace_id_t *)(ctx->hdr + 1));
    memcpy(ctx->trace, ctx->hdr + 1, ctx->trace_len);
    wlk++;

    /*
     * Populate the ctx->hooks table with pointers into the
     * already-NULL-terminated strings in the buffer.
     */
    nstr = *wlk++;
    for (int i = 0; i < nstr; i++) {
        slen = *wlk;
        wlk++;
        ctx->hooks[i] = (const char *)wlk;
        wlk += slen;
    }

    /* Verify that there wasn't any data lingering at the end. */
    is(wlk, (fipspost_trace_id_t *)(buf + len), "whole buffer consumed");
}

/*
 * Validate the tracing functionality works as expected and produces a cleanly
 * structured buffer.
 */
int ccfips_trace_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    size_t old_len;
    uint8_t buf[16*1024];
    struct ccfips_trace_test_write_ctx ctx = {.buf = buf, .len = 0 };
    struct ccfips_trace_test_parse_ctx parse;
    size_t two_event_max_len;
    memset(&parse, 0, sizeof(struct ccfips_trace_test_parse_ctx));

    /* Magic number of 'is', 'isnt', etc related statements here. */
    plan_tests(275);

    /* Initialize sample strings */
    for (int i = 0; i < FIPSPOST_TRACE_MAX_HOOKS; i++) {
        snprintf(ccfips_trace_test_strings[i], CCFIPS_TRACE_TEST_STRING_LEN, "%d", i);
    }

    /* Test with tracing disabled. */
    fipspost_trace_start(0, &ccfips_trace_test_writer, &ctx);
    FIPSPOST_TRACE_EVENT;
    is (-1, fipspost_trace_end(0), "nothing written");
    is(ctx.len, (size_t)0, "no-op test");

    /* Test with tracing enabled. */
    fipspost_trace_start(FIPS_MODE_FLAG_TRACE, &ccfips_trace_test_writer, &ctx);
    old_len = ctx.len;

    /*
     * Trace four events, one for the current function, and then 'h', 'w', and
     * 'h' again.
     */
    FIPSPOST_TRACE_EVENT;
    is(ctx.len, old_len + 1, "single byte written");
    old_len = ctx.len;
    fipspost_trace_call("h");
    is(ctx.len, old_len + 1, "single byte written");
    old_len = ctx.len;
    two_event_max_len = ctx.len + 1;
    fipspost_trace_call("w");
    is(ctx.len, old_len + 1, "single byte written");
    old_len = ctx.len;
    fipspost_trace_call("h");
    is(ctx.len, old_len + 1, "single byte written");
    is(0, fipspost_trace_end(0), "successful write");

    ccfips_trace_test_parse(&parse, ctx.buf, ctx.len);

    /*
     * A bit of magic numbers here; the first two slots in the string table are
     * reserved for internal usage by fipspost_trace_start(), so the following
     * values of 2, 3, 4 apply to the current function, 'h', and 'w'
     * respectively.
     */
    is(parse.hooks[2][0], 'c', "");
    is(parse.hooks[3][0], 'h', "");
    is(parse.hooks[4][0], 'w', "");
    is(parse.hooks[5][6], 'S', "");     /* -POST_SUCCESS */

    /* Make sure that the resulting trace is as expected. */
    is(parse.trace_len, (size_t)5, "right number of traces");
    is(parse.trace[0], 2, "valid trace");
    is(parse.trace[1], 3, "valid trace");
    is(parse.trace[2], 4, "valid trace");
    is(parse.trace[3], 3, "valid trace");
    is(parse.trace[4], 5, "valid trace");

    /*
     * Trace four events, but only allow space for three.  Verify that
     * subsequent calls to 'fipspost_trace_end()' return non-zero.
     */
    /* Test with tracing enabled. */
    ctx.len = 0;
    ctx.max_len = two_event_max_len;
    fipspost_trace_start(FIPS_MODE_FLAG_TRACE, &ccfips_trace_test_writer, &ctx);
    ok(fipspost_trace_is_active(), "active");
    fipspost_trace_call("1");
    ok(fipspost_trace_is_active(), "active");
    fipspost_trace_call("2");
    ok(fipspost_trace_is_active(), "active");
    is(ctx.len, ctx.max_len - 1, "unable to fit");
    fipspost_trace_call("3");       // Attempt to write data that's rejected.
    is(ctx.len, ctx.max_len - 1, "len unchanged");
    ok(!fipspost_trace_is_active(), "not active");
    is(-1, fipspost_trace_end(0), "unsuccessful write");
    /* A normal caller would discard the tracing buffer at this point. */

    /*
     * Trace too many events, exceeding the number of FIPSPOST_TRACE_MAX_HOOKS.
     */
    ctx.len = 0;
    ctx.max_len = 0;
    fipspost_trace_start(FIPS_MODE_FLAG_TRACE, &ccfips_trace_test_writer, &ctx);
    ok(fipspost_trace_is_active(), "active");
    /* Starts at '2' because that's how many 'fipspost_trace_start' adds. */
    for (int i = 2; i < FIPSPOST_TRACE_MAX_HOOKS; i++) {
        /*
         * Have to use the static buffer because the string table only stores
         * pointers, it doesn't copy the values internally.
         */
        fipspost_trace_call(ccfips_trace_test_strings[i]);
        ok(fipspost_trace_is_active(), "active: %d", i);
    }
    fipspost_trace_call(ccfips_trace_test_strings[FIPSPOST_TRACE_MAX_HOOKS]);
    ok(!fipspost_trace_is_active(), "not active");
    is(-1, fipspost_trace_end(0), "unsuccessful write");

    /*
     * Trace an event name that is longer than FIPSPOST_TRACE_MAX_EVENT_LEN.
     */
    ctx.len = 0;
    ctx.max_len = 0;
    fipspost_trace_start(FIPS_MODE_FLAG_TRACE, &ccfips_trace_test_writer, &ctx);
    ok(fipspost_trace_is_active(), "active");

    /* Create a large buffer with limited scope. */
    {
        char long_buf[FIPSPOST_TRACE_MAX_EVENT_LEN + 2];
        memset(long_buf, ' ', FIPSPOST_TRACE_MAX_EVENT_LEN + 2);
        long_buf[FIPSPOST_TRACE_MAX_EVENT_LEN + 1] = 0;
        is((unsigned long)FIPSPOST_TRACE_MAX_EVENT_LEN + 1, strlen(long_buf), "long buffer");
        fipspost_trace_call(long_buf);
        /*
         * It doesn't actually fail until the fipspost_trace_end call attempts
         * to serialize the string table.
         */
        ok(fipspost_trace_is_active(), "active");
        is(-1, fipspost_trace_end(0), "unsuccessful write");
    }

    return 1;
}

