/* Copyright (c) (2017-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_FIPSPOST_TRACE_PRIV_H_
#define _CORECRYPTO_FIPSPOST_TRACE_PRIV_H_

/*
 * FIPSPOST_TRACE writes, using a supplied fipspost_trace_writer function, a
 * buffer in three steps.  The first is the fipspost_trace_hdr, which includes
 * contextual information such as the file version, the fips_mode, the hmac
 * that's associated with this file, and any compilation flags as are
 * considered important.
 *
 * Subsequently are a long stream of fipspost_trace_id_t elements, each of
 * which represents a single trace event.
 *
 * Finally, a FIPSPOST_TRACE_TABLE_ID event is written, and the string table
 * that was constructued is dumped in pascal format (length+string).
 * Currently, all of the strings are NULL terminated.
 */

/* Current version produced by this file. */
#define FIPSPOST_TRACE_PROTOCOL_VERSION 1

/* Magic to start each fipspost trace file with. */
#define FIPSPOST_TRACE_MAGIC            0x66707472

/* Some flags to set to help further identify the system. */
#define FIPSPOST_TRACE_SYSFLAG_IPHONE   (1 << 0)
#define FIPSPOST_TRACE_SYSFLAG_OSX      (1 << 1)
#define FIPSPOST_TRACE_SYSFLAG_L4       (1 << 2)
#define FIPSPOST_TRACE_SYSFLAG_KERNEL   (1 << 3)

/* Header prepended onto each file. */
struct fipspost_trace_hdr {
    uint32_t magic;
    uint32_t version;
    uint32_t fips_mode;
    uint8_t  integ_hmac[FIPSPOST_PRECALC_HMAC_SIZE];
    uint64_t system_flags;
} __attribute__((packed));

/*
 * After the header are the trace events, each of which is a
 * fipspost_trace_id_t actings as an index to a string table which is sent
 * after the events.
 *
 * An indiviual trace event is an index into the string table that's persisted
 * until the fipspost_trace_end call.
 */
typedef uint8_t fipspost_trace_id_t;

/*
 * Supplied writer function that returns 0 on success.
 *
 * Failure results in fipspost_trace_clear being called (disabling further
 * tracing). No expected action taken by the caller.
 */
typedef int (*fipspost_trace_writer_t)(void *ctx, const uint8_t *buf, size_t len);

/*
 * Maximum length of an event string.
 */
#define FIPSPOST_TRACE_MAX_EVENT_LEN 0xFF

/*
 * Maximum number of unique functions that can be recorded, with space for
 * additional flags before the maxint of fipspost_trace_id_t.
 */
#define FIPSPOST_TRACE_MAX_HOOKS    0xF0    // uint8_t size limitation

#define FIPSPOST_TRACE_SUCCESS_STR "-POST_SUCCESS"
#define FIPSPOST_TRACE_FAILURE_STR "-POST_FAILURE: 0x"
#define FIPSPOST_TRACE_FAILURE_STR_LEN 17

/*
 * Reserve a value for dumping the trace_hooks table after the samples.
 */
#define FIPSPOST_TRACE_TABLE_ID     (fipspost_trace_id_t)(FIPSPOST_TRACE_MAX_HOOKS + 1)

/*
 * Maximum number of trace events to record.
 */
#define FIPSPOST_TRACE_MAX_EVENTS   65535

/*
 * Maximum size of the result buffer:
 *   struct fipspost_trace_hdr
 *   FIPSPOST_TRACE_MAX_EVENTS * fipspost_trace_id_t
 *   FIPSPOST_TRACE_MAX_HOOKS * (FIPSPOST_TRACE_MAX_EVENT_LEN + 1 (for the length))
 */
#define FIPSPOST_TRACE_MAX_BUFFER                                       \
    (sizeof(struct fipspost_trace_hdr) +                                \
    (FIPSPOST_TRACE_MAX_EVENTS * sizeof(fipspost_trace_id_t)) +         \
    (FIPSPOST_TRACE_MAX_HOOKS * (FIPSPOST_TRACE_MAX_EVENT_LEN + 1)))

/*
 * Certain users may desire the types and constants for parsing, but not
 * require the symbols to execute tracing events.
 */

#if CC_FIPSPOST_TRACE
/* Start the tracing. */
int fipspost_trace_start(uint32_t fips_mode,
        fipspost_trace_writer_t trace_writer, void *ctx);

/*
 * Finish the tracing; returns 0 if successful, or -1 if no valid output was
 * collected.
 */
int fipspost_trace_end(uint32_t result);

/* Reset back to defaults. */
void fipspost_trace_clear(void);
#endif

/*
 * Provide a lookup table to allow an app or kext to link against both
 * a dylib/kernel providing POST trace capabilities and a version that does
 * not.
 */
struct fipspost_trace_vtable {
    int (*fipspost_trace_start)(uint32_t, fipspost_trace_writer_t, void *);
    int (*fipspost_trace_end)(uint32_t result);
    void (*fipspost_trace_clear)(void);
};

typedef const struct fipspost_trace_vtable *fipspost_trace_vtable_t;

#endif
