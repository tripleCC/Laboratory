/* Copyright (c) (2012,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <os/bsd.h>

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>

#include <corecrypto/fipspost.h>
#include "fipspost_get_hmac.h"
#include "fipspost_trace.h"
#include "fipspost_trace_priv.h"
#include "module_id.h"

static void usage(const char *argv[]);
static struct mach_header *fipspost_dylib_get_header(void);

static void usage(const char *argv[])
{
    fprintf(stderr,
            "Usage: %s [-dFN] [-m mode] [-t trace.out]\n\n"
            "Execute the FIPS POST tests under a variety of conditions.\n"
            "\t-b,--boot-arg   \tRead the \"fips_mode\" boot arg.\n"
            "\t-d,--disable    \tDisable testing and return success.\n"
            "\t-F,--fail       \tForce tests to fail, but continue testing.\n"
            "\t-N,--nointegrity\tBypass the integrity checks.\n"
            "\t-m,--mode mode  \tSpecify a discrete numerical fips_mode to test.\n"
            "\t-t,--trace file \tLog tracing output, if available, to the filename.\n"
            "\t                \tReturn an error if tracing is disabled.\n"
            "%s\n"
            , argv[0], cc_module_id(cc_module_id_Full));
    exit(-1);
}

static struct mach_header *fipspost_dylib_get_header(void)
{
    // Get information about the dylib
    Dl_info dylib_info;
    memset(&dylib_info, 0, sizeof(dylib_info));
    if (!dladdr(fipspost_post, &dylib_info)) {
        fprintf(stderr, "dladdr failed\n");
        return NULL;
    }

    return (struct mach_header *)dylib_info.dli_fbase;
}

CC_WARN_RESULT
static int fipspost_trace_writer(void *ctx, const uint8_t *buf, size_t len)
{
    FILE *f = (FILE *)ctx;
    size_t ret = fwrite(buf, 1, len, f);
    if (ret != len) {
        return -1;
    }
    return 0;
}

static void
parse_boot_arg(uint32_t *fips_mode)
{
    int64_t n;

    if (os_parse_boot_arg_int("fips_mode", &n)) {
        *fips_mode = (uint32_t)n;
        fprintf(stderr, "A fips_mode boot arg was set: 0x%x\n", *fips_mode);
    }
}

struct fips_config {
    uint32_t fips_mode;
    const char *trace_fname;
};

static void initconfig(struct fips_config *config, int argc, const char **argv)
{
    bool initialized = false;

    // The default configuration is what you'd expect: we run all
    // tests and check all results faithfully.
    cc_clear(sizeof(*config), config);

    /* initialize first from command-line arguments */
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (!strcmp(arg, "-v") || !strcmp(arg, "--verbose")) {
            // This flag is obsolete
        } else if (!strcmp(arg, "-f") || !strcmp(arg, "--force")) {
            // This flag is obsolete
        } else if (!strcmp(arg, "-b") || !strcmp(arg, "--boot-arg")) {
            // In the future, make initialization from boot arg explicit
            parse_boot_arg(&config->fips_mode);
        } else if (!strcmp(arg, "-d") || !strcmp(arg, "--disable")) {
            config->fips_mode |= FIPS_MODE_FLAG_DISABLE;
        } else if (!strcmp(arg, "-F") || !strcmp(arg, "--fail")) {
            config->fips_mode |= FIPS_MODE_FLAG_FORCEFAIL;
        } else if (!strcmp(arg, "-N") || !strcmp(arg, "--nointegrity")) {
            config->fips_mode |= FIPS_MODE_FLAG_NOINTEG;
        } else if (!strcmp(arg, "-m") || !strcmp(arg, "--mode")) {
            config->fips_mode = (uint32_t)strtoll(argv[++i], NULL, 10);
        } else if (!strcmp(arg, "-t") || !strcmp(arg, "--trace")) {
            config->fips_mode |= FIPS_MODE_FLAG_TRACE;
            config->trace_fname = argv[++i];
        } else {
            usage(argv);
        }

        initialized = true;
    }

    /* in the absence of command-line arguments, initialize from boot-args */
    if (!initialized) {
        parse_boot_arg(&config->fips_mode);
    }
}

CC_WARN_RESULT
static int fipspost(struct fips_config *config)
{
    uint32_t fips_mode = config->fips_mode;
    int fipspost_result = CCPOST_GENERIC_FAILURE;
    FILE *fipstrace_out = NULL;
    fipspost_trace_vtable_t fipstrace_vtab = fipspost_trace_vtable;

    fprintf(stderr, "About to call the FIPS_POST function in the corecrypto.dylib\n");

    if (FIPS_MODE_IS_TRACE(fips_mode)) {
        if (fipstrace_vtab == NULL) {
            fprintf(stderr, "Tracing: disabled, not available.\n");
            fprintf(stderr, "Tracing required by test parameters; exiting.\n");
            exit(-1);
        }

        if (config->trace_fname == NULL) {
            fprintf(stderr, "Tracing: disabled, no trace file.\n");
            fprintf(stderr, "Tracing required by test parameters; exiting.\n");
            exit(-1);
        }

        fprintf(stderr, "Tracing: enabled\n");
        fipstrace_out = fopen(config->trace_fname, "w");
        (*fipstrace_vtab->fipspost_trace_start)(fips_mode, fipspost_trace_writer, fipstrace_out);
    } else {
        fprintf(stderr, "Tracing: disabled%s\n", fipstrace_vtab == NULL ? "" : ", but available.");
    }

    fipspost_result = fipspost_post(fips_mode, fipspost_dylib_get_header());

    fprintf(stderr, "Returned from calling the FIPS_POST function in the corecrypto.dylib: result = %s\n", (fipspost_result==0) ? "true" : "false");

    if (fipspost_result != CCERR_OK) {
        fprintf(stderr, "FIPS_POST failed!\n");
    }

    if (fipstrace_out) {
        int ret = (fipstrace_vtab->fipspost_trace_end)((uint32_t)fipspost_result);
        fprintf(stderr, "Tracing returned: %d\n", ret);
        fclose(fipstrace_out);
    }

    return fipspost_result;
}

// The current Assumption is that FIPS will be on all of the time.
// If that assumption changes this code must change
int main(int argc, const char **argv)
{
    int fipspost_result;
    struct fips_config config;

    initconfig(&config, argc, argv);
    fipspost_result = fipspost(&config);

    return fipspost_result;
}
