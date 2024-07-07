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

#include <setjmp.h>
#include <unistd.h>

#include "testmore.h"

#include "cc_internal.h"
#include <corecrypto/cckprng.h>
#include <corecrypto/ccrng_schedule.h>
#include "cckprng_internal.h"
#include <corecrypto/ccaes.h>
#include "testbyteBuffer.h"
#include "cc_priv.h"

#if CC_LINUX
#define CC_PRNG_SEEDTESTS 0
#else
#define CC_PRNG_SEEDTESTS 1
#endif

#include "ccshadow.h"

#if CC_PRNG_SEEDTESTS

struct file {
    const char *path;
    int fd;
    uint8_t buf[256];
    size_t len;
    size_t pos;
};

static const int seedfd = 3;
static const int randomfd = 4;

static struct file filetab[] = {
    { .path = CCKPRNG_SEEDFILE, .fd = seedfd },
    { .path = CCKPRNG_RANDOMDEV, .fd = randomfd },
};

static struct file *seedfile = &filetab[0];
static struct file *randomdev = &filetab[1];

static struct file *file_lookup_path(const char *path)
{
    int i;

    for (i = 0; i < 2; i += 1) {
        if (strcmp(path, filetab[i].path) == 0) {
            return &filetab[i];
        }
    }

    return NULL;
}

static struct file *file_lookup_fd(int fd)
{
    int i;

    for (i = 0; i < 2; i += 1) {
        if (fd == filetab[i].fd) {
            return &filetab[i];
        }
    }

    return NULL;
}

static void file_erase(struct file *f)
{
    cc_clear(sizeof(f->buf), f->buf);
    f->pos = 0;
    f->len = 0;
}

static void file_setup(struct file *f, const void *buf, size_t buflen)
{
    memcpy(f->buf, buf, buflen);
    f->pos = 0;
    f->len = buflen;
}

static int open_lookup(const char *path, int oflag, mode_t mode)
{
    (void)oflag;
    (void)mode;

    return file_lookup_path(path)->fd;
}

static int open_seedfile_fail(const char *path, int oflag, mode_t mode)
{
    if (strcmp(path, CCKPRNG_SEEDFILE) == 0) {
        return -1;
    }

    return open_lookup(path, oflag, mode);
}

static int open_randomdev_fail(const char *path, int oflag, mode_t mode)
{
    if (strcmp(path, CCKPRNG_RANDOMDEV) == 0) {
        return -1;
    }

    return open_lookup(path, oflag, mode);
}

static int close_nop(int fd)
{
    (void)fd;

    return 0;
}

static ssize_t read_fail(int fd, void *buf, size_t nbytes)
{
    (void)fd;
    (void)buf;
    (void)nbytes;

    return -1;
}

static ssize_t write_fail(int fd, const void *buf, size_t nbytes)
{
    (void)fd;
    (void)buf;
    (void)nbytes;

    return -1;
}

// The size of this buffer is arbitrary, but it is meant to be larger
// than and indivisible by CCKPRNG_SEEDSIZE
static const uint8_t seed[173] = {
    0x14, 0xfb, 0xb6, 0xc1, 0xd3, 0x6d, 0x96, 0x93, 0x99, 0x04, 0x01, 0x41, 0xc9, 0xbe, 0x18, 0xe1, 0x65, 0x9f, 0x4c, 0xc5,
    0x93, 0x00, 0x83, 0xb6, 0x7e, 0x02, 0xf0, 0x50, 0xcb, 0xf1, 0xdc, 0x76, 0xce, 0xa8, 0x44, 0x1c, 0x36, 0x1f, 0xa6, 0x8a,
    0x17, 0x13, 0x3d, 0x5a, 0x94, 0x7d, 0xd1, 0x04, 0x8e, 0xd9, 0xef, 0xc3, 0x95, 0xa0, 0x40, 0x8a, 0xe2, 0xb2, 0xe5, 0x7c,
    0x17, 0x20, 0xa8, 0xbf, 0xd0, 0xc9, 0x8d, 0xb1, 0x18, 0x10, 0x5f, 0x04, 0xac, 0xda, 0xb9, 0x85, 0xc7, 0x9a, 0xfc, 0x40,
    0x9b, 0xf3, 0x64, 0x33, 0xa0, 0x13, 0x3c, 0x1c, 0x29, 0x6e, 0x87, 0xb9, 0x4c, 0xa1, 0xd7, 0xb5, 0x77, 0x83, 0xcb, 0x54,
    0x39, 0x0e, 0x5f, 0x91, 0x5e, 0x1b, 0xd3, 0x74, 0xc7, 0x5a, 0x92, 0x73, 0x84, 0x7f, 0xe2, 0x2c, 0xf3, 0xfe, 0x26, 0xf5,
    0x8d, 0xac, 0x89, 0xff, 0x01, 0x0f, 0x8e, 0x48, 0x20, 0xef, 0x05, 0xe4, 0x45, 0x27, 0x60, 0x77, 0xa7, 0x19, 0xcc, 0x0f,
    0xc1, 0x35, 0xe9, 0xbd, 0x9f, 0x75, 0xb1, 0x2f, 0x4e, 0xba, 0xc2, 0x24, 0xc8, 0x7b, 0x09, 0x3f, 0xd3, 0x3b, 0x2c, 0x67,
    0x52, 0x80, 0xc8, 0x07, 0x62, 0x01, 0x75, 0xdd, 0x70, 0x61, 0xd6, 0xae, 0x1a,
};

static ssize_t read_manybytes(int fd, void *buf, size_t nbytes)
{
    struct file *f = file_lookup_fd(fd);

    nbytes = CC_MIN(f->len - f->pos, nbytes);
    memcpy(buf, &f->buf[f->pos], nbytes);
    f->pos += nbytes;

    return (ssize_t)nbytes;
}

static ssize_t read_onebyte(int fd, void *buf, size_t nbytes)
{
    (void)nbytes;

    return read_manybytes(fd, buf, 1);
}

static ssize_t write_manybytes(int fd, const void *buf, size_t nbytes)
{
    struct file *f = file_lookup_fd(fd);

    // This should never happen
    if (nbytes > sizeof(f->buf) - f->pos) {
        return -1;
    }

    memcpy(&f->buf[f->pos], buf, nbytes);
    f->pos += nbytes;
    f->len += nbytes;

    return (ssize_t)nbytes;
}

static ssize_t write_onebyte(int fd, const void *buf, size_t nbytes)
{
    (void)nbytes;

    return write_manybytes(fd, buf, 1);
}

static int cckprng_test_loadseed(void)
{
    file_setup(seedfile, seed, sizeof(seed));
    file_erase(randomdev);

    close_mock = close_nop;

    open_mock = open_seedfile_fail;
    is(cckprng_loadseed(), CCKPRNG_SEEDFILE_OPEN, "cckprng_loadseed open seedfile");
    seedfile->pos = 0;

    open_mock = open_randomdev_fail;
    is(cckprng_loadseed(), CCKPRNG_RANDOMDEV_OPEN, "cckprng_loadseed open random device");
    seedfile->pos = 0;

    open_mock = open_lookup;
    read_mock = read_fail;
    is(cckprng_loadseed(), CCKPRNG_SEEDFILE_READ, "cckprng_loadseed read seedfile");
    seedfile->pos = 0;

    read_mock = read_manybytes;
    write_mock = write_fail;
    is(cckprng_loadseed(), CCKPRNG_RANDOMDEV_WRITE, "cckprng_loadseed write random device");
    seedfile->pos = 0;

    open_mock = open_lookup;
    read_mock = read_manybytes;
    write_mock = write_manybytes;
    file_erase(randomdev);
    seedfile->pos = 0;
    is(cckprng_loadseed(), CCERR_OK, "cckprng_loadseed ok (many-byte read, many-byte write)");
    is(randomdev->len, seedfile->len, "cckprng_loadseed size (many-byte read, many-byte write)");
    ok_memcmp(seedfile->buf, randomdev->buf, seedfile->len, "cckprng_loadseed match (many-byte read, many-byte write)");

    read_mock = read_onebyte;
    write_mock = write_manybytes;
    file_erase(randomdev);
    seedfile->pos = 0;
    is(cckprng_loadseed(), CCERR_OK, "cckprng_loadseed ok (one-byte read, many-byte write)");
    is(randomdev->len, seedfile->len, "cckprng_loadseed size (one-byte read, many-byte write)");
    ok_memcmp(seedfile->buf, randomdev->buf, seedfile->len, "cckprng_loadseed match (one-byte read, many-byte write)");

    read_mock = read_manybytes;
    write_mock = write_onebyte;
    file_erase(randomdev);
    seedfile->pos = 0;
    is(cckprng_loadseed(), CCERR_OK, "cckprng_loadseed ok (many-byte read, one-byte write)");
    is(randomdev->len, seedfile->len, "cckprng_loadseed size (many-byte read, one-byte write)");
    ok_memcmp(seedfile->buf, randomdev->buf, seedfile->len, "cckprng_loadseed match (many-byte read, one-byte write)");

    read_mock = read_onebyte;
    write_mock = write_onebyte;
    file_erase(randomdev);
    seedfile->pos = 0;
    is(cckprng_loadseed(), CCERR_OK, "cckprng_loadseed ok (one-byte read, one-byte write)");
    is(randomdev->len, seedfile->len, "cckprng_loadseed size (one-byte read, one-byte write)");
    ok_memcmp(seedfile->buf, randomdev->buf, seedfile->len, "cckprng_loadseed match (one-byte read, one-byte write)");

    open_mock = NULL;
    read_mock = NULL;
    write_mock = NULL;
    close_mock = NULL;

    return 1;
}

static int getentropy_fail(void *buf, size_t buflen)
{
    (void)buf;
    (void)buflen;

    return -1;
}

static int getentropy_seed(void *buf, size_t buflen)
{
    memcpy(buf, seed, buflen);

    return 0;
}

static int fchmod_fail(int fd, mode_t mode)
{
    (void)fd;
    (void)mode;

    return -1;
}

static int fchmod_nop(int fd, mode_t mode)
{
    (void)fd;
    (void)mode;

    return 0;
}

static int fchown_fail(int fd, uid_t owner, gid_t group)
{
    (void)fd;
    (void)owner;
    (void)group;

    return -1;
}

static int fchown_nop(int fd, uid_t owner, gid_t group)
{
    (void)fd;
    (void)owner;
    (void)group;

    return 0;
}

static int cckprng_test_storeseed(void)
{
    close_mock = close_nop;

    getentropy_mock = getentropy_fail;
    is(cckprng_storeseed(), CCKPRNG_GETENTROPY, "cckprng_storeseed get entropy");
    getentropy_mock = getentropy_seed;

    open_mock = open_seedfile_fail;
    is(cckprng_storeseed(), CCKPRNG_SEEDFILE_OPEN, "cckprng_storeseed open seedfile");

    open_mock = open_lookup;
    fchmod_mock = fchmod_fail;
    is(cckprng_storeseed(), CCKPRNG_SEEDFILE_CHMOD, "cckprng_storeseed chmod seedfile");

    fchmod_mock = fchmod_nop;
    fchown_mock = fchown_fail;
    is(cckprng_storeseed(), CCKPRNG_SEEDFILE_CHOWN, "cckprng_storeseed chown seedfile");

    fchown_mock = fchown_nop;
    write_mock = write_manybytes;
    file_erase(seedfile);
    is(cckprng_storeseed(), CCERR_OK, "cckprng_storeseed ok (many-byte write)");
    is(seedfile->len, CCKPRNG_SEEDSIZE, "cckprng_storeseed size (many-byte write)");
    ok_memcmp(seedfile->buf, seed, seedfile->len, "cckprng_storeseed match (many-byte write)");

    write_mock = write_onebyte;
    file_erase(seedfile);
    is(cckprng_storeseed(), CCERR_OK, "cckprng_storeseed ok (one-byte write)");
    is(seedfile->len, CCKPRNG_SEEDSIZE, "cckprng_storeseed size (one-byte write)");
    ok_memcmp(seedfile->buf, seed, seedfile->len, "cckprng_storeseed match (one-byte write)");

    getentropy_mock = NULL;
    open_mock = NULL;
    fchmod_mock = NULL;
    fchown_mock = NULL;
    write_mock = NULL;
    close_mock = NULL;

    return 1;
}

#endif /* CC_PRNG_SEEDTESTS */

/*
 
 Test Structures
 
 */

enum {
    OP_INIT,
    OP_RESEED,
    OP_REFRESH,
    OP_GENERATE
};

struct cckprng_op {
    unsigned id;
    unsigned kind;
    bool abort;
};

struct cckprng_vector {
    unsigned id;
    const char *note;
    unsigned nops;
    const struct cckprng_op **ops;
};

struct cckprng_op_init {
    struct cckprng_op hd;
    uint8_t seed[32];
    uint8_t nonce[8];
    ccrng_fortuna_getentropy getentropy;
};

struct cckprng_op_reseed {
    struct cckprng_op hd;
    uint64_t nonce;
    size_t seed_nbytes;
    uint8_t seed[512];
};

struct cckprng_op_refresh {
    struct cckprng_op hd;
    uint64_t rand;
    int32_t nsamples;
    bool needreseed;
};

struct cckprng_op_generate {
    struct cckprng_op hd;
    size_t rand_nbytes;
    struct {
        const uint8_t rand[512];
        const uint8_t key[32];
        const uint8_t ctr[16];
    } out;
};

struct kat_ctx {
    struct cckprng_ctx ctx;
    bool reseed;
    uint8_t rand[512];
    int gen_err;
};

typedef void (*process_fn_t)(struct kat_ctx *, const struct cckprng_op *);
typedef void (*verify_fn_t)(struct kat_ctx *, const struct cckprng_op *);

static uint64_t nonce_static;
static uint64_t cckprng_reseed_get_nonce_static(void)
{
    return nonce_static;
}

static uint64_t rand_static;
static bool cc_rdrand_static(uint64_t *rand)
{
    *rand = rand_static;
    return true;
}


static int32_t fortuna_get_entropy_nsamples;
static int32_t fortuna_get_entropy_ones(size_t *entropy_nbytes, void *entropy, void *arg)
{
    (void) arg;
    uint8_t *out = (uint8_t *) entropy;
    for (size_t i = 0; i < *entropy_nbytes; i++) {
        out[i] = 0x01;
    }
    return fortuna_get_entropy_nsamples;
}

/*
 
 Process & Verify Functions
 
 */

static void process_init(struct kat_ctx *kat_ctx, const struct cckprng_op *op)
{
    const struct cckprng_op_init *o = (const struct cckprng_op_init *)op;
    struct cckprng_ctx *ctx = &kat_ctx->ctx;
    
    cckprng_init(ctx, sizeof(o->seed), o->seed, sizeof(o->nonce), o->nonce, o->getentropy, NULL);
}

static void verify_init(struct kat_ctx *kat_ctx, const struct cckprng_op *op)
{
    (void) kat_ctx;
    (void) op;
}

static void process_reseed(struct kat_ctx *kat_ctx, const struct cckprng_op *op)
{
    const struct cckprng_op_reseed *o = (const struct cckprng_op_reseed *)op;
    struct cckprng_ctx *ctx = &kat_ctx->ctx;
    
    nonce_static = o->nonce;
    cckprng_reseed(ctx, o->seed_nbytes, o->seed);
}

static void verify_reseed(struct kat_ctx *kat_ctx, const struct cckprng_op *op)
{
    (void) kat_ctx;
    (void) op;
}

static void process_refresh(struct kat_ctx *kat_ctx, const struct cckprng_op *op)
{
    const struct cckprng_op_refresh *o = (const struct cckprng_op_refresh *)op;
    struct cckprng_ctx *ctx = &kat_ctx->ctx;
    
    fortuna_get_entropy_nsamples = o->nsamples;
    rand_static = o->rand;
    
    cckprng_refresh(ctx);
}

static void verify_refresh(struct kat_ctx *kat_ctx, const struct cckprng_op *op)
{
    const struct cckprng_op_refresh *o = (const struct cckprng_op_refresh *)op;
    struct cckprng_ctx *ctx = &kat_ctx->ctx;
    bool needreseed = ctx->schedule_ctx.flag == CCRNG_SCHEDULE_MUST_RESEED;
    is(needreseed, o->needreseed, "refresh needreseed");
}


static void process_generate(struct kat_ctx *kat_ctx, const struct cckprng_op *op)
{
    const struct cckprng_op_generate *o = (const struct cckprng_op_generate *)op;
    struct cckprng_ctx *ctx = &kat_ctx->ctx;
    
    cckprng_generate(ctx, 0, o->rand_nbytes, kat_ctx->rand);
}

static void verify_generate(struct kat_ctx *kat_ctx, const struct cckprng_op *op)
{
    const struct cckprng_op_generate *o = (const struct cckprng_op_generate *)op;
    
    ok_memcmp(kat_ctx->rand, o->out.rand, o->rand_nbytes, "generate rand");
}

/*
 
 KAT Functions
 
 */

static void cckprng_test_kat(const struct cckprng_vector *vec)
{
    struct kat_ctx kat_ctx;
    process_fn_t process_fns[] = {
                                process_init,
                                process_reseed,
                                process_refresh,
                                process_generate
    };
    verify_fn_t verify_fns[] = {
                                verify_init,
                                verify_reseed,
                                verify_refresh,
                                verify_generate
    };

    cc_clear(sizeof(kat_ctx), &kat_ctx);
    cckprng_reseed_get_nonce_mock = cckprng_reseed_get_nonce_static;
    cc_rdrand_mock = cc_rdrand_static;

    for (unsigned i = 0; i < vec->nops; i += 1) {
        const struct cckprng_op *op = vec->ops[i];

        // Reset ephemeral bits of state
        cc_clear(sizeof(kat_ctx.rand), kat_ctx.rand);

        // Process vector
        process_fns[op->kind](&kat_ctx, op);

        // Verify results
        verify_fns[op->kind](&kat_ctx, op);
    }

    cckprng_reseed_get_nonce_mock = NULL;
    cc_rdrand_mock = NULL;
}

#include "cckprng_kat.inc"

static int cckprng_test_runner(void) {
    diag("Start Fortuna KAT Tests");
   
    for (unsigned i = 0; i < CC_ARRAY_LEN(test_vectors); i += 1) {
        cckprng_test_kat(test_vectors[i]);
    }
    
    diag("End Fortuna KAT Tests");
    return 0;
}

#if CC_TSAN
#include <pthread.h>
static struct cckprng_ctx tsan_kprng;
static int32_t cckprng_tsan_get_entropy(size_t *nbytes, void *entropy, void *arg) {
    (void) arg;
    uint8_t *eb = (uint8_t *) entropy;
    for (size_t i = 0; i < *nbytes; i++) {
        eb[i] = i & 0xff;
    }
    return 2048;
}

static void *cckprng_tsan_thread_generate(void *arg) {
    (void) arg;
    uint8_t generate[32] = {0};
    for (int i = 0; i < 10000; i++) {
        cckprng_generate(&tsan_kprng, 0, sizeof(generate), generate);
    }
    return NULL;
}

static void *cckprng_tsan_thread_reseed(void *arg) {
    (void) arg;
    uint8_t reseed[32] = {1,2,3,4,5};
    for (int i = 0; i < 10000; i++) {
        cckprng_reseed(&tsan_kprng, sizeof(reseed), reseed);
    }
    return NULL;
}

static void cckprng_tsan_test() {
    uint8_t seed[64] = {0};
    uint8_t nonce[32] = {0};
    cckprng_init(&tsan_kprng, sizeof(seed), seed, sizeof(nonce), nonce, cckprng_tsan_get_entropy, NULL);
    
    pthread_t t_generate, t_reseed;
    
    pthread_create(&t_generate, NULL, cckprng_tsan_thread_generate, NULL);
    pthread_create(&t_reseed, NULL, cckprng_tsan_thread_reseed, NULL);
    
    pthread_join(t_generate, NULL);
    pthread_join(t_reseed, NULL);
}
#endif

int cckprng_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(3980);

#if CC_PRNG_SEEDTESTS
    ok(cckprng_test_loadseed(), "cckprng_test_loadseed");
    ok(cckprng_test_storeseed(), "cckprng_test_storeseed");
#endif /* CC_PRNG_SEEDTESTS */
    
    cckprng_test_runner();
    
#if CC_TSAN
    diag("Start KPRNG TSAN Tests");
    cckprng_tsan_test();
    diag("End KPRNG TSAN Tests");
#endif

    return 0;
}
