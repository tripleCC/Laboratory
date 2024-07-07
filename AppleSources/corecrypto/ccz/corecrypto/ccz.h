/* Copyright (c) (2011,2012,2015,2017-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCZ_H_
#define _CORECRYPTO_CCZ_H_

#include <corecrypto/ccn.h>

CC_PTRCHECK_CAPABLE_HEADER()

struct ccz {
    size_t n;
    struct ccz_class *isa;
    int sac;
    cc_unit *cc_counted_by(n) u;
};
typedef struct ccz ccz;

struct ccz_class {
	void *ctx;
	void * /* cc_sized_by(len) */ (*ccz_alloc)(void * ctx, size_t len);
	void * /* cc_sized_by(len) */ (*ccz_realloc)(void *, size_t, void * ctx, size_t len);
	void (*ccz_free)(void *, size_t, void *);
};

/* Return the size needed for a ccz big enough to hold cls type ccz's. */
CC_NONNULL_ALL
size_t ccz_size(struct ccz_class *cls);

/* Initialize a new ccz instance. */
CC_NONNULL_ALL
void ccz_init(struct ccz_class *cls, ccz *r);

/* Release the memory a ccz is holding on to. */
CC_NONNULL_ALL
void ccz_free(ccz *r);

/* r = 0, and clear memory accessed by r. */
CC_NONNULL_ALL
void ccz_zero(ccz *r);

/* r = s */
CC_NONNULL_ALL
void ccz_set(ccz *r, const ccz *s);

CC_NONNULL((1))
void ccz_seti(ccz *r, uint64_t v);

/* s == 0 -> return 0 | s > 0 -> return index (starting at 1) of most
 significant bit that is 1. */
CC_PURE CC_NONNULL_ALL
size_t ccz_bitlen(const ccz *s);

/* s == 0 -> return 0 | s > 0 -> return the number of bits which are zero
   before the first one bit from least to most significant bit. */
CC_PURE CC_NONNULL_ALL
size_t ccz_trailing_zeros(const ccz *s);

/* Return actual size in bytes needed to serialize s. */
CC_PURE CC_NONNULL((1))
size_t ccz_write_uint_size(const ccz *s);

/* Serialize s, to out.
 First byte of byte stream is the m.s. byte of s,
 regardless of the size of cc_unit.

 No assumption is made about the alignment of out.

 The out_size argument should be the value returned from ccz_write_uint_size,
 and is also the exact number of bytes this function will write to out.
 If out_size if less than the value returned by ccz_write_uint_size, only the
 first out_size non-zero most significant octets of s will be written. */
CC_NONNULL((1, 3))
void ccz_write_uint(const ccz *s, size_t out_size, void *cc_sized_by(out_size) out);

/*  Return actual size in bytes needed to serialize s as int
 (adding leading zero if high bit is set). */
CC_PURE CC_NONNULL((1))
size_t ccz_write_int_size(const ccz *s);

/*  Serialize s, to out.
 First byte of byte stream is the m.s. byte of s,
 regardless of the size of cc_unit.

 No assumption is made about the alignment of out.

 The out_size argument should be the value returned from ccz_write_int_size,
 and is also the exact number of bytes this function will write to out.
 If out_size if less than the value returned by ccz_write_int_size, only the
 first out_size non-zero most significant octets of s will be written. */
CC_NONNULL((1, 3))
void ccz_write_int(const ccz *s, size_t out_size, void *cc_sized_by(out_size) out);

/*  Return actual size in bytes needed to serialize s in base radix. Radix can be any value between 2 and 64.  */
CC_PURE CC_NONNULL((1))
size_t ccz_write_radix_size(const ccz *s, unsigned radix);

/* r = (data, len) treated as a big endian byte array, written in base radix. Radix can be any value between 2 and 64. */
/* Not constant time. Do not use for sensitive information. */
CC_NONNULL((1, 3))
int ccz_write_radix(const ccz *s, size_t out_size, void *cc_sized_by(out_size) out, unsigned radix);

/* r = (data, len) treated as a big endian byte array. */
CC_NONNULL((1, 3))
void ccz_read_uint(ccz *r, size_t data_size, const uint8_t *cc_counted_by(data_size) data);

/* r = (data, len) treated as a big endian byte array.  Return nonzero iff the passed in buffer isn't a valid base radix input string. Radix can be any value between 2 and 64.
 Returns: 0 if no error
    CCZ_INVALID_INPUT_ERROR if the input is not valid for the select radar
    CCZ_INVALID_RADIX_ERROR if the radix is not supported (>64) */
/* Not constant time. Do not use for sensitive information. */
CC_NONNULL((1, 3))
int ccz_read_radix(ccz *r, size_t data_size, const char *cc_counted_by(data_size) data, unsigned radix);

CC_PURE CC_NONNULL_ALL
int ccz_cmp(const ccz *s, const ccz *t);

CC_PURE CC_NONNULL_ALL
int ccz_cmpi(const ccz *s, uint32_t v);

/* r = -r. */
CC_NONNULL_ALL
void ccz_neg(ccz *r);

/* r = s + t. */
CC_NONNULL_ALL
void ccz_add(ccz *r, const ccz *s, const ccz *t);

/* r = s + v. */
CC_NONNULL_ALL
void ccz_addi(ccz *r, const ccz *s, uint32_t v);

/* r = s - t. */
CC_NONNULL_ALL
void ccz_sub(ccz *r, const ccz *s, const ccz *t);

/* r = s - v. */
CC_NONNULL_ALL
void ccz_subi(ccz *r, const ccz *s, uint32_t v);

/* r = s * t  */
CC_NONNULL_ALL
void ccz_mul(ccz *r, const ccz *s, const ccz *t);

/* r = s * t  */
CC_NONNULL_ALL
void ccz_muli(ccz *r, const ccz *s, uint32_t v);

/* q = s / t, r = s % t */
CC_NONNULL((3, 4))
void ccz_divmod(ccz *q, ccz *r, const ccz *s, const ccz *t);

/* r = s >> k  */
CC_NONNULL((1, 2))
void ccz_lsr(ccz *r, const ccz *s, size_t k);

/* r = s << k */
CC_NONNULL((1, 2))
void ccz_lsl(ccz *r, const ccz *s, size_t k);

/* r = s % t */
CC_NONNULL_ALL
void ccz_mod(ccz *r, const ccz *s, const ccz *t);

/* r = (s * t) mod u.  */
CC_NONNULL_ALL
void ccz_mulmod(ccz *r, const ccz *s, const ccz *t, const ccz *u);

/* r = (s^t) mod u.  */
CC_NONNULL_ALL
int ccz_expmod(ccz *r, const ccz *s, const ccz *t, const ccz *u);

/* Return the value of bit k in s. */
CC_PURE CC_NONNULL((1))
bool ccz_bit(const ccz *s, size_t k);

/* Set the value of bit k in r to value. */
CC_NONNULL((1))
void ccz_set_bit(ccz *r, size_t k, bool value);

/* Return true iff s a is likely prime. Using rabin miller for depth.
 This method is not safe for adverserial prime-testing where `s` can be attacker-controlled.
 */
CC_NONNULL_ALL
bool ccz_is_prime(const ccz *s, unsigned depth);

/* s == 0 -> return true | s != 0 -> return false */
CC_PURE CC_NONNULL_ALL
bool ccz_is_zero(const ccz *s);

/* s == 1 -> return true | s != 1 -> return false */
CC_PURE CC_NONNULL_ALL
bool ccz_is_one(const ccz *s);

/* s < 0 -> return true | s >= 0 -> return false */
CC_PURE CC_NONNULL_ALL
bool ccz_is_negative(const ccz *s);

/* Forward declaration so we don't depend on ccrng.h. */
struct ccrng_state;

/* Make a ccz with up to nbits sized random value. */
CC_NONNULL((1, 3))
int ccz_random_bits(ccz *r, size_t nbits, struct ccrng_state *rng);

#endif /* _CORECRYPTO_CCZ_H_ */
