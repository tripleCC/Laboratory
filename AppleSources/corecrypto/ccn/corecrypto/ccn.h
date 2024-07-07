/* Copyright (c) (2010-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCN_H_
#define _CORECRYPTO_CCN_H_

#include <corecrypto/cc.h>

CC_PTRCHECK_CAPABLE_HEADER()

typedef size_t  cc_size;

#if CCN_UNIT_SIZE == 8
typedef uint64_t cc_unit;          // 64 bit unit
typedef int64_t  cc_int;
#define CCN_LOG2_BITS_PER_UNIT  6  // 2^6 = 64 bits
#define CC_UNIT_C(x) UINT64_C(x)
#elif CCN_UNIT_SIZE == 4
typedef uint32_t cc_unit;          // 32 bit unit
typedef int32_t cc_int;
#define CCN_LOG2_BITS_PER_UNIT  5  // 2^5 = 32 bits
#define CC_UNIT_C(x) UINT32_C(x)

#else
#error Unsupported CCN_UNIT_SIZE
#endif

#define CCN_UNIT_BITS  (sizeof(cc_unit) * 8)
#define CCN_UNIT_MASK  ((cc_unit)~0)
#define CCN_UNIT_LOWER_HALF_MASK  ((CCN_UNIT_MASK) >> (CCN_UNIT_BITS/2))
#define CCN_UNIT_UPPER_HALF_MASK  (~CCN_UNIT_LOWER_HALF_MASK)
#define CCN_UNIT_HALF_BITS (CCN_UNIT_BITS / 2)

/* Conversions between n sizeof and bits */

/* Returns the sizeof a ccn vector of length _n_ units. */
#define ccn_sizeof_n(_n_)  (sizeof(cc_unit) * (_n_))

/* Returns the count (n) of a ccn vector that can represent _bits_. */
#define ccn_nof(_bits_)  (((_bits_) + CCN_UNIT_BITS - 1) / CCN_UNIT_BITS)

/* Returns the sizeof a ccn vector that can represent _bits_. */
#define ccn_sizeof(_bits_)  (ccn_sizeof_n(ccn_nof(_bits_)))

/* Returns the count (n) of a ccn vector that can represent _size_ bytes. */
#define ccn_nof_size(_size_)  (((_size_) + sizeof(cc_unit) - 1) / sizeof(cc_unit))

#define ccn_nof_sizeof(_expr_) ccn_nof_size(sizeof(_expr_))

/* Return the max number of bits a ccn vector of _n_ units can hold. */
#define ccn_bitsof_n(_n_)  ((_n_) * CCN_UNIT_BITS)

/* Return the max number of bits a ccn vector of _size_ bytes can hold. */
#define ccn_bitsof_size(_size_)  ((_size_) * 8)

/* Return the size of a ccn of size bytes in bytes. */
#define ccn_sizeof_size(_size_)  ccn_sizeof_n(ccn_nof_size(_size_))

/*!
 @function ccn_set_bit
 @param x The input cc_unit
 @param k The index to set
 @param v The value to set
 */
CC_NONNULL_ALL
void ccn_set_bit(cc_unit *cc_indexable x, size_t k, cc_unit v);

/* Macros for making ccn constants.  You must use list of CCN64_C() instances
 separated by commas, with an optional smaller sized CCN32_C, CCN16_C, or
 CCN8_C() instance at the end of the list, when making macros to declare
 larger sized constants. */
#define CCN8_C(a0) CC_UNIT_C(0x##a0)

#define CCN16_C(a1,a0) CC_UNIT_C(0x##a1##a0)
#define ccn16_v(a0)  (a0)

#define CCN32_C(a3,a2,a1,a0) CC_UNIT_C(0x##a3##a2##a1##a0)
#define ccn32_v(a0)  (a0)

#if CCN_UNIT_SIZE == 8
#define CCN64_C(a7,a6,a5,a4,a3,a2,a1,a0) CC_UNIT_C(0x##a7##a6##a5##a4##a3##a2##a1##a0)
#define CCN40_C(a4,a3,a2,a1,a0) CC_UNIT_C(0x##a4##a3##a2##a1##a0)
#define ccn64_v(a0)  (a0)
#else
#define CCN64_C(a7,a6,a5,a4,a3,a2,a1,a0) CCN32_C(a3,a2,a1,a0),CCN32_C(a7,a6,a5,a4)
#define CCN40_C(a4,a3,a2,a1,a0) CCN32_C(a3,a2,a1,a0),CCN8_C(a4)
#define ccn64_v(a0)  ccn32_v((uint64_t)a0 & UINT32_C(0xffffffff)),ccn32_v((uint64_t)a0 >> 32)
#endif

/* Macro's for reading uint32_t and uint64_t from ccns, the index is in 32 or
 64 bit units respectively. */
#if CCN_UNIT_SIZE == 8

#define ccn64_32(a1,a0) (((const cc_unit)a1) << 32 | ((const cc_unit)a0))
#define ccn32_32(a0) a0
#if __LITTLE_ENDIAN__
#define ccn32_32_parse(p,i) (((const uint32_t *)p)[i])
#else
#define ccn32_32_parse(p,i) (((const uint32_t *)p)[i^1])
#endif
#define ccn32_32_null 0

#define ccn64_64(a0) a0
#define ccn64_64_parse(p,i) p[i]
#define ccn64_64_null 0

#elif CCN_UNIT_SIZE == 4

#define ccn32_32(a0) a0
#define ccn32_32_parse(p,i) p[i]
#define ccn32_32_null 0
#define ccn64_32(a1,a0) ccn32_32(a0),ccn32_32(a1)

#define ccn64_64(a1,a0) a0,a1
#define ccn64_64_parse(p,i) p[1+(i<<1)],p[i<<1]
#define ccn64_64_null 0,0

#endif


/* Macros to construct fixed size ccn arrays from 64 or 32 bit quantities. */
#define ccn192_64(a2,a1,a0) ccn64_64(a0),ccn64_64(a1),ccn64_64(a2)
#define ccn192_32(a5,a4,a3,a2,a1,a0) ccn64_32(a1,a0),ccn64_32(a3,a2),ccn64_32(a5,a4)
#define ccn224_32(a6,a5,a4,a3,a2,a1,a0) ccn64_32(a1,a0),ccn64_32(a3,a2),ccn64_32(a5,a4),ccn32_32(a6)
#define ccn256_32(a7,a6,a5,a4,a3,a2,a1,a0) ccn64_32(a1,a0),ccn64_32(a3,a2),ccn64_32(a5,a4),ccn64_32(a7,a6)
#define ccn384_32(a11,a10,a9,a8,a7,a6,a5,a4,a3,a2,a1,a0) ccn64_32(a1,a0),ccn64_32(a3,a2),ccn64_32(a5,a4),ccn64_32(a7,a6),ccn64_32(a9,a8),ccn64_32(a11,a10)


#define CCN192_C(c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0) \
    CCN64_C(a7,a6,a5,a4,a3,a2,a1,a0),\
    CCN64_C(b7,b6,b5,b4,b3,b2,b1,b0),\
    CCN64_C(c7,c6,c5,c4,c3,c2,c1,c0)

#define CCN200_C(d0,c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0) \
    CCN192_C(c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0),\
    CCN8_C(d0)

#define CCN224_C(d3,d2,d1,d0,c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0) \
    CCN192_C(c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0),\
    CCN32_C(d3,d2,d1,d0)

#define CCN232_C(d4,d3,d2,d1,d0,c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0) \
    CCN192_C(c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0),\
    CCN40_C(d4,d3,d2,d1,d0)

#define CCN256_C(d7,d6,d5,d4,d3,d2,d1,d0,c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0) \
    CCN192_C(c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0),\
    CCN64_C(d7,d6,d5,d4,d3,d2,d1,d0)

#define CCN384_C(f7,f6,f5,f4,f3,f2,f1,f0,e7,e6,e5,e4,e3,e2,e1,e0,d7,d6,d5,d4,d3,d2,d1,d0,c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0) \
    CCN256_C(d7,d6,d5,d4,d3,d2,d1,d0,c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0),\
    CCN64_C(e7,e6,e5,e4,e3,e2,e1,e0),\
    CCN64_C(f7,f6,f5,f4,f3,f2,f1,f0)

#define CCN448_C(g7,g6,g5,g4,g3,g2,g1,g0,f7,f6,f5,f4,f3,f2,f1,f0,e7,e6,e5,e4,e3,e2,e1,e0,d7,d6,d5,d4,d3,d2,d1,d0,c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0) \
    CCN256_C(d7,d6,d5,d4,d3,d2,d1,d0,c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0),\
    CCN192_C(g7,g6,g5,g4,g3,g2,g1,g0,f7,f6,f5,f4,f3,f2,f1,f0,e7,e6,e5,e4,e3,e2,e1,e0)

#define CCN528_C(i1,i0,h7,h6,h5,h4,h3,h2,h1,h0,g7,g6,g5,g4,g3,g2,g1,g0,f7,f6,f5,f4,f3,f2,f1,f0,e7,e6,e5,e4,e3,e2,e1,e0,d7,d6,d5,d4,d3,d2,d1,d0,c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0) \
    CCN256_C(d7,d6,d5,d4,d3,d2,d1,d0,c7,c6,c5,c4,c3,c2,c1,c0,b7,b6,b5,b4,b3,b2,b1,b0,a7,a6,a5,a4,a3,a2,a1,a0),\
    CCN256_C(h7,h6,h5,h4,h3,h2,h1,h0,g7,g6,g5,g4,g3,g2,g1,g0,f7,f6,f5,f4,f3,f2,f1,f0,e7,e6,e5,e4,e3,e2,e1,e0),\
    CCN16_C(i1,i0)

#define CCN192_N  ccn_nof(192)
#define CCN224_N  ccn_nof(224)
#define CCN256_N  ccn_nof(256)
#define CCN384_N  ccn_nof(384)
#define CCN448_N  ccn_nof(448)
#define CCN512_N  ccn_nof(512)
#define CCN521_N  ccn_nof(521)

/* s == 0 -> return 0 | s > 0 -> return index (starting at 1) of most
 * significant bit that is 1.
 * { N bit } N = n * sizeof(cc_unit) * 8
 *
 * Runs in constant time, independent of the value of `s`.
 */
CC_NONNULL((2))
size_t ccn_bitlen(cc_size n, const cc_unit *cc_counted_by(n) s);

/* s == 0 -> return true | s != 0 -> return false
 { N bit } N = n * sizeof(cc_unit) * 8 */
#define ccn_is_zero(_n_, _s_) (!ccn_n((_n_), (_s_)))

/* s == 1 -> return true | s != 1 -> return false
 { N bit } N = n * sizeof(cc_unit) * 8 */
#define ccn_is_one(_n_, _s_) (ccn_n((_n_), (_s_)) == 1 && (_s_)[0] == 1)

#define ccn_is_zero_or_one(_n_, _s_) (((_n_)==0) || ((ccn_n((_n_), (_s_)) <= 1) && ((_s_)[0] <= 1)))

/* s < t -> return - 1 | s == t -> return 0 | s > t -> return 1
 { N bit, N bit -> int } N = n * sizeof(cc_unit) * 8 */
CC_PURE CC_NONNULL((2, 3))
int ccn_cmp(cc_size n, const cc_unit *cc_counted_by(n) s, const cc_unit *cc_counted_by(n) t) __asm__("_ccn_cmp");

/*! @function ccn_cmpn
 @abstract Compares the values of two big ints of different lengths.

 @discussion The execution time does not depend on the values of either s or t.
             The function does not hide ns, nt, or whether ns > nt.

 @param ns  Length of s
 @param s   First integer
 @param nt  Length of t
 @param t   Second integer

 @return 1 if s > t, -1 if s < t, 0 otherwise.
 */
CC_NONNULL_ALL
int ccn_cmpn(cc_size ns, const cc_unit *cc_counted_by(ns) s, cc_size nt, const cc_unit *cc_counted_by(nt) t);

/* s - t -> r return 1 iff t > s
 { N bit, N bit -> N bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL((2, 3, 4))
cc_unit ccn_sub(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, const cc_unit *cc_counted_by(n) t) __asm__("_ccn_sub");

/* s + t -> r return carry if result doesn't fit in n bits.
 { N bit, N bit -> N bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL((2, 3, 4))
cc_unit ccn_add(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, const cc_unit *cc_counted_by(n) t) __asm__("_ccn_add");

/* s + v -> r return carry if result doesn't fit in n bits.
 { N bit, sizeof(cc_unit) * 8 bit -> N bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL((2, 3))
cc_unit ccn_add1(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, cc_unit v);

/*!
 @function   ccn_read_uint
 @abstract   Copy big endian integer and represent it in cc_units
 
 @param n           Input allocated size of the cc_unit output array r
 @param r           Ouput cc_unit array for unsigned integer
 @param data_nbytes Input byte size of data
 @param data        Input unsigned integer represented in big endian
 
 @result r is initialized with the big unsigned number
 
 @return 0 if no error, !=0 if the big number cannot be represented in the allocated cc_unit array.
 
 @discussion The execution pattern of this function depends on both n and data_nbytes but not on data values except the handling
 of the error case.
 */

CC_NONNULL((2, 4))
int ccn_read_uint(cc_size n, cc_unit *cc_counted_by(n) r, size_t data_nbytes, const uint8_t *cc_sized_by(data_nbytes) data);

/* r = (data, len) treated as a big endian byte array, return -1 if data
 doesn't fit in r, return 0 otherwise.
 ccn_read_uint strips leading zeroes and doesn't care about sign. */
#define ccn_read_int(n, r, data_size, data) ccn_read_uint(n, r, data_size, data)

/*!
 @function   ccn_write_uint_size
 @abstract   Compute the minimum size required to store an big integer
 
 @param n           Input size of the cc_unit array representing the input
 @param s           Input cc_unit array
 
 @result Return value is the exact byte size of the big integer
 
 @discussion
 The execution flow is independent on the value of the big integer.
 However, the use of the returned value may leak the position of the most significant byte
 */
CC_PURE CC_NONNULL((2)) size_t ccn_write_uint_size(cc_size n, const cc_unit *cc_counted_by(n) s);

/*!
 @function   ccn_write_uint
 @abstract   Serialize the big integer into a big endian byte buffer
 
 @param n           Input size of the cc_unit array representing the input
 @param s           Input cc_unit array
 @param out_size    Size of the output buffer
 @param out         Output byte array of size at least  out_size

 @discussion This function writes exactly
 MIN(out_size,ccn_write_uint_size(n,s)) bytes truncating to keep the
 most significant bytes when out_size<ccn_write_uint_size(n,s). The
 execution flow of function is based on the position of the most
 significant byte as well as input sizes.

 */

CC_NONNULL((2, 4))
void ccn_write_uint(cc_size n, const cc_unit *cc_counted_by(n) s, size_t out_size, void *cc_sized_by(out_size) out);

/*!
 @function   ccn_write_uint_padded_ct
 @abstract   Serialize the big integer into a big endian byte buffer
 
 @param n           Input size of the cc_unit array representing the input
 @param s           Input cc_unit array
 @param out_size    Size of the output buffer
 @param out         Output byte array of size at least  out_size
 
 @return number of leading zero bytes in case of success, a negative error value in case of failure
 
 @result  This function writes exactly out_size byte, padding with zeroes when necessary.
 This function DOES NOT support truncation and returns an error if out_size < ccn_write_uint_size
 
 @discussion The execution flow of function is independent on the value of the big integer
 However, the processing of the return value by the caller may expose the position of
 the most significant byte
 */
CC_NONNULL((2, 4))
int ccn_write_uint_padded_ct(cc_size n, const cc_unit *cc_sized_by(n) s, size_t out_size, uint8_t *cc_counted_by(out_size) out);

/*!
 @function   ccn_write_uint_padded
 @abstract   Serialize the big integer into a big endian byte buffer
 Not recommended, for most cases ccn_write_uint_padded_ct is more appropriate
 Sensitive big integers are exposed since the processing expose the position of the MS byte
 
 @param n           Input size of the cc_unit array representing the input
 @param s           Input cc_unit array
 @param out_size    Size of the output buffer
 @param out         Output byte array of size at least  out_size
 
 @return number of leading zero bytes
 
 @result  This function writes exactly out_size byte, padding with zeroes when necessary.
 This function DOES support truncation when out_size<ccn_write_uint_size()
 
 @discussion The execution flow of this function DEPENDS on the position of the most significant byte in
 case truncation is required.
 */

CC_NONNULL((2, 4))
size_t ccn_write_uint_padded(cc_size n, const cc_unit *cc_counted_by(n) s, size_t out_size, uint8_t *cc_sized_by(out_size) out);


/*  Return actual size in bytes needed to serialize s as int
    (adding leading zero if high bit is set). */
CC_PURE CC_NONNULL((2))
size_t ccn_write_int_size(cc_size n, const cc_unit *cc_counted_by(n) s);

/*  Serialize s, to out.
    First byte of byte stream is the m.s. byte of s,
    regardless of the size of cc_unit.

    No assumption is made about the alignment of out.

    The out_size argument should be the value returned from ccn_write_int_size,
    and is also the exact number of bytes this function will write to out.
    If out_size if less than the value returned by ccn_write_int_size, only the
    first out_size non-zero most significant octets of s will be written. */
CC_NONNULL((2, 4))
void ccn_write_int(cc_size n, const cc_unit *cc_counted_by(n) s, size_t out_size, void *cc_sized_by(out_size) out);

CC_NONNULL((2))
void ccn_zero(cc_size n, cc_unit *cc_sized_by(n) r);

CC_NONNULL((2))
void ccn_seti(cc_size n, cc_unit *cc_counted_by(n) r, cc_unit v);

#define CC_SWAP_HOST_BIG_64(x) \
    ((uint64_t)((((uint64_t)(x) & 0xff00000000000000ULL) >> 56) | \
    (((uint64_t)(x) & 0x00ff000000000000ULL) >> 40) | \
    (((uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) | \
    (((uint64_t)(x) & 0x000000ff00000000ULL) >>  8) | \
    (((uint64_t)(x) & 0x00000000ff000000ULL) <<  8) | \
    (((uint64_t)(x) & 0x0000000000ff0000ULL) << 24) | \
    (((uint64_t)(x) & 0x000000000000ff00ULL) << 40) | \
    (((uint64_t)(x) & 0x00000000000000ffULL) << 56)))
#define CC_SWAP_HOST_BIG_32(x) \
    ((((x) & 0xff000000) >> 24) | \
    (((x) & 0x00ff0000) >>  8) | \
    (((x) & 0x0000ff00) <<  8) | \
    (((x) & 0x000000ff) <<  24))
#define CC_SWAP_HOST_BIG_16(x) \
    ((((x) & 0xff00) >>  8) | \
    (((x) & 0x00ff) <<  8))

/* This should probably move if we move ccn_swap out of line. */
#if CCN_UNIT_SIZE == 8
#define CC_UNIT_TO_BIG(x) CC_SWAP_HOST_BIG_64(x)
#elif CCN_UNIT_SIZE == 4
#define CC_UNIT_TO_BIG(x) CC_SWAP_HOST_BIG_32(x)
#else
#error Unsupported CCN_UNIT_SIZE
#endif

/*!
 @function ccn_swap
 @discussion Swaps r inplace from cc_unit vector byte order to big endian byte order (or back)
 */
CC_NONNULL((2))
void ccn_swap(cc_size n, cc_unit *cc_counted_by(n) r);

CC_NONNULL((2, 3, 4))
void ccn_xor(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, const cc_unit *cc_counted_by(n) t);

/* Debugging */
CC_NONNULL((2))
void ccn_print(cc_size n, const cc_unit *cc_counted_by(n) s);
CC_NONNULL((3))
void ccn_lprint(cc_size n, const char *cc_cstring label, const cc_unit *cc_counted_by(n) s);

/* Forward declaration so we don't depend on ccrng.h. */
struct ccrng_state;

#define ccn_random(_n_,_r_,_ccrng_ctx_) \
    ccrng_generate(_ccrng_ctx_, ccn_sizeof_n(_n_), (unsigned char *)_r_)

#endif /* _CORECRYPTO_CCN_H_ */
