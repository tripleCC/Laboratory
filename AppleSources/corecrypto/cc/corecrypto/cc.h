/* Copyright (c) (2010-2012,2014-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CC_H_
#define _CORECRYPTO_CC_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/cc_impl.h>
#include <corecrypto/cc_error.h>

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>

CC_PTRCHECK_CAPABLE_HEADER()

#if __has_feature(attribute_availability_with_replacement)
#if __has_feature(attribute_availability_bridgeos)
  #ifndef __CC_BRIDGE_OS_DEPRECATED
    #define __CC_BRIDGEOS_DEPRECATED(_dep, _msg) __attribute__((availability(bridgeos,deprecated=_dep, replacement=_msg)))
  #endif
#endif

#ifndef __CC_BRIDGEOS_DEPRECATED
  #define __CC_BRIDGEOS_DEPRECATED(_dep, _msg)
#endif

#define cc_deprecate_with_replacement(replacement_message, ios_version, macos_version, tvos_version, watchos_version, bridgeos_version) \
__attribute__((availability(macos,deprecated=macos_version,       replacement=replacement_message)))\
__attribute__((availability(ios,deprecated=ios_version,           replacement=replacement_message)))\
__attribute__((availability(watchos,deprecated=watchos_version,   replacement=replacement_message)))\
__attribute__((availability(tvos,deprecated=tvos_version,         replacement=replacement_message)))\
__CC_BRIDGEOS_DEPRECATED(bridgeos_version, replacement_message)

#define cc_unavailable() \
__attribute__((availability(macos,unavailable)))\
__attribute__((availability(ios,unavailable)))\
__attribute__((availability(watchos,unavailable)))\
__attribute__((availability(tvos,unavailable)))\
__attribute__((availability(bridgeos,unavailable)))

#if CC_PTRCHECK
#define cc_ptrcheck_unavailable() cc_unavailable()
#else
#define cc_ptrcheck_unavailable()
#endif

#else /* !__has_feature(attribute_availability_with_replacement) */

#define cc_deprecate_with_replacement(replacement_message, ios_version, macos_version, tvos_version, watchos_version, bridgeos_version)
#define cc_unavailable()
#define cc_ptrcheck_unavailable()

#endif /* __has_feature(attribute_availability_with_replacement) */

/* Provide a general purpose macro concat method. */
#define cc_concat_(a, b) a##b
#define cc_concat(a, b) cc_concat_(a, b)

#if defined(_MSC_VER)
#define __asm__(x)
#endif

/* Manage asserts here because a few functions in header public files do use asserts */
#if CORECRYPTO_DEBUG
#define cc_assert(x) assert(x)
#else
#define cc_assert(x)
#endif

#if CC_KERNEL
#include <kern/assert.h>
#else
#include <assert.h>
#endif

/* Provide a static assert that can be used to create compile-type failures. */
#if __has_feature(c_static_assert) || __has_extension(c_static_assert)
 #define cc_static_assert(e, m) _Static_assert(e, m)
#elif !defined(__GNUC__)
 #define cc_static_assert(e, m) enum { cc_concat(static_assert_, __COUNTER__) = 1 / (int)(!!(e)) }
#else
 #define cc_static_assert(e, m)
#endif

/* Declare a struct element with a guarenteed alignment of _alignment_.
   The resulting struct can be used to create arrays that are aligned by
   a certain amount.  */
#define cc_aligned_struct(_alignment_)  \
typedef struct { \
uint8_t b[_alignment_]; \
} CC_ALIGNED(_alignment_)

#if defined(__BIGGEST_ALIGNMENT__)
#define CC_MAX_ALIGNMENT ((size_t)__BIGGEST_ALIGNMENT__)
#else
#define CC_MAX_ALIGNMENT ((size_t)16)
#endif

/* pads a given size to be a multiple of the biggest alignment for any type */
#define cc_pad_align(_size_) ((_size_ + CC_MAX_ALIGNMENT - 1) & (~(CC_MAX_ALIGNMENT - 1)))

/* number of array elements used in a cc_ctx_decl */
#define cc_ctx_n(_type_, _size_) ((_size_ + sizeof(_type_) - 1) / sizeof(_type_))

/* sizeof of a context declared with cc_ctx_decl */
#define cc_ctx_sizeof(_type_, _size_) sizeof(_type_[cc_ctx_n(_type_, _size_)])

// VLA warning opt-outs to help transition away from VLAs.
#if defined(__KEIL__)
 #define CC_IGNORE_VLA_WARNINGS \
     #pragma push               \
     #pragma diag_suppress 1057

 #define CC_RESTORE_VLA_WARNINGS \
     #pragma pop
#else
 #define CC_IGNORE_VLA_WARNINGS     \
     _Pragma("GCC diagnostic push") \
     _Pragma("GCC diagnostic ignored \"-Wvla\"")

 #define CC_RESTORE_VLA_WARNINGS \
     _Pragma("GCC diagnostic pop")
#endif

/*
  1. _alloca cannot be removed because this header file is compiled with both MSVC++ and with clang.
  2. The _MSC_VER version of cc_ctx_decl() is not compatible with the way *_decl macros as used in CommonCrypto, AppleKeyStore and SecurityFrameworks. To observe the incompatibilities and errors, use below definition. Corecrypto itself, accepts both definitions
      #define cc_ctx_decl(_type_, _size_, _name_)  _type_ _name_ ## _array[cc_ctx_n(_type_, (_size_))]; _type_ *_name_ = _name_ ## _array
  3. Never use sizeof() operator for the variables declared with cc_ctx_decl(), because it is not be compatible with the _MSC_VER version of cc_ctx_decl().
 */
#if defined(_MSC_VER)

#include <malloc.h>
#define cc_ctx_decl(_type_, _size_, _name_)  _type_ * _name_ = (_type_ *) _alloca(sizeof(_type_) * cc_ctx_n(_type_, _size_) )

#else

// Enable VLA warnings for internal uses of cc_ctx_decl().
#if defined(DISABLE_INTERNAL_VLAS) && DISABLE_INTERNAL_VLAS

#define cc_ctx_decl(_type_, _size_, _name_) \
  _type_ _name_ [cc_ctx_n(_type_, _size_)];

#else

#define cc_ctx_decl(_type_, _size_, _name_) \
  CC_IGNORE_VLA_WARNINGS                    \
  _type_ _name_ [cc_ctx_n(_type_, _size_)]; \
  CC_RESTORE_VLA_WARNINGS

#endif // DISABLE_INTERNAL_VLAS

#endif // defined(_MSC_VER)

#define cc_ctx_decl_field(_type_, _size_, _name_) \
  _type_ _name_ [cc_ctx_n(_type_, _size_)]

// VLA warning opt-outs to help transition away from VLAs.
#define cc_ctx_decl_vla(_type_, _size_, _name_) \
  CC_IGNORE_VLA_WARNINGS                        \
  cc_ctx_decl(_type_, _size_, _name_);          \
  CC_RESTORE_VLA_WARNINGS

/*!
 @brief cc_clear(len, dst) zeroizes array dst and it will not be optimized out.
 @discussion It is used to clear sensitive data, particularly when the are defined in the stack
 @param len number of bytes to be cleared in dst
 @param dst input array
 */
CC_NONNULL((2))
void cc_clear(size_t len, void *cc_sized_by(len) dst);

#define cc_copy(_size_, _dst_, _src_) memcpy(_dst_, _src_, _size_)

CC_INLINE CC_NONNULL((2))
void cc_xor(size_t size, void *cc_sized_by(size) r, const void *cc_sized_by(size) s, const void *cc_sized_by(size) t) {
    uint8_t *_r=(uint8_t *)r;
    const uint8_t *_s=(const uint8_t *)s;
    const uint8_t *_t=(const uint8_t *)t;
    size_t _size = size;
    while (_size--) {
        _r[_size] = _s[_size] ^ _t[_size];
    }
}

/*!
 @brief cc_cmp_safe(num, pt1, pt2) compares two array ptr1 and ptr2 of num bytes.
 @discussion The execution time/cycles is independent of the data and therefore guarantees no leak about the data. However, the execution time depends on num.
 @param num  number of bytes in each array
 @param ptr1 input array
 @param ptr2 input array
 @return  returns 0 if the num bytes starting at ptr1 are identical to the num bytes starting at ptr2 and 1 if they are different or if num is 0 (empty arrays).
 */
CC_NONNULL((2, 3))
int cc_cmp_safe (size_t num, const void * cc_sized_by(num) ptr1, const void * cc_sized_by(num) ptr2);

/* Exchange S and T of any value type.
   NOTE: S and T are evaluated multiple times and MUST NOT be expressions. */
#define CC_SWAP(S, T) do {  \
    S ^= T; T ^= S; S ^= T; \
} while (0)

/* Return the maximum value between S and T. */
#define CC_MAX(S, T) ({__typeof__(S) _cc_max_s = S; __typeof__(T) _cc_max_t = T; _cc_max_s > _cc_max_t ? _cc_max_s : _cc_max_t;})

/* Clone of CC_MAX() that evalutes S and T multiple times to allow nesting. */
#define CC_MAX_EVAL(S, T) ((S) > (T) ? (S) : (T))

/* Return the minimum value between S and T. */
#define CC_MIN(S, T) ({__typeof__(S) _cc_min_s = S; __typeof__(T) _cc_min_t = T; _cc_min_s <= _cc_min_t ? _cc_min_s : _cc_min_t;})

/* Clone of CC_MIN() that evalutes S and T multiple times to allow nesting. */
#define CC_MIN_EVAL(S, T) ((S) < (T) ? (S) : (T))

/*
 When building with "-nostdinc" (i.e. iboot), ptrauth.h is in a non-standard location.
 This requires a new flag to be used when building iboot: -ibuiltininc which is not
 yet available.
*/
#if __has_feature(ptrauth_calls) && (CC_KERNEL || CC_USE_L4 || CC_USE_SEPROM)
#include <ptrauth.h>
#define CC_SPTR(_sn_, _n_) \
    __ptrauth(ptrauth_key_process_independent_code, 1, ptrauth_string_discriminator("cc_" #_sn_ #_n_)) _n_
#else
#define CC_SPTR(_sn_, _n_) _n_
#endif

// Similar to the iovec type used in scatter-gather APIs like readv()
// and writev().
typedef struct cc_iovec {
    const void *base;
    size_t nbytes;
} cc_iovec_t;

// An abstract wrapper around an environment-specified lock
// implementation.
typedef struct cc_lock_ctx cc_lock_ctx_t;

#endif /* _CORECRYPTO_CC_H_ */
