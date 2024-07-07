/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef ccdict_h
#define ccdict_h

#include <stdbool.h>
#include <corecrypto/cc.h>

/*!
 * @abstract Opaque dictionary (associative array) type.
 */
typedef struct ccdict *ccdict_t;

/*!
 * @enum ccdict_entry_type_t
 * @abstract Types of values that may be stored by the dictionary.
 */
typedef enum {
    ccdict_entry_type_int64,
    ccdict_entry_type_uint64,
    ccdict_entry_type_value,
    ccdict_entry_type_flags,
} ccdict_entry_type_t;

/*!
 * @function ccdict_create
 * @abstract Create an empty `ccdict_t`.
 * @return A newly allocated `ccdict_t` that must be released with `ccdict_release`.
 */
ccdict_t
ccdict_create(void);

/*!
 * @function ccdict_release
 * @abstract Release a `ccdict_t` and all its contents.
 * @param dict A pointer to a `ccdict_t` instance.
 */
CC_NONNULL((1))
void
ccdict_release(ccdict_t *dict);

/*!
 * @function ccdict_print
 * @abstract Display the contents of a `ccdict_t` instance on stdout.
 * @param dict A pointer to a `ccdict_t` instance.
 * @param indentation Number of spaces to indent contents of this dictionary.
 */
CC_NONNULL((1))
void
ccdict_print(const ccdict_t dict, size_t indentation);

/*!
 * @function ccdict_create_flag_entry
 * @abstract Create an entry to store flags within the dictionary.
 * @param dict A `ccdict_t` instance.
 * @param key A NULL-terminated C string that contains the entry key.
 */
CC_NONNULL((1,2))
void ccdict_create_flag_entry(ccdict_t dict, const char *key);

/*!
 * @function ccdict_put_flag_value
 * @abstract Place a flag into the dictionary.
 * @param dict A `ccdict_t` instance.
 * @param key A NULL-terminated C string that contains the entry key.
 */
CC_NONNULL((1,2))
void ccdict_put_flag_value(ccdict_t dict, const char *key, uint64_t value);

/*!
 * @function ccdict_put_value
 * @abstract Copy a value into the dictionary.
 * @param dict A `ccdict_t` instance.
 * @param key A NULL-terminated C string that contains the entry key.
 * @param value Pointer to a value associated with the key.
 * @param value_len Length of `value`.
 */
CC_NONNULL((1,2,3))
void
ccdict_put_value(ccdict_t dict, const char *key, const void *value, size_t value_len);

/*!
 * @function ccdict_put_int64
 * @abstract Copy a int64_t into the dictionary.
 * @param dict A `ccdict_t` instance.
 * @param key A NULL-terminated C string that contains the entry key.
 * @param value An int64_t value.
 */
CC_NONNULL((1,2))
void
ccdict_put_int64(ccdict_t dict, const char *key, int64_t value);

/*!
 * @function ccdict_put_uint64
 * @abstract Copy a uint64_t into the dictionary.
 * @param dict A `ccdict_t` instance.
 * @param key A NULL-terminated C string that contains the entry key.
 * @param value An uint64_t value.
 */
CC_NONNULL((1,2))
void
ccdict_put_uint64(ccdict_t dict, const char *key, uint64_t value);

/*!
 * @function ccdict_contains_key
 * @abstract Returns whether the given key exists in the dictionary.
 * @param dict A `ccdict_t` instance.
 * @param key A NULL-terminated C string that contains the entry key.
 * @return true if the given key exists in the dictionary, false otherwise
 */
CC_NONNULL_ALL
bool
ccdict_contains_key(ccdict_t dict, const char *key);

/*!
 * @function ccdict_get_flags
 * @abstract Get the flags from the dictionary.
 * @param dict A `ccdict_t` instance.
 * @param key A NULL-terminated C string that contains the entry key.
 */
const uint64_t ccdict_get_flags(const ccdict_t dict, const char *key);

/*!
 * @function ccdict_get_value
 * @abstract Return the value associated with a key in the dictionary.
 * @param dict A `ccdict_t` instance.
 * @param key A NULL-terminated C string that contains the entry key.
 * @param value_len Pointer to storage for the length of the returned value.
 * @return Pointer to the value associated with the key `key`, or NULL if no such value exists.
 */
CC_NONNULL((1,2,3))
const void *
ccdict_get_value(const ccdict_t dict, const char *key, size_t *value_len);

/*!
 * @function ccdict_get_int64
 * @abstract Return the int64_t value associated with a key in the dictionary.
 * @param dict A `ccdict_t` instance.
 * @param key A NULL-terminated C string that contains the entry key.
 * @return int64_t value associated with the key `key`, or 0 if no such value exists.
 */
CC_NONNULL((1,2))
const int64_t
ccdict_get_int64(const ccdict_t dict, const char *key);

/*!
 * @function ccdict_get_uint64
 * @abstract Return the uint64_t value associated with a key in the dictionary.
 * @param dict A `ccdict_t` instance.
 * @param key A NULL-terminated C string that contains the entry key.
 * @return uint64_t value associated with the key `key`, or 0 if no such value exists.
 */
CC_NONNULL((1,2))
const uint64_t
ccdict_get_uint64(const ccdict_t dict, const char *key);

#endif /* ccdict_h */
