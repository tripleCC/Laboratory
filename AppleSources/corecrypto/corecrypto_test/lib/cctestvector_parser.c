/* Copyright (c) (2018-2020,2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <corecrypto/cc_priv.h>

#include "testmore.h"
#include "cc_macros.h"
#include "cctestvector_parser.h"
#include "ccdict.h"
#include "yajl_common.h"
#include "yajl_parse.h"

struct cctestvector_parser {
    void *context;
    void *(*init)(cctest_driver_t driver);
    void (*release)(void *context);
    yajl_handle handle;
    yajl_callbacks callbacks;
};

#define FLAG_ConstructedIv "ConstructedIv"
#define FLAG_ZeroLengthIv "ZeroLengthIv"
#define FLAG_AddSubChain "AddSubChain"
#define FLAG_CVE_2017_10176 "CVE_2017_10176"
#define FLAG_CompressedPoint "CompressedPoint"
#define FLAG_GroupIsomorphism "GroupIsomorphism"
#define FLAG_InvalidPublic "InvalidPublic"
#define FLAG_IsomorphicPublicKey "IsomorphicPublicKey"
#define FLAG_ModifiedPrime "ModifiedPrime"
#define FLAG_UnnamedCurve "UnnamedCurve"
#define FLAG_UnusedParam "UnusedParam"
#define FLAG_WeakPublicKey "WeakPublicKey"
#define FLAG_WrongOrder "WrongOrder"
#define FLAG_BER "BER"
#define FLAG_EdgeCase "EdgeCase"
#define FLAG_MissingZero "MissingZero"
#define FLAG_PointDuplication "PointDuplication"
#define FLAG_WeakHash "WeakHash"
#define FLAG_MissingNull "MissingNull"
#define FLAG_SmallModulus "SmallModulus"
#define FLAG_SmallPublicKey "SmallPublicKey"
#define FLAG_SignatureMalleability "SignatureMalleability"
#define FLAG_NegativeOfPrime "NegativeOfPrime"
#define FLAG_ZeroSharedSecret "ZeroSharedSecret"
#define FLAG_LowOrderPublic "LowOrderPublic"

struct flag_mapping {
    const char *flag_name;
    wycheproof_flag_t flag_enum;
};

#define FLAG_MAP_ENTRY(NAME) \
    { .flag_name = FLAG_##NAME, .flag_enum = wycheproof_flag_##NAME }

static const struct flag_mapping flag_mappings[] = {
    FLAG_MAP_ENTRY(ConstructedIv),
    FLAG_MAP_ENTRY(ZeroLengthIv),
    FLAG_MAP_ENTRY(AddSubChain),
    FLAG_MAP_ENTRY(CVE_2017_10176),
    FLAG_MAP_ENTRY(CompressedPoint),
    FLAG_MAP_ENTRY(GroupIsomorphism),
    FLAG_MAP_ENTRY(InvalidPublic),
    FLAG_MAP_ENTRY(IsomorphicPublicKey),
    FLAG_MAP_ENTRY(ModifiedPrime),
    FLAG_MAP_ENTRY(UnnamedCurve),
    FLAG_MAP_ENTRY(UnusedParam),
    FLAG_MAP_ENTRY(WeakPublicKey),
    FLAG_MAP_ENTRY(WrongOrder),
    FLAG_MAP_ENTRY(BER),
    FLAG_MAP_ENTRY(EdgeCase),
    FLAG_MAP_ENTRY(MissingZero),
    FLAG_MAP_ENTRY(PointDuplication),
    FLAG_MAP_ENTRY(WeakHash),
    FLAG_MAP_ENTRY(MissingNull),
    FLAG_MAP_ENTRY(SmallModulus),
    FLAG_MAP_ENTRY(SmallPublicKey),
    FLAG_MAP_ENTRY(SignatureMalleability),
    FLAG_MAP_ENTRY(NegativeOfPrime),
    FLAG_MAP_ENTRY(ZeroSharedSecret),
    FLAG_MAP_ENTRY(LowOrderPublic),
};

static const size_t num_flags = CC_ARRAY_LEN(flag_mappings);

#define KEY_ALGORITHM "algorithm"
#define KEY_IV_SIZE "ivsize"
#define KEY_KEY_SIZE "keysize"
#define KEY_TAG_SIZE "tagsize"
#define KEY_COMMENT "comment"
#define KEY_ID "tcid"
#define KEY_TYPE "type"
#define KEY_VALUE "value"
#define KEY_KEY "key"
#define KEY_KEY_DER "keyder"
#define KEY_RSA_MODULUS "n"
#define KEY_IV "iv"
#define KEY_AAD "aad"
#define KEY_MSG "msg"
#define KEY_CT "ct"
#define KEY_TAG "tag"
#define KEY_CURVE "curve"
#define KEY_PUBLIC "public"
#define KEY_PRIVATE "private"
#define KEY_PRIVATE_KEY_PKCS8 "privatekeypkcs8"
#define KEY_SHARED "shared"
#define KEY_SIGNATURE "sig"
#define KEY_PADDING "padding"
#define KEY_VALID "result"
#define KEY_SHA "sha"
#define KEY_MGF_SHA "mgfsha"
#define KEY_RSA_PUBLICKEY "e"
#define KEY_FLAGS "flags"
#define KEY_LABEL "label"
#define KEY_SALT_SIZE "slen"
#define KEY_PK "pk"
#define KEY_SK "sk"

const char *cctestvector_key_algorithm = KEY_ALGORITHM;
const char *cctestvector_key_iv_size = KEY_IV_SIZE;
const char *cctestvector_key_key_size = KEY_KEY_SIZE;
const char *cctestvector_key_tag_size = KEY_TAG_SIZE;
const char *cctestvector_key_comment = KEY_COMMENT;
const char *cctestvector_key_id = KEY_ID;
const char *cctestvector_key_type = KEY_TYPE;
const char *cctestvector_key_value = KEY_VALUE;
const char *cctestvector_key_key = KEY_KEY;
const char *cctestvector_key_key_der = KEY_KEY_DER;
const char *cctestvector_key_iv = KEY_IV;
const char *cctestvector_key_aad = KEY_AAD;
const char *cctestvector_key_msg = KEY_MSG;
const char *cctestvector_key_ct = KEY_CT;
const char *cctestvector_key_tag = KEY_TAG;
const char *cctestvector_key_curve = KEY_CURVE;
const char *cctestvector_key_rsa_modulus = KEY_RSA_MODULUS;
const char *cctestvector_key_rsa_public_key = KEY_RSA_PUBLICKEY;
const char *cctestvector_key_public = KEY_PUBLIC;
const char *cctestvector_key_private = KEY_PRIVATE;
const char *cctestvector_key_private_key_pkcs8 = KEY_PRIVATE_KEY_PKCS8;
const char *cctestvector_key_shared = KEY_SHARED;
const char *cctestvector_key_signature = KEY_SIGNATURE;
const char *cctestvector_key_valid = KEY_VALID;
const char *cctestvector_key_sha = KEY_SHA;
const char *cctestvector_key_mgf_sha = KEY_MGF_SHA;
const char *cctestvector_key_padding = KEY_PADDING;
const char *cctestvector_key_flags = KEY_FLAGS;
const char *cctestvector_key_label = KEY_LABEL;
const char *cctestvector_key_salt_size = KEY_SALT_SIZE;
const char *cctestvector_key_pk = KEY_PK;
const char *cctestvector_key_sk = KEY_SK;

struct wycheproof_result {
    ccdict_t values;
    struct wycheproof_result *outer;
};

struct wycheproof_context {
    cctestvector_parser_t parser;
    const char *family;
    cctest_driver_t driver;
    const char *key;
    const char *array_key;
    const char *map_key;
    ccdict_entry_type_t key_type;
    struct wycheproof_result *result;
};

struct key_info {
    ccdict_entry_type_t key_type;
    const char *key;
};

static const struct key_info keys[] = {
    {
        .key_type = ccdict_entry_type_value, .key = KEY_ALGORITHM,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_IV_SIZE,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_KEY_SIZE,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_TAG_SIZE,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_CURVE,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_PK,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_SK,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_KEY_DER,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_RSA_MODULUS,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_RSA_PUBLICKEY,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_SHA,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_MGF_SHA,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_COMMENT,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_ID,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_TYPE,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_VALUE,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_KEY,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_IV,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_AAD,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_MSG,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_CT,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_TAG,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_VALID,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_PUBLIC,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_PADDING,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_PRIVATE,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_PRIVATE_KEY_PKCS8,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_SHARED,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_SIGNATURE,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_LABEL,
    },
    {
        .key_type = ccdict_entry_type_value, .key = KEY_SALT_SIZE,
    },
    {
        .key_type = ccdict_entry_type_flags, .key = KEY_FLAGS,
    }
};
static const size_t num_keys = CC_ARRAY_LEN(keys);

static int
wycheproof_parser_on_null(void *ctx)
{
    struct wycheproof_context *context = (struct wycheproof_context *)ctx;

    if (context->key == NULL) {
        // Do not attempt to parse unhandled keys
        return 1;
    }

    // Reset the state
    context->key = NULL;

    return 1;
}

static void
wycheproof_parser_insert_flag(struct wycheproof_context *context, uint64_t value)
{
     ccdict_put_flag_value(context->result->values, context->array_key, value);
}

static void
wycheproof_parser_insert_uint64(struct wycheproof_context *context, uint64_t value)
{
    ccdict_put_uint64(context->result->values, context->key, value);
}

static void
wycheproof_parser_insert_value(struct wycheproof_context *context, const unsigned char *value, size_t len)
{
    ccdict_put_value(context->result->values, context->key, value, len);
}

static int
wycheproof_parser_on_boolean(void *ctx, int value)
{
    struct wycheproof_context *context = (struct wycheproof_context *)ctx;

    if (context->key == NULL) {
        // Do not attempt to parse unhandled keys
        return 1;
    }

    wycheproof_parser_insert_uint64(context, (uint64_t)value);
    context->key = NULL;

    return 1;
}

static int
wycheproof_parser_on_number(void * ctx, const char *number, size_t number_len)
{
    struct wycheproof_context *context = (struct wycheproof_context *)ctx;

    if (context->key == NULL) {
        // Do not attempt to parse unhandled keys
        return 1;
    }

    wycheproof_parser_insert_value(context, (const uint8_t *)number, number_len);
    context->key = NULL;

    return 1;
}

static struct wycheproof_result *
wycheproof_result_create(struct wycheproof_result *outer)
{
    struct wycheproof_result *result = (struct wycheproof_result *)malloc(sizeof(struct wycheproof_result));
    result->values = ccdict_create();
    result->outer = outer;
    return result;
}

static struct wycheproof_result *
wycheproof_result_release(struct wycheproof_result *result)
{
    struct wycheproof_result *outer = result->outer;
    ccdict_release(&result->values);
    free(result);

    return outer;
}

static int
wycheproof_parser_start_map(void *ctx)
{
    struct wycheproof_context *context = (struct wycheproof_context *)ctx;
    context->map_key = context->key;
    context->result = wycheproof_result_create(context->result);
    return 1;
}

static void
wycheproof_parser_merge_dict(ccdict_t dst, const ccdict_t src)
{
    for (size_t i = 0; i < num_keys; i++) {
        const struct key_info ki = keys[i];

        // Don't override existing values.
        if (ccdict_contains_key(dst, ki.key)) {
            continue;
        }

        // Skip undefined keys.
        if (!ccdict_contains_key(src, ki.key)) {
            continue;
        }

        if (ki.key_type == ccdict_entry_type_value) {
            size_t value_len = 0;
            const void *value = ccdict_get_value(src, ki.key, &value_len);
            ccdict_put_value(dst, ki.key, value, value_len);
        } else if (ki.key_type == ccdict_entry_type_int64) {
            int64_t value = ccdict_get_int64(src, ki.key);
            ccdict_put_int64(dst, ki.key, value);
        } else if (ki.key_type == ccdict_entry_type_uint64) {
            uint64_t value = ccdict_get_uint64(src, ki.key);
            ccdict_put_uint64(dst, ki.key, value);
        }
    }
}

static int
wycheproof_parser_end_map(void *ctx)
{
    struct wycheproof_context *context = (struct wycheproof_context *)ctx;
    struct wycheproof_result *outer = context->result->outer;
    ccdict_t values = context->result->values;

    while (outer) {
        wycheproof_parser_merge_dict(values, outer->values);
        outer = outer->outer;
    }

    // Add the vector to the running set, and then create a new one
    if (context->driver != NULL &&
        cctest_driver_can_run(context->driver, values) &&
        ccdict_contains_key(values, cctestvector_key_id)) {

        size_t td_id_len = 0;
        const char *td_id = ccdict_get_value(values, cctestvector_key_id, &td_id_len);
        char *id = (char *)malloc(td_id_len + 1);
        memset(id, 0, td_id_len + 1);
        memcpy(id, td_id, td_id_len);
        (void)cctest_driver_run(context->driver, values);
        free(id);
    } else {
        // If the map is not a test vector, merge the values we found with the
        // values from the outer context. That's useful, e.g., for "key" maps
        // that specify key attributes for a whole test group.
        struct wycheproof_result *outer = context->result->outer;
        if (outer && context->map_key && strcmp("key", context->map_key) == 0) {
            wycheproof_parser_merge_dict(outer->values, values);
        }
    }

    // Pop the current result and release it.
    context->result = wycheproof_result_release(context->result);
    context->map_key = NULL;

    return 1;
}

static int
wycheproof_parser_start_array(void *ctx)
{
    struct wycheproof_context *context = (struct wycheproof_context *)ctx;
    if (context->key == NULL) {
        // Do not attempt to parse unhandled keys
        return 1;
    }
    context->array_key = context->key;
    ccdict_create_flag_entry(context->result->values, context->array_key);

    return 1;
}

static int
wycheproof_parser_end_array(void *ctx)
{
    struct wycheproof_context *context = (struct wycheproof_context *)ctx;
    context->array_key = NULL;
    return 1;
}

static int
wycheproof_parser_on_string(void *ctx, const unsigned char *value, size_t len)
{
    struct wycheproof_context *context = (struct wycheproof_context *)ctx;

    // Special case when we are parsing an array of flags
    if (context->array_key != NULL) {
        for (size_t i = 0; i < num_flags; i++) {
            struct flag_mapping fm = flag_mappings[i];
            if (len == strlen(fm.flag_name) && 0 == memcmp(fm.flag_name, value, len)) {
                wycheproof_parser_insert_flag(context, fm.flag_enum);
            }
        }
    }

    if (context->key == NULL) {
        // Do not attempt to parse unhandled keys
        return 1;
    }

    // We have to special-case certain Wycheproof keys
    if (strcmp(context->key, cctestvector_key_valid) == 0) {
        if (strncmp((const char *)value, "valid", strlen("valid")) == 0) {
            wycheproof_parser_insert_uint64(context, cctestvector_result_valid);
        } else if (strncmp((const char *)value, "acceptable", strlen("acceptable")) == 0) {
            wycheproof_parser_insert_uint64(context, cctestvector_result_acceptable);
        } else {
            wycheproof_parser_insert_uint64(context, cctestvector_result_invalid);
        }
        context->key = NULL;
        return 1;
    }

    wycheproof_parser_insert_value(context, value, len);
    context->key = NULL;

    return 1;
}

static int wycheproof_parser_map_key(void * ctx, const unsigned char *key, size_t len)
{
    struct wycheproof_context *context = (struct wycheproof_context *)ctx;
    context->key = NULL;

    for (size_t i = 0; i < num_keys; i++) {
        struct key_info ki = keys[i];

        if (len == strlen(ki.key) && strncasecmp((const char *)key, ki.key, len) == 0) {
            context->key = ki.key;
            break;
        }
    }

    return 1;
}

static void *
wycheproof_parser_init(cctest_driver_t driver)
{
    struct wycheproof_context *context = (struct wycheproof_context *)calloc(1, sizeof(struct wycheproof_context));
    if (context != NULL) {
        context->driver = driver;
        context->result = wycheproof_result_create(NULL);
    }
    return context;
}

static void
wycheproof_parser_release(void *opaque_context)
{
    struct wycheproof_context *context = (struct wycheproof_context *)opaque_context;
    if (context != NULL) {
        while (context->result) {
            context->result = wycheproof_result_release(context->result);
        }

        free(context);
    }
}

static struct cctestvector_parser wycheproof_parser = {
    .context = NULL,
    .init = wycheproof_parser_init,
    .release = wycheproof_parser_release,
    .callbacks = {
        .yajl_null = wycheproof_parser_on_null,
        .yajl_boolean = wycheproof_parser_on_boolean,
        .yajl_integer = NULL,
        .yajl_double = NULL,
        .yajl_number = wycheproof_parser_on_number,
        .yajl_map_key = wycheproof_parser_map_key,
        .yajl_string = wycheproof_parser_on_string,
        .yajl_start_map = wycheproof_parser_start_map,
        .yajl_end_map = wycheproof_parser_end_map,
        .yajl_start_array = wycheproof_parser_start_array,
        .yajl_end_array = wycheproof_parser_end_array,
    },
};

cctestvector_parser_t
cctestvector_parser_from_family(const char *algorithm)
{
    if (strcmp("wycheproof", algorithm) == 0) {
        return &wycheproof_parser;
    }
    return NULL;
}

int cctestvector_parser_parse(cctestvector_parser_t parser,
                              const uint8_t *vector_buffer,
                              size_t vector_buffer_len,
                              cctest_driver_t driver)
{
    static size_t stash_size = 1024;
    yajl_status status = yajl_status_error;

    parser->context = parser->init(driver);
    parser->handle = yajl_alloc(&(parser->callbacks), NULL, parser->context);

    for (size_t j = 0; j < vector_buffer_len; j += stash_size) {
        size_t read_count = CC_MIN(vector_buffer_len - j, stash_size);
        status = yajl_parse(parser->handle, vector_buffer + j, read_count);
        cc_require(status == yajl_status_ok, errOut);
    }

errOut:
    parser->release(parser->context);

    if (status == yajl_status_ok) {
        status = yajl_complete_parse(parser->handle);
    }

    yajl_free(parser->handle);

    if (status == yajl_status_ok) {
        return CCERR_OK;
    }

    return CCERR_INTERNAL;
}
