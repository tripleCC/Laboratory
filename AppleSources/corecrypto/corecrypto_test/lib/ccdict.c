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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <corecrypto/cc_priv.h>

#include "ccdict.h"

struct ccdict_entry {
    ccdict_entry_type_t type;
    char *key;
    struct ccdict_entry *next;
    void *value;
    size_t value_len;
    int64_t int_value;
    uint64_t uint_value;
};

CC_NONNULL((1))
static struct ccdict_entry *ccdict_entry_create_value(const char *key, const void *value, size_t value_len)
{
    struct ccdict_entry *entry = (struct ccdict_entry *)calloc(1, sizeof(struct ccdict_entry));
    if (entry != NULL) {
        entry->key = strdup(key);
        entry->value = (void *)malloc(value_len);
        entry->value_len = value_len;
        entry->type = ccdict_entry_type_value;
        if (entry->value) {
            memcpy(entry->value, value, value_len);
        } else {
            free(entry);
            return NULL;
        }
    }

    return entry;
}

CC_NONNULL((1))
static struct ccdict_entry *ccdict_entry_create_int64(const char *key, int64_t value)
{
    struct ccdict_entry *entry = (struct ccdict_entry *)calloc(1, sizeof(struct ccdict_entry));
    if (entry != NULL) {
        entry->key = strdup(key);
        entry->int_value = value;
        entry->type = ccdict_entry_type_int64;
    }

    return entry;
}

CC_NONNULL((1))
static struct ccdict_entry *ccdict_entry_create_uint64(const char *key, uint64_t value)
{
    struct ccdict_entry *entry = (struct ccdict_entry *)calloc(1, sizeof(struct ccdict_entry));
    if (entry != NULL) {
        entry->key = strdup(key);
        entry->uint_value = value;
        entry->type = ccdict_entry_type_uint64;
    }

    return entry;
}

CC_NONNULL((1))
static struct ccdict_entry *ccdict_entry_create_flag_array(const char *key)
{
    return ccdict_entry_create_uint64(key, 0);
}

CC_NONNULL((1))
static void ccdict_entry_release(struct ccdict_entry **entryP)
{
    if (*entryP == NULL) {
        cc_try_abort("dictionary entry pointer or referenced entry cannot be NULL");
        return;
    }

    free((*entryP)->value);
    free((void *)(*entryP)->key);
    cc_clear(sizeof(struct ccdict_entry), *entryP);

    free(*entryP);
    *entryP = NULL;
}

CC_NONNULL((1))
static void ccdict_entry_display(const struct ccdict_entry *entry, size_t indentation)
{
    for (size_t i = 0; i < indentation; i++) {
        printf(" ");
    }

    printf("\"%s\" : ", entry->key);

    switch (entry->type) {
    case ccdict_entry_type_int64: {
        printf("%lld,", (int64_t)entry->int_value);
        break;
    }
    case ccdict_entry_type_uint64: {
        printf("%llu,", (uint64_t)entry->uint_value);
        break;
    }
    case ccdict_entry_type_value: {
        printf("\"");
        for (size_t i = 0; i < entry->value_len; i++) {
            printf("%c", ((char *)entry->value)[i]);
        }
        printf("\",");
        break;
    }
    case ccdict_entry_type_flags: {
        printf("%llu,", (uint64_t)entry->uint_value);
        break;
    }
    }

    printf("\n");
}

CC_NONNULL((1, 2))
static bool ccdict_entry_matches(const struct ccdict_entry *entry, const char *key)
{
    return 0 == strcmp(entry->key, key);
}

CC_NONNULL((1))
static const void *ccdict_entry_get_value(const struct ccdict_entry *entry)
{
    return entry->value;
}

CC_NONNULL((1))
static size_t ccdict_entry_get_value_len(const struct ccdict_entry *entry)
{
    return entry->value_len;
}

CC_NONNULL((1))
static int64_t ccdict_entry_get_int64(const struct ccdict_entry *entry)
{
    return entry->int_value;
}

CC_NONNULL((1))
static uint64_t ccdict_entry_get_uint64(const struct ccdict_entry *entry)
{
    return entry->uint_value;
}

CC_NONNULL((1, 2))
static void ccdict_entry_set_value(struct ccdict_entry *entry, const void *value, size_t value_len)
{
    if (entry->value != NULL) {
        free(entry->value);
    }

    entry->value = (void *)malloc(value_len);
    if (entry->value != NULL) {
        entry->value_len = value_len;
        memcpy(entry->value, value, value_len);
    } else {
        entry->value_len = 0;
    }
}

CC_NONNULL((1))
static void ccdict_entry_set_int64(struct ccdict_entry *entry, int64_t value)
{
    entry->int_value = value;
}

CC_NONNULL((1))
static void ccdict_entry_set_uint64(struct ccdict_entry *entry, uint64_t value)
{
    entry->uint_value = value;
}

struct ccdict {
    struct ccdict_entry *head;
};

ccdict_t ccdict_create(void)
{
    return (ccdict_t)calloc(1, sizeof(struct ccdict));
}

void ccdict_release(ccdict_t *dict)
{
    struct ccdict_entry *current = (*dict)->head;
    while (current != NULL) {
        struct ccdict_entry *next = current->next;
        ccdict_entry_release(&current);
        current = next;
    }

    free(*dict);
    *dict = NULL;
}

void ccdict_print(const ccdict_t dict, size_t indentation)
{
    for (size_t i = 0; i < indentation; i++) {
        printf(" ");
    }
    printf("{\n");

    struct ccdict_entry *entry = dict->head;
    while (entry != NULL) {
        ccdict_entry_display(entry, indentation + 2);
        entry = entry->next;
    }

    for (size_t i = 0; i < indentation; i++) {
        printf(" ");
    }
    printf("}\n");
}

void ccdict_create_flag_entry(ccdict_t dict, const char *key)
{
    struct ccdict_entry *previous = NULL;
    struct ccdict_entry *current = dict->head;
    if (current == NULL) {
        dict->head = ccdict_entry_create_flag_array(key);
        return;
    }

    while (current != NULL) {
        previous = current;
        current = current->next;
    }

    struct ccdict_entry *new_entry = ccdict_entry_create_flag_array(key);
    previous->next = new_entry;
}

void ccdict_put_flag_value(ccdict_t dict, const char *key, uint64_t value)
{
    struct ccdict_entry *current = dict->head;
    if (current == NULL) {
        // We should have already created the array
        cc_assert(1 == 2);
    }

    while (current != NULL) {
        if (ccdict_entry_matches(current, key)) {
            current->uint_value |= value;
            return;
        }
        current = current->next;
    }

    cc_assert(2 == 3);
}

void ccdict_put_value(ccdict_t dict, const char *key, const void *value, size_t value_len)
{
    struct ccdict_entry *previous = NULL;
    struct ccdict_entry *current = dict->head;
    if (current == NULL) {
        dict->head = ccdict_entry_create_value(key, value, value_len);
        return;
    }

    while (current != NULL) {
        if (ccdict_entry_matches(current, key)) {
            ccdict_entry_set_value(current, value, value_len);
            return;
        }
        previous = current;
        current = current->next;
    }

    struct ccdict_entry *new_entry = ccdict_entry_create_value(key, value, value_len);
    previous->next = new_entry;
}

void ccdict_put_int64(ccdict_t dict, const char *key, int64_t value)
{
    struct ccdict_entry *previous = NULL;
    struct ccdict_entry *current = dict->head;
    if (current == NULL) {
        dict->head = ccdict_entry_create_int64(key, value);
        return;
    }

    while (current != NULL) {
        if (ccdict_entry_matches(current, key)) {
            ccdict_entry_set_int64(current, value);
            return;
        }
        previous = current;
        current = current->next;
    }

    struct ccdict_entry *new_entry = ccdict_entry_create_int64(key, value);
    previous->next = new_entry;
}

void ccdict_put_uint64(ccdict_t dict, const char *key, uint64_t value)
{
    struct ccdict_entry *previous = NULL;
    struct ccdict_entry *current = dict->head;
    if (current == NULL) {
        dict->head = ccdict_entry_create_uint64(key, value);
        return;
    }

    while (current != NULL) {
        if (ccdict_entry_matches(current, key)) {
            ccdict_entry_set_uint64(current, value);
            return;
        }
        previous = current;
        current = current->next;
    }

    struct ccdict_entry *new_entry = ccdict_entry_create_uint64(key, value);
    previous->next = new_entry;
}

bool ccdict_contains_key(ccdict_t dict, const char *key)
{
    struct ccdict_entry *current = dict->head;

    while (current != NULL) {
        if (ccdict_entry_matches(current, key)) {
            return true;
        }
        current = current->next;
    }

    return false;
}

const uint64_t ccdict_get_flags(const ccdict_t dict, const char *key)
{
    struct ccdict_entry *current = dict->head;
    while (current != NULL) {
        if (ccdict_entry_matches(current, key)) {
            return ccdict_entry_get_uint64(current);
        }
        current = current->next;
    }

    return 0;
}

const void *ccdict_get_value(const ccdict_t dict, const char *key, size_t *value_len)
{
    *value_len = 0;

    struct ccdict_entry *current = dict->head;
    while (current != NULL) {
        if (ccdict_entry_matches(current, key)) {
            *value_len = ccdict_entry_get_value_len(current);
            return ccdict_entry_get_value(current);
        }
        current = current->next;
    }

    return NULL;
}

const int64_t ccdict_get_int64(const ccdict_t dict, const char *key)
{
    struct ccdict_entry *current = dict->head;
    while (current != NULL) {
        if (ccdict_entry_matches(current, key)) {
            return ccdict_entry_get_int64(current);
        }
        current = current->next;
    }

    return 0;
}

const uint64_t ccdict_get_uint64(const ccdict_t dict, const char *key)
{
    struct ccdict_entry *current = dict->head;
    while (current != NULL) {
        if (ccdict_entry_matches(current, key)) {
            return ccdict_entry_get_uint64(current);
        }
        current = current->next;
    }

    return 0;
}
