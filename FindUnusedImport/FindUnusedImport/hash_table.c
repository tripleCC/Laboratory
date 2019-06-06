//
//  hash.c
//  FindUnusedImport
//
//  Created by tripleCC on 6/6/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "hash_table.h"

static const unsigned int g_hash_table_node_number = 512;
static const unsigned int g_hash_table_probing_length = 8;

struct fui_hash_node {
    const char *key;
    void *value;
    bool busy;
};

struct fui_hash_table {
    unsigned int max_number;
    unsigned int cur_number;
    struct fui_hash_node *nodes;
};

static bool
fui_hash_table_full(fui_hash_table_ref t) {
    return t->max_number / 2 < t->cur_number;
}

// http://www.cse.yorku.ca/~oz/hash.html
// djb2
static unsigned long
fui_hash(const char *str) {
    unsigned long hash = 5381;
    char ch;
    
    while ((ch = *str++))
        hash = ((hash << 5) + hash) + ch; /* hash * 33 + ch */
    
    return hash;
}

static unsigned int
fui_hash_index_in_theory(fui_hash_table_ref t, const char *key) {
    return fui_hash(key) % t->max_number;
}

static int
fui_hash_index(fui_hash_table_ref t, const char *key) {
    if (fui_hash_table_full(t)) return FUI_TABLE_FULL;
    
    int index = fui_hash_index_in_theory(t, key);
    for (int i = 0; i < g_hash_table_probing_length; i++) {
        struct fui_hash_node node = t->nodes[index];
        if (!node.busy || (node.busy && !strcmp(node.key, key)))
            return index;
        index = (index + 1) % t->max_number;
    }
    
    return FUI_TABLE_FULL;
}

static fui_table_operate_status
fui_hash_table_resize(fui_hash_table_ref t) {
    unsigned int old_number = t->max_number;
    unsigned int new_number = 2 * old_number;
    
    struct fui_hash_node *old_nodes = t->nodes;
    struct fui_hash_node *new_nodes = calloc(new_number, sizeof(struct fui_hash_node));
    if (!new_nodes) return FUI_TABLE_OUT_OF_MEMORY;
    
    t->nodes = new_nodes;
    t->max_number = new_number;
    if (old_nodes) {
        struct fui_hash_node *node;
        struct fui_hash_node *end_node = old_nodes + old_number;
        for (node = old_nodes; node < end_node; node++) {
            if (!node->busy) continue;
            fui_table_operate_status status = fui_hash_table_add(t, node->key, node->value);
            if (status != FUI_TABLE_SUCCESS) return status;
        }
        free(old_nodes);
    }
    
    return FUI_TABLE_SUCCESS;
}

void
fui_hash_table_free(fui_hash_table_ref t) {
    free(t->nodes);
    free(t);
}

fui_hash_table_ref
fui_hash_table_allocate(void) {
    fui_hash_table_ref t = malloc(sizeof(struct fui_hash_table));
    if (!t) goto fail;
    
    t->nodes = calloc(g_hash_table_node_number, sizeof(struct fui_hash_node));
    if (!t->nodes) goto fail;
    
    t->max_number = g_hash_table_node_number;
    t->cur_number = 0;
    
    return t;
    
fail:
    if (t) fui_hash_table_free(t);
    return NULL;
}

fui_table_operate_status
fui_hash_table_add(fui_hash_table_ref t, const char *key, void *value) {
    unsigned index = fui_hash_index(t, key);
    while (index == FUI_TABLE_FULL) {
        if (fui_hash_table_resize(t) == FUI_TABLE_OUT_OF_MEMORY)
            return FUI_TABLE_OUT_OF_MEMORY;
        index = fui_hash_index(t, key);
    }
    
    struct fui_hash_node *node = &t->nodes[index];
    if (!node->busy) t->cur_number++;
    node->value = value;
    node->key = key;
    node->busy = true;
    
    return FUI_TABLE_SUCCESS;
}

fui_table_operate_status
fui_hash_table_get(fui_hash_table_ref t, const char *key, void **value) {
    unsigned int index = fui_hash_index_in_theory(t, key);
    for (int i = 0; i < g_hash_table_probing_length; i++) {
        struct fui_hash_node node = t->nodes[index];
        if (node.busy && !strcmp(node.key, key)) {
            if (value) *value = t->nodes[index].value;
            return FUI_TABLE_SUCCESS;
        }
        index = (index + 1) % t->max_number;
    }
    
    if (value) *value = NULL;
    
    return FUI_TABLE_MISSING;
}

fui_table_operate_status
fui_hash_table_remove(fui_hash_table_ref t, const char *key) {
    unsigned int index = fui_hash_index_in_theory(t, key);
    for (int i = 0; i < g_hash_table_probing_length; i++) {
        struct fui_hash_node node = t->nodes[index];
        if (node.busy && !strcmp(node.key, key)) {
            node.busy = false;
            node.key = NULL;
            node.value = NULL;
            t->cur_number--;
            
            return FUI_TABLE_SUCCESS;
        }
        index = (index + 1) % t->max_number;
    }
    
    return FUI_TABLE_MISSING;
}

unsigned int
fui_hash_table_get_number(fui_hash_table_ref t) {
    return t->max_number;
}

void
fui_hash_table_foreach(fui_hash_table_ref t, fui_hash_table_foreach_func each) {
    if (!each) return;
    
    for (int i = 0; i < t->cur_number; i++) {
        struct fui_hash_node *node = &t->nodes[i];
        if (!node->busy) continue;
        each(node->key, node->value);
    }
}
