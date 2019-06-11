//
//  list.c
//  FindUnusedImport
//
//  Created by tripleCC on 6/6/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#include <stdlib.h>
#include <stdbool.h>
#include "list.h"

struct fui_list_node {
    void *value;
    struct fui_list_node *next;
};

struct fui_list {
    unsigned int number;
    struct fui_list_node *node;
};

void
fui_list_free(fui_list_ref l) {
    struct fui_list_node *node = l->node;
    struct fui_list_node *next = NULL;
    
    while (l->number-- > 0) {
        next = node->next;
        free(node);
        node = next;
    }
    free(l);
}

fui_list_ref
fui_list_allocate(void) {
    fui_list_ref l = calloc(1, sizeof(struct fui_list));
    if (!l) return NULL;
    
    l->number = 0;
    
    return l;
}

void
fui_list_add(fui_list_ref l, void *value) {
    struct fui_list_node *node = calloc(1, sizeof(struct fui_list_node));
    if (!node) return;
    
    node->value = value;
    node->next = NULL;
    
    if (l->number == 0) {
        l->node = node;
    } else {
        struct fui_list_node *tail = l->node;
        while (tail->next) tail = tail->next;
        tail->next = node;
    }
    
    l->number++;
}

void
fui_list_get(fui_list_ref l, unsigned int i, void **value) {
    if (i >= l->number || i < 0) {
        *value = NULL;
        return;
    }
    
    struct fui_list_node *node = l->node;
    for (int j = 1; j <= i; j++)
        node = node->next;
    
    if (node) *value = node->value;
}

void
fui_list_remove(fui_list_ref l, unsigned int i) {
    if (i >= l->number || i < 0) return;
    
    struct fui_list_node *node = l->node;
    if (i == 0) {
        l->node = node->next;
        l->node = NULL;
    }  else {
        for (int j = 1; j <= i - 1; j++)
            node = node->next;
        
        struct fui_list_node *prev = node->next;
        node->next = prev->next;
        node = prev;
    }
    
    l->number--;
    free(node);
}

unsigned int
fui_list_get_number(fui_list_ref l) {
    return l->number;
}

extern void
fui_list_foreach(fui_list_ref l, fui_list_foreach_func each, void *context) {
    if (!each) return;
    
    struct fui_list_node *node = l->node;
    struct fui_list_node *next = NULL;
    unsigned int number = l->number;
    
    while (number-- > 0) {
        next = node->next;
        each(node->value, context);
        node = next;
    }
}
