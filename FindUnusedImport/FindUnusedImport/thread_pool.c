//
//  thread_pool.c
//  FindUnusedImport
//
//  Created by tripleCC on 6/8/19.
//  Copyright © 2019 tripleCC. All rights reserved.
//
#include <pthread.h>
#include <stdlib.h>
#include <math.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>
#include "thread_pool.h"

static atomic_bool g_atomic_threads_alive = ATOMIC_VAR_INIT(false);

static const unsigned int g_default_thread_number = 4;

typedef struct fui_task {
    struct fui_task *next;
    void *(*func)(void *argv);
    void *argv;
} fui_task_t;

typedef struct fui_task_queue {
    unsigned int task_number;
    fui_task_t *head;
    fui_task_t *tail;
    pthread_mutex_t rwlock;
    pthread_cond_t task_cond;
    pthread_mutex_t task_cond_lock;
    bool task_cond_signaled;
} fui_task_queue_t;

struct fui_thread_pool {
    unsigned int max_number;
    unsigned int created_number;
    unsigned int working_number;
    pthread_mutex_t number_lock;
    pthread_cond_t all_done_cond;
    struct fui_task_queue task_queue;
};

static void
task_queue_init(fui_task_queue_t *q) {
    q->task_number = 0;
    q->tail = NULL;
    q->head = NULL;
    q->task_cond_signaled = false;
    
    pthread_mutex_init(&q->rwlock, NULL);
    pthread_mutex_init(&q->task_cond_lock, NULL);
    pthread_cond_init(&q->task_cond, NULL);
}

static void
task_queue_push(fui_task_queue_t *q, fui_task_t *t) {
    t->next = NULL;
    
    pthread_mutex_lock(&q->rwlock);
    if (q->task_number)
        q->tail->next = t;
    else
        q->head = t;
    q->tail = t;
    q->task_number++;
    
    pthread_mutex_lock(&q->task_cond_lock);
    q->task_cond_signaled = true;
    pthread_cond_signal(&q->task_cond);
    pthread_mutex_unlock(&q->task_cond_lock);
    pthread_mutex_unlock(&q->rwlock);
}

static fui_task_t *
task_queue_pop(fui_task_queue_t *q) {
    pthread_mutex_lock(&q->rwlock);
    fui_task_t *t = q->head;
    if (q->task_number == 1) {
        q->head = NULL;
        q->tail = NULL;
        q->task_number--;
    } else if (q->task_number > 1) {
        q->head = t->next;
        q->task_number--;
        pthread_mutex_lock(&q->task_cond_lock);
        q->task_cond_signaled = true;
        pthread_cond_signal(&q->task_cond);
        pthread_mutex_unlock(&q->task_cond_lock);
    }
    pthread_mutex_unlock(&q->rwlock);
    
    return t;
}

static void
task_queue_destroy(fui_task_queue_t *q) {
    pthread_mutex_lock(&q->rwlock);
    fui_task_t *t = q->head;
    fui_task_t *next = NULL;
    while (q->task_number > 0) {
        next = t->next;
        free(t);
        t = next;
        q->task_number--;
    }
    q->head = NULL;
    q->tail = NULL;
    pthread_mutex_unlock(&q->rwlock);
    
    pthread_mutex_destroy(&q->rwlock);
    pthread_mutex_destroy(&q->task_cond_lock);
    pthread_cond_destroy(&q->task_cond);
}

static unsigned int
task_queue_task_number(fui_task_queue_t *q) {
    pthread_mutex_lock(&q->rwlock);
    unsigned int n = q->task_number;
    pthread_mutex_unlock(&q->rwlock);
    
    return n;
}

static void
task_queue_cond_wait(fui_task_queue_t *q) {
    pthread_mutex_lock(&q->task_cond_lock);
    while (!q->task_cond_signaled)
        pthread_cond_wait(&q->task_cond, &q->task_cond_lock);
    pthread_mutex_unlock(&q->task_cond_lock);
}

static void
task_queue_cond_sinal(fui_task_queue_t *q) {
    pthread_mutex_lock(&q->task_cond_lock);
    q->task_cond_signaled = true;
    pthread_cond_signal(&q->task_cond);
    pthread_mutex_unlock(&q->task_cond_lock);
}

void *
task_worker(fui_thread_pool_ref p) {
    char name[20] = {0};
    sprintf(name, "task worker %d", p->created_number);
    pthread_setname_np(name);
    
    while (atomic_load(&g_atomic_threads_alive)) {
        task_queue_cond_wait(&p->task_queue);
        
        pthread_mutex_lock(&p->number_lock);
        p->working_number++;
        pthread_mutex_unlock(&p->number_lock);
        
        fui_task_t *t = task_queue_pop(&p->task_queue);
        if (t) {
            t->func(t->argv);
            free(t);
        }
        
        pthread_mutex_lock(&p->number_lock);
        if (!--p->working_number) pthread_cond_signal(&p->all_done_cond);
        pthread_mutex_unlock(&p->number_lock);
    }
    
    pthread_mutex_lock(&p->number_lock);
    p->created_number--;
    pthread_mutex_unlock(&p->number_lock);
    
    return NULL;
}

int
thread_pool_add_task(fui_thread_pool_ref p, void *(*func)(void *argv), void *argv) {
    fui_task_t *task = malloc(sizeof(fui_task_t));
    if (!task) return -1;
    
    task->func = func;
    task->argv = argv;
    task->next = NULL;
    
    unsigned int task_number = task_queue_task_number(&p->task_queue);
    pthread_mutex_lock(&p->number_lock);
    if (task_number > p->created_number - p->working_number &&
        p->max_number > p->created_number) {
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, (void *(*)(void *))task_worker, p);
        pthread_detach(thread_id);
        p->created_number++;
    }
    pthread_mutex_unlock(&p->number_lock);
    
    task_queue_push(&p->task_queue, task);
    
    return 0;
}

void
thread_pool_wait(fui_thread_pool_ref p) {
    pthread_mutex_lock(&p->number_lock);
    while (task_queue_task_number(&p->task_queue) ||
           p->working_number) {
        pthread_cond_wait(&p->all_done_cond, &p->number_lock);
    }
    pthread_mutex_unlock(&p->number_lock);
}

void
thread_pool_destroy(fui_thread_pool_ref p) {
    atomic_store(&g_atomic_threads_alive, false);
    
    while (p->created_number) {
        task_queue_cond_sinal(&p->task_queue);
        sleep(1);
    }
    
    task_queue_destroy(&p->task_queue);
    pthread_mutex_destroy(&p->number_lock);
    pthread_cond_destroy(&p->all_done_cond);
    free(p);
}

fui_thread_pool_ref
thread_pool_init(void) {
    atomic_store(&g_atomic_threads_alive, true);
    
    fui_thread_pool_ref p = calloc(1, sizeof(struct fui_thread_pool));
    if (!p) return NULL;
    
    unsigned int pro_number = (unsigned int)sysconf(_SC_NPROCESSORS_ONLN);
    p->max_number = pro_number > g_default_thread_number ? pro_number : g_default_thread_number;
    p->created_number = 0;
    p->working_number = 0;
    pthread_mutex_init(&p->number_lock, NULL);
    pthread_cond_init(&p->all_done_cond, NULL);
    
    task_queue_init(&p->task_queue);
   
    return p;
}
