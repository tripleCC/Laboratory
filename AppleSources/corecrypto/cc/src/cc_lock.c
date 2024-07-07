/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_lock.h"

#if CC_LOCK_IMPL_POSIX

int cc_lock_init(struct cc_lock_ctx *lock_ctx,
                 CC_UNUSED const char *group_name)
{
    int rc = CCERR_INTERNAL;

    rc = pthread_mutex_init(&lock_ctx->mutex, NULL);
    return rc;
}

#elif CC_LOCK_IMPL_USER

int cc_lock_init(struct cc_lock_ctx *lock_ctx,
                 CC_UNUSED const char *group_name)
{
    lock_ctx->lock = OS_UNFAIR_LOCK_INIT;
    return CCERR_OK;
}

#elif CC_LOCK_IMPL_WIN

int cc_lock_init(struct cc_lock_ctx *lock_ctx,
                 CC_UNUSED const char *group_name)
{
    lock_ctx->hMutex = CreateMutex(NULL,  // default security attributes
                                   FALSE, // initially not owned
                                   NULL); // unnamed mutex

    if (lock_ctx->hMutex != NULL) {
        return CCERR_OK;
    }
    return CCERR_INTERNAL;
}

#elif CC_LOCK_IMPL_KERNEL

int cc_lock_init(struct cc_lock_ctx *lock_ctx,
                 const char *group_name)
{
    lock_ctx->group = lck_grp_alloc_init(group_name, LCK_GRP_ATTR_NULL);
    lock_ctx->mutex = lck_mtx_alloc_init(lock_ctx->group, LCK_ATTR_NULL);

    return CCERR_OK;
}

#else
#error "cc_lock_init is not implemented."
#endif /* CC_LOCK_IMPL_USER */
