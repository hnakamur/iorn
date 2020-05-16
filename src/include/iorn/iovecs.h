#ifndef IORN_IOVECS_H
#define IORN_IOVECS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <sys/uio.h>
#include "iorn/malloc.h"

/* iorn_iovec_t */

typedef struct iovec iorn_iovec_t;

#define IORN_IOVEC_EMPTY { .iov_len = 0, .iov_base = NULL }

static inline void iorn_iovec_init(iorn_iovec_t *vec)
{
    memset(vec, 0, sizeof(*vec));
}

void iorn_iovec_adjust_after_short(iorn_iovec_t *vec, size_t advance, void **saved_iov_base);
void iorn_iovec_restore_from_short_adjust(iorn_iovec_t *vec, void **saved_iov_base);

static inline void iorn_iovec_free_ma(iorn_iovec_t *vec, iorn_malloc_t *ma)
{
    ma->free(vec->iov_base, ma->user_data);
}

/* iorn_iovecs_t */

typedef struct iorn_iovecs iorn_iovecs_t;
typedef struct iorn_iovecs_save_for_short iorn_iovecs_save_for_short_t;

struct iorn_iovecs {
    size_t        nmemb;
    iorn_iovec_t *vecs;
};

struct iorn_iovecs_save_for_short {
    iorn_iovec_t *vecs;
    void         *iov_base;
};

#define IORN_IOVECS_EMPTY { .nmemb = 0, .vecs = NULL }
#define IORN_IOVECS_SAVE_FOR_SHORT_EMPTY { .vecs = NULL, iov_base = NULL }

static inline void iorn_iovecs_init(iorn_iovecs_t *vecs)
{
    memset(vecs, 0, sizeof(*vecs));
}

iorn_negative_errno_t iorn_iovecs_add_vec(iorn_iovecs_t *vecs, iorn_iovec_t *vec, iorn_malloc_t *ma);
iorn_negative_errno_t iorn_iovecs_resize(iorn_iovecs_t *vecs, size_t nmemb, iorn_malloc_t *ma);

void iorn_iovecs_adjust_after_short(iorn_iovecs_t *vecs, size_t advance, iorn_iovecs_save_for_short_t *save);
void iorn_iovecs_restore_from_short_adjust(iorn_iovecs_t *vecs, iorn_iovecs_save_for_short_t *save);

static inline void iorn_iovecs_shallow_free_ma(iorn_iovecs_t *vecs, iorn_malloc_t *ma)
{
    ma->free(vecs->vecs, ma->user_data);
}

void iorn_iovecs_deep_free_ma(iorn_iovecs_t *vecs, iorn_malloc_t *ma);

#ifdef __cplusplus
}
#endif

#endif /* IORN_IOVECS_H */
