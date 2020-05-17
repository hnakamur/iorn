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

/**
  Adjust an iovec after a short read/write.
  @param [in]     iov_len        the length of an iovec.
  @param [in,out] iov_base       the base of an iovec.
  @param [in]     advance        a number of advanced bytes in a short read/write.
  @param [in,out] save_iov_base  the saved base of an iovec. *save_iov_base must be NULL at first , and must not be modified by user.
  @return the adjusted value of iov_len.

  An example for a struct iovec:
    void *save_iov_base = NULL;
    struct iovec *vec;
    vec = calloc(1, sizeof(*vec));
    vec->iov_len = 4096;
    vec->iov_base = calloc(1, vec->iov_len);
    size_t advance = 30;
    vec->iov_len = iorn_iovec_adjust_after_short(vec->iov_len, &vec->iov_base, advance, &save_iov_base);
    // write code here to retry for a read/write and call iorn_iovec_adjust_after_short again.
    // after a full read/write, restore the iovec.
    vec->iov_len = iorn_iovec_restore_from_short_adjust(vec->iov_len, &vec->iov_base, &save_iov_base);

  An example for a size and a buffer:
    void *save_iov_base = NULL;
    unsigned nbytes = 256;
    char *buf;
    buf = calloc(1, nbytes);
    size_t advance = 30;
    nbytes = iorn_iovec_adjust_after_short(nbytes, (void **) &buf, advance, &save_iov_base);
    // write code here to retry for a read/write and call iorn_iovec_adjust_after_short again.
    // after a full read/write, restore the size and the buffer.
    nbytes = iorn_iovec_restore_from_short_adjust(nbytes, (void **) &buf, &save_iov_base);
*/
size_t iorn_iovec_adjust_after_short(size_t iov_len, void **iov_base, size_t advance, void **save_iov_base);

/**
  Restore an iovec to the original state before calling iorn_iovec_adjust_after_short.
  See iorn_iovec_adjust_after_short for an example.
  @param [in]     iov_len        the adjusted length of an iovec.
  @param [in,out] iov_base       the adjusted base of an iovec.
  @param [in,out] save_iov_base  the saved base of an iovec. *save_iov_base will be set to NULL.
  @return the original value of iov_len.
*/
size_t iorn_iovec_restore_from_short_adjust(size_t adjusted_iov_len, void **adjusted_iov_base, void **save_iov_base);

static inline void iorn_iovec_free_ma(iorn_iovec_t *vec, iorn_malloc_t *ma)
{
    ma->free(vec->iov_base, ma->user_data);
}

/* iorn_iovec_array_t */

typedef struct iorn_iovec_array iorn_iovec_array_t;

struct iorn_iovec_array {
    size_t        nmemb;
    iorn_iovec_t *vecs;
};

#define IORN_IOVEC_ARRAY_EMPTY { .nmemb = 0, .vecs = NULL }

static inline void iorn_iovec_array_init(iorn_iovec_array_t *vecs)
{
    memset(vecs, 0, sizeof(*vecs));
}

iorn_negative_errno_t iorn_iovec_array_add_vec(iorn_iovec_array_t *vecs, iorn_iovec_t *vec, iorn_malloc_t *ma);
iorn_negative_errno_t iorn_iovec_array_resize(iorn_iovec_array_t *vecs, size_t nmemb, iorn_malloc_t *ma);

/**
  Get the total length in bytes of an iovec array.
  @param [in]     vecs_len       the length of an iovec array.
  @param [in]     vecs           an iovec array.
  @return the total length in bytes of an iovec array.
*/
size_t iorn_iovec_array_total_byte_len(size_t vecs_len, const iorn_iovec_t *vecs);

/**
  Adjust an iovec array after a short read/write.
  @param [in]     vecs_len       the length of an iovec array.
  @param [in,out] vecs           an iovec array.
  @param [in]     advance        a number of advanced bytes in a short read/write.
  @param [in,out] save_vecs      the saved iovec array. *save_vecs must be NULL at first , and must not be modified by user.
  @param [in,out] save_iov_base  the saved base of an iovec. *save_iov_base must be NULL at first , and must not be modified by user.
  @return the adjusted value of vecs_len.

  An example for a struct iovec array:
    iorn_iovec_t *save_vecs = NULL;
    void *save_iov_base = NULL;
    int vecs_len = 3;
    struct iovec *vecs;
    vecs = calloc(vecs_len, sizeof(struct iovec));
    for (int i = 0; i < vecs_len; i++) {
        vecs[i].iov_len = 4096;
        vecs[i].iov_base = calloc(1, vecs[i].iov_len);
    }
    size_t advance = 30;
    vecs_len = iorn_iovec_array_adjust_after_short(vecs_len, &vecs, advance, &save_vecs, &save_iov_base);
    // write code here to retry for a read/write and call iorn_iovec_array_adjust_after_short again.
    // after a full read/write, restore the size and the buffer.
    vecs_len = iorn_iovec_array_restore_from_short_adjust(vecs_len, &vecs, &save_vecs, &save_iov_base);
}

  An example for a struct msghdr:
    iorn_iovec_t *save_vecs = NULL;
    void *save_iov_base = NULL;
    struct msghdr *h;
    h = calloc(1, sizeof(*h));
    h->msg_iovlen = 3;
    h->msg_iov = calloc(h->msg_iovlen, sizeof(struct iovec));
    for (size_t i = 0; i < h->msg_iovlen; i++) {
        h->msg_iov[i].iov_len = 4096;
        h->msg_iov[i].iov_base = calloc(1, h->msg_iov[i].iov_len);
    }
    size_t advance = 30;
    h->msg_iovlen = iorn_iovec_array_adjust_after_short(h->msg_iovlen, &h->msg_iov, advance, &save_vecs, &save_iov_base);
    // write code here to retry for a read/write and call iorn_iovec_array_adjust_after_short again.
    // after a full read/write, restore the size and the buffer.
    h->msg_iovlen = iorn_iovec_array_restore_from_short_adjust(h->msg_iovlen, &h->msg_iov, &save_vecs, &save_iov_base);
*/
size_t iorn_iovec_array_adjust_after_short(size_t vecs_len, iorn_iovec_t **vecs, size_t advance, iorn_iovec_t **save_vecs, void **save_iov_base);

/**
  Restore an iovec array to the original state before calling iorn_iovec_array_adjust_after_short.
  See iorn_iovec_array_adjust_after_short for an example.
  @param [in]     adjusted_vecs_len   the adjusted length of an iovec array.
  @param [in,out] adjusted_vecs       the adjusted an iovec array.
  @param [in,out] save_vecs           the saved iovec array. *save_vecs must be NULL at first , and must not be modified by user.
  @param [in,out] save_iov_base       the saved base of an iovec. *save_iov_base will be set to NULL.
  @return the original value of vecs_len.
*/
size_t iorn_iovec_array_restore_from_short_adjust(size_t adjusted_vecs_len, iorn_iovec_t **adjusted_vecs, iorn_iovec_t **save_vecs, void **save_iov_base);

static inline void iorn_iovec_array_shallow_free_ma(iorn_iovec_array_t *vecs, iorn_malloc_t *ma)
{
    ma->free(vecs->vecs, ma->user_data);
}

void iorn_iovec_array_deep_free_ma(iorn_iovec_array_t *vecs, iorn_malloc_t *ma);

#ifdef __cplusplus
}
#endif

#endif /* IORN_IOVECS_H */
