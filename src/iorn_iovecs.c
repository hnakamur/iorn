#include "iorn/error.h"
#include "iorn/iovecs.h"

/* functions for iorn_iovec_t */

void iorn_iovec_adjust_after_short(iorn_iovec_t *vec, size_t advance, void **saved_iov_base)
{
    if (*saved_iov_base == NULL) {
        *saved_iov_base = vec->iov_base;
    }
    vec->iov_len -= advance;
    vec->iov_base += advance;
}

void iorn_iovec_restore_from_short_adjust(iorn_iovec_t *vec, void **saved_iov_base)
{
    if (*saved_iov_base != NULL) {
        vec->iov_len += (const char *) vec->iov_base - (const char *) saved_iov_base;
        vec->iov_base = *saved_iov_base;
        *saved_iov_base = NULL;
    }
}

/* functions for iorn_iovecs_t */

void iorn_iovecs_adjust_after_short(iorn_iovecs_t *vecs, size_t advance, iorn_iovecs_save_for_short_t *save)
{
    if (save->vecs == NULL) {
        save->vecs = vecs->vecs;
    }
    iorn_iovec_t *vec = vecs->vecs;
    if (advance >= vec->iov_len) {
        iorn_iovec_restore_from_short_adjust(vec, &save->iov_base);
        advance -= vec->iov_len;
        vecs->nmemb--;
        vec++;
    }
    for (; advance >= vec->iov_len; advance -= vec->iov_len) {
        vecs->nmemb--;
        vec++;
    }
    if (advance > 0) {
        iorn_iovec_adjust_after_short(vec, advance, &save->iov_base);
    }
    vecs->vecs = vec;
}

void iorn_iovecs_restore_from_short_adjust(iorn_iovecs_t *vecs, iorn_iovecs_save_for_short_t *save)
{
    if (save->vecs != NULL) {
        iorn_iovec_restore_from_short_adjust(vecs->vecs, &save->iov_base);
        vecs->nmemb += vecs->vecs - save->vecs;
        vecs->vecs = save->vecs;
        save->vecs = NULL;
    }
}

iorn_negative_errno_t iorn_iovecs_resize(iorn_iovecs_t *vecs, size_t nmemb, iorn_malloc_t *ma)
{
    iorn_iovec_t *new_vecs = ma->reallocarray(vecs->vecs, nmemb, sizeof(iorn_iovec_t), ma->user_data);
    if (new_vecs == NULL) {
        IORN_PERROR_FROM_ERRNO();
        return -errno;
    }
    vecs->vecs = new_vecs;
    vecs->nmemb = nmemb;
    return 0;
}

iorn_negative_errno_t iorn_iovecs_add_vec(iorn_iovecs_t *vecs, iorn_iovec_t *vec, iorn_malloc_t *ma)
{
    iorn_negative_errno_t ret = iorn_iovecs_resize(vecs, vecs->nmemb + 1, ma);
    if (ret < 0) {
        return ret;
    }
    vecs->vecs[vecs->nmemb - 1] = *vec;
    return 0;
}

void iorn_iovecs_deep_free_ma(iorn_iovecs_t *vecs, iorn_malloc_t *ma)
{
    for (int i = 0; i < vecs->nmemb; i++) {
        iorn_iovec_free_ma(vecs->vecs + i, ma);
    }
    iorn_iovecs_shallow_free_ma(vecs, ma);
}
