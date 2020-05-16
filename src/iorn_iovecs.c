#include <sys/types.h>
#include <sys/socket.h>
#include "iorn/error.h"
#include "iorn/iovecs.h"

/* functions for iorn_iovec_t */

size_t iorn_iovec_adjust_after_short(size_t iov_len, void **iov_base, size_t advance, void **save_iov_base)
{
    if (*save_iov_base == NULL) {
        *save_iov_base = *iov_base;
    }
    *iov_base += advance;
    return iov_len - advance;
}

size_t iorn_iovec_restore_from_short_adjust(size_t adjusted_iov_len, void **adjusted_iov_base, void **save_iov_base)
{
    if (*save_iov_base != NULL) {
        adjusted_iov_len += (const char *) *adjusted_iov_base - (const char *) save_iov_base;
        *adjusted_iov_base = *save_iov_base;
        *save_iov_base = NULL;
    }
    return adjusted_iov_len;
}

/* functions for iorn_iovecs_t */

size_t iorn_iovecs_adjust_after_short(size_t vecs_len, iorn_iovec_t **vecs, size_t advance, iorn_iovec_t **save_vecs, void **save_iov_base)
{
    if (*save_vecs == NULL) {
        *save_vecs = *vecs;
    }
    iorn_iovec_t *vec = *vecs;
    if (advance >= vec->iov_len) {
        vec->iov_len = iorn_iovec_restore_from_short_adjust(vec->iov_len, &vec->iov_base, save_iov_base);
        advance -= vec->iov_len;
        vecs_len--;
        vec++;
    }
    for (; advance >= vec->iov_len; advance -= vec->iov_len) {
        vecs_len--;
        vec++;
    }
    if (advance > 0) {
        vec->iov_len = iorn_iovec_adjust_after_short(vec->iov_len, &vec->iov_base, advance, save_iov_base);
    }
    *vecs = vec;
    return vecs_len;
}

size_t iorn_iovecs_restore_from_short_adjust(size_t adjusted_vecs_len, iorn_iovec_t **adjusted_vecs, iorn_iovec_t **save_vecs, void **save_iov_base)
{
    if (*save_vecs != NULL) {
        (*adjusted_vecs)->iov_len = iorn_iovec_restore_from_short_adjust((*adjusted_vecs)->iov_len, &(*adjusted_vecs)->iov_base, save_iov_base);
        adjusted_vecs_len += *adjusted_vecs - *save_vecs;
        *adjusted_vecs = *save_vecs;
        *save_vecs = NULL;
    }
    return adjusted_vecs_len;
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
