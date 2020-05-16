#include "iorn/error.h"
#include "iorn/iovecs.h"

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
