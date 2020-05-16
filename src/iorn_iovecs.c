#include "iorn/iovecs.h"

void iorn_iovecs_free_ma(iorn_iovecs_t *vecs, iorn_malloc_t *ma)
{
    for (int i = 0; i < vecs->nmemb; i++) {
        iorn_iovec_free_ma(vecs->vecs + i, ma);
    }
    ma->free(vecs->vecs, ma->user_data);
}
