#include <stdlib.h>

void *iorn_malloc_std_calloc(size_t nmemb, size_t size, void *user_data)
{
    return calloc(nmemb, size);
}

void *iorn_malloc_std_reallocarray(void *ptr, size_t nmemb, size_t size, void *user_data)
{
    return reallocarray(ptr, nmemb, size);
}

void iorn_malloc_std_free(void *ptr, void *user_data)
{
    free(ptr);
}

iorn_malloc_t iorn_malloc_std = {
    .calloc = iorn_malloc_std_calloc,
    .reallocarray = iorn_malloc_std_reallocarray,
    .free = iorn_malloc_std_free,
    .user_data = NULL
};
