#ifndef IORN_MALLOC_H
#define IORN_MALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

typedef struct iorn_malloc iorn_malloc_t;

typedef void *(*iorn_malloc_calloc_t)(size_t nmemb, size_t size, void *user_data);
typedef void *(*iorn_malloc_reallocarray_t)(void *ptr, size_t nmemb, size_t size, void *user_data);
typedef void (*iorn_malloc_free_t)(void *ptr, void *user_data);

struct iorn_malloc {
  iorn_malloc_calloc_t        calloc;
  iorn_malloc_reallocarray_t  reallocarray;
  iorn_malloc_free_t          free;
  void                       *user_data;
};

void *iorn_malloc_std_calloc(size_t nmemb, size_t size, void *user_data);
void *iorn_malloc_std_reallocarray(void *ptr, size_t nmemb, size_t size, void *user_data);
void iorn_malloc_std_free(void *ptr, void *user_data);

const iorn_malloc_t *iorn_malloc_std();

#ifdef __cplusplus
}
#endif

#endif /* IORN_MALLOC_H */
