#ifndef IORN_ERROR_H
#define IORN_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

typedef int iorn_negative_errno_t;

#define IORN_PERROR_FROM_ERRNO() fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, strerror(errno))

#ifdef __cplusplus
}
#endif

#endif /* IORN_ERROR_H */
