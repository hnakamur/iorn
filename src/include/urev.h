#ifndef UREV_H
#define UREV_H

#include <stdio.h>
#include <liburing.h>

typedef struct urev_queue urev_queue_t;

typedef struct urev_op_common          urev_op_common_t;
typedef struct urev_accept_op          urev_accept_op_t;
typedef struct urev_close_op           urev_close_op_t;
typedef struct urev_fsync_op           urev_fsync_op_t;
typedef struct urev_openat_op          urev_openat_op_t;
typedef struct urev_openat2_op         urev_openat2_op_t;
typedef struct urev_read_or_write_op   urev_read_or_write_op_t;
typedef struct urev_readv_or_writev_op urev_readv_or_writev_op_t;
typedef struct urev_statx_op           urev_statx_op_t;
typedef struct urev_timeout_op         urev_timeout_op_t;
typedef struct urev_timeout_cancel_op  urev_timeout_cancel_op_t;

struct urev_queue {
    struct io_uring ring;
};

static inline int urev_queue_init(unsigned entries, urev_queue_t *queue,
    unsigned flags)
{
    return io_uring_queue_init(entries, &queue->ring, flags);
}

static inline void urev_queue_exit(urev_queue_t *queue)
{
    io_uring_queue_exit(&queue->ring);
}

static inline int urev_submit(urev_queue_t *queue)
{
    return io_uring_submit(&queue->ring);
}

/**
 * completion handler type for a accept operation.
 * @param [in] op     a accept operation.
 */
typedef void (*urev_accept_handler_t)(urev_accept_op_t *op);

/**
 * completion handler type for a close operation.
 * @param [in] op     a close operation.
 */
typedef void (*urev_close_handler_t)(urev_close_op_t *op);

/**
 * completion handler type for a fsync operation.
 * @param [in] op     a fsync operation.
 */
typedef void (*urev_fsync_handler_t)(urev_fsync_op_t *op);

/**
 * completion handler type for a openat operation.
 * @param [in] op     a openat operation.
 */
typedef void (*urev_openat_handler_t)(urev_openat_op_t *op);

/**
 * completion handler type for a openat2 operation.
 * @param [in] op     a openat2 operation.
 */
typedef void (*urev_openat2_handler_t)(urev_openat2_op_t *op);

/**
 * completion handler type for a read or operation.
 * @param [in] op     a read or write operation.
 */
typedef void (*urev_read_or_write_handler_t)(urev_read_or_write_op_t *op);

/**
 * completion handler type for a readv or writev operation.
 * @param [in] op     a readv or writev operation.
 */
typedef void (*urev_readv_or_writev_handler_t)(urev_readv_or_writev_op_t *op);

/**
 * completion handler type for a statx operation.
 * @param [in] op     a statx operation.
 */
typedef void (*urev_statx_handler_t)(urev_statx_op_t *op);

/**
 * completion handler type for a timeout operation.
 * @param [in] op     a timeout operation.
 */
typedef void (*urev_timeout_handler_t)(urev_timeout_op_t *op);
/**
 * completion handler type for a timeout_remove operation.
 * @param [in] op     a timeout_remove operation.
 */
typedef void (*urev_timeout_cancel_handler_t)(urev_timeout_cancel_op_t *op);

struct urev_op_common {
    int           opcode;
    urev_queue_t *queue;
    int32_t       cqe_res;
    int           err_code;
    void         *ctx;
};

struct urev_accept_op {
    urev_op_common_t       common; // must be the first field
    urev_accept_handler_t  handler;

    int              fd;
    struct sockaddr *addr;
    socklen_t       *addrlen;
    int             flags;
};

struct urev_close_op {
    urev_op_common_t     common; // must be the first field
    urev_close_handler_t handler;

    int fd;
};

struct urev_fsync_op {
    urev_op_common_t     common; // must be the first field
    urev_fsync_handler_t handler;

    int      fd;
    unsigned fsync_flags;
};

struct urev_openat_op {
    urev_op_common_t      common; // must be the first field
    urev_openat_handler_t handler;

    int         dfd;
    const char *path;
    int         flags;
    mode_t      mode;
};

struct urev_openat2_op {
    urev_op_common_t       common; // must be the first field
    urev_openat2_handler_t handler;

    int              dfd;
    const char      *path;
    struct open_how *how;
};

struct urev_read_or_write_op {
    urev_op_common_t              common; // must be the first field
    urev_read_or_write_handler_t  handler;

    int       fd;
    void     *buf;
    unsigned  nbytes;
    off_t     offset;

    unsigned  nbytes_left;
    void     *saved_buf;
    unsigned  saved_nbytes;
    off_t     saved_offset;
};

struct urev_readv_or_writev_op {
    urev_op_common_t               common; // must be the first field
    urev_readv_or_writev_handler_t handler;

    int           fd;
    int           nr_vecs;
    struct iovec *iovecs;
    off_t         offset;

    size_t        nbytes_left;
    int           saved_nr_vecs;
    struct iovec *saved_iovecs;
    void         *saved_iov_base;
    off_t         saved_offset;
};

struct urev_statx_op {
    urev_op_common_t     common; // must be the first field
    urev_statx_handler_t handler;

    int           dfd;
    const char   *path;
    int           flags;
    unsigned      mask;
    struct statx *statxbuf;
};

struct urev_timeout_op {
    urev_op_common_t       common; // must be the first field
    urev_timeout_handler_t handler;

    struct timespec ts;
    unsigned        count;
    unsigned        flags;
};

struct urev_timeout_cancel_op {
    urev_op_common_t              common; // must be the first field
    urev_timeout_cancel_handler_t handler;

    urev_timeout_op_t *target_op;
    unsigned           flags;
};

static inline void urev_op_set_err_code(urev_op_common_t *common, int err_code)
{
    if (common->err_code == 0) {
        common->err_code = err_code;
    }
}

/**
 * Get a sqe and prepare an accept operation.
 *
 * If the submission queue is full, this function tries to make room
 * with calling urev_submit and urev_wait_and_handle_completion repeatedly.
 *
 * @param [in,out] queue a queue.
 * @param [in,out] op    an accept operatoin.
 * @return zero if success, -errno from urev_submit or urev_wait_and_handle_completion if error.
 */
int urev_prep_accept(urev_queue_t *queue, urev_accept_op_t *op);
int urev_prep_close(urev_queue_t *queue, urev_close_op_t *op);
int urev_prep_fsync(urev_queue_t *queue, urev_fsync_op_t *op);
int urev_prep_openat(urev_queue_t *queue, urev_openat_op_t *op);
int urev_prep_openat2(urev_queue_t *queue, urev_openat2_op_t *op);
int urev_prep_read(urev_queue_t *queue, urev_read_or_write_op_t *op);
int urev_prep_readv(urev_queue_t *queue, urev_readv_or_writev_op_t *op);
int urev_prep_statx(urev_queue_t *queue, urev_statx_op_t *op);
int urev_prep_write(urev_queue_t *queue, urev_read_or_write_op_t *op);
int urev_prep_writev(urev_queue_t *queue, urev_readv_or_writev_op_t *op);
int urev_prep_timeout(urev_queue_t *queue, urev_timeout_op_t *op);

/**
 * Prepare a timeout_cancel operation.
 *
 * If the submission queue is full, this function tries to make room
 * with calling urev_submit and urev_wait_and_handle_completion repeatedly.
 *
 * @param [in,out] sqe  a submission queue entry.
 * @param [in,out] op   a timeout_cancel operation.
 *                      op->target_op must be set to the target
 *                      timeout operation.
 * @return zero if success, -errno from urev_submit or urev_wait_and_handle_completion if error.
 */
int urev_prep_timeout_cancel(urev_queue_t *queue, urev_timeout_cancel_op_t *op);

void urev_handle_completion(urev_queue_t *queue, struct io_uring_cqe *cqe);

static inline int urev_wait_and_handle_completion(urev_queue_t *queue)
{
    int ret;
    struct io_uring_cqe *cqe;

    ret = io_uring_wait_cqe(&queue->ring, &cqe);
    if (cqe != NULL) {
        urev_handle_completion(queue, cqe);
        io_uring_cq_advance(&queue->ring, 1);
    }
    return ret;
}

static inline void urev_peek_and_handle_completions(urev_queue_t *queue)
{
    struct io_uring_cqe *cqe;
    unsigned head;
    unsigned cqe_count;

    cqe_count = 0;
    io_uring_for_each_cqe(&queue->ring, head, cqe) {
        cqe_count++;
        urev_handle_completion(queue, cqe);
    }
    io_uring_cq_advance(&queue->ring, cqe_count);
}

static inline int urev_wait_and_handle_completions(urev_queue_t *queue)
{
    int ret;

    ret = urev_wait_and_handle_completion(queue);
    if (ret < 0) {
        return ret;
    }

    urev_peek_and_handle_completions(queue);
    return 0;
}

void urev_handle_short_read(urev_read_or_write_op_t *op);
void urev_handle_short_write(urev_read_or_write_op_t *op);
void urev_handle_short_readv(urev_readv_or_writev_op_t *op);
void urev_handle_short_writev(urev_readv_or_writev_op_t *op);

/* NOTE: These functions are exported just for testing. */
void _urev_adjust_after_short_readv_or_writev(urev_readv_or_writev_op_t *op, size_t nr_advance);
void _urev_restore_after_short_readv_or_writev(urev_readv_or_writev_op_t *op);

#endif
