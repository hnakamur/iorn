#ifndef UREV_H
#define UREV_H

#include <stdio.h>
#include <liburing.h>

typedef struct urev_queue  urev_queue_t;

typedef struct urev_accept_op           urev_accept_op_t;
typedef struct urev_read_or_write_op    urev_read_or_write_op_t;
typedef struct urev_readv_or_writev_op  urev_readv_or_writev_op_t;
typedef struct urev_timeout_op          urev_timeout_op_t;
typedef struct urev_timeout_cancel_op   urev_timeout_cancel_op_t;

struct urev_queue {
    struct io_uring ring;
    int cqe_count;
    int sqe_count;
};

static inline int urev_queue_init(unsigned entries, urev_queue_t *queue,
    unsigned flags)
{
    queue->cqe_count = 0;
    return io_uring_queue_init(entries, &queue->ring, flags);
}

static inline void urev_queue_exit(urev_queue_t *queue)
{
    io_uring_queue_exit(&queue->ring);
}

static inline int urev_submit(urev_queue_t *queue)
{
    int ret;

    // fprintf(stderr, "urev_submit start, sqe_count=%d\n", queue->sqe_count);
    if (queue->sqe_count == 0) {
        return 0;
    }
    ret = io_uring_submit(&queue->ring);
    // fprintf(stderr, "urev_submit start, io_uring_submit ret=%d\n", ret);
    if (ret > 0) {
        queue->sqe_count -= ret;
    }
    return ret;
}

/**
 * completion handler type for a accept operation.
 * @param [in] op     a accept operation.
 * @param [in] cqe    a completion queue entry.
 */
typedef void (*urev_accept_handler_t)(urev_accept_op_t *op, struct io_uring_cqe *cqe);

/**
 * completion handler type for a read or operation.
 * @param [in] op     a read or write operation.
 * @param [in] cqe    a completion queue entry.
 */
typedef void (*urev_read_or_write_handler_t)(urev_read_or_write_op_t *op, struct io_uring_cqe *cqe);

/**
 * completion handler type for a readv or writev operation.
 * @param [in] op     a readv or writev operation.
 * @param [in] cqe    a completion queue entry.
 */
typedef void (*urev_readv_or_writev_handler_t)(urev_readv_or_writev_op_t *op, struct io_uring_cqe *cqe);

/**
 * completion handler type for a timeout operation.
 * @param [in] op     a timeout operation.
 * @param [in] cqe    a completion queue entry.
 */
typedef void (*urev_timeout_handler_t)(urev_timeout_op_t *op, struct io_uring_cqe *cqe);
/**
 * completion handler type for a timeout_remove operation.
 * @param [in] op     a timeout_remove operation.
 * @param [in] cqe    a completion queue entry.
 */
typedef void (*urev_timeout_cancel_handler_t)(urev_timeout_cancel_op_t *op, struct io_uring_cqe *cqe);

struct urev_accept_op {
    int opcode; // must be the first field
    urev_queue_t *queue;
    void *ctx;
    urev_accept_handler_t handler;
    int fd;
    struct sockaddr *addr;
    socklen_t *addrlen;
    int flags;
};

struct urev_read_or_write_op {
    int opcode; // must be the first field
    urev_queue_t *queue;
    void *ctx;
    urev_read_or_write_handler_t handler;
    int fd;
    void *buf;
    unsigned nbytes;
    off_t offset;
};

struct urev_readv_or_writev_op {
    int opcode; // must be the first field
    urev_queue_t *queue;
    void *ctx;
    urev_readv_or_writev_handler_t handler;
    int fd;
    int nr_vecs;
    struct iovec *iovecs;
    off_t offset;
};

struct urev_timeout_op {
    int opcode; // must be the first field
    urev_queue_t *queue;
    void *ctx;
    urev_timeout_handler_t handler;
    struct timespec ts;
    unsigned count;
    unsigned flags;
};

struct urev_timeout_cancel_op {
    int opcode; // must be the first field
    urev_queue_t *queue;
    void *ctx;
    urev_timeout_cancel_handler_t handler;
    struct urev_timeout_op *target_op;
    unsigned flags;
};

int urev_queue_accept(urev_queue_t *queue, struct urev_accept_op *op);
int urev_prep_read(urev_queue_t *queue, urev_read_or_write_op_t *op);
int urev_prep_write(urev_queue_t *queue, urev_read_or_write_op_t *op);
int urev_prep_readv(urev_queue_t *queue, urev_readv_or_writev_op_t *op);
int urev_prep_writev(urev_queue_t *queue, urev_readv_or_writev_op_t *op);
int urev_prep_timeout(urev_queue_t *queue, urev_timeout_op_t *op);
/**
 * Prepare a timeout_cancel operation.
 * @param [in,out] sqe  a submission queue entry.
 * @param [in]     op   a timeout_cancel operation.
 *                      op->target_op must be set to the target
 *                      timeout operation.
 */
int urev_prep_timeout_cancel(urev_queue_t *queue, urev_timeout_cancel_op_t *op);

void urev_handle_completion(urev_queue_t *queue, struct io_uring_cqe *cqe);

static inline void urev_handle_completions(urev_queue_t *queue)
{
    struct io_uring_cqe *cqe;
    unsigned head;
    unsigned cqe_count;

    fprintf(stderr, "urev_handle_completions start\n");
    cqe_count = 0;
    io_uring_for_each_cqe(&queue->ring, head, cqe) {
        cqe_count++;
        fprintf(stderr, "io_uring_for_each_cqe, cqe=%p, cqe_count=%d\n", cqe, cqe_count);
        urev_handle_completion(queue, cqe);
    }
    io_uring_cq_advance(&queue->ring, cqe_count);
}

static inline int urev_wait_and_handle_completions(urev_queue_t *queue)
{
    struct io_uring_cqe *cqe;
    int ret;

    fprintf(stderr, "urev_wait_and_handle_completions start\n");
    ret = io_uring_wait_cqe(&queue->ring, &cqe);
    fprintf(stderr, "after io_uring_wait_cqe, cqe=%p\n", cqe);
    if (cqe != NULL) {
        urev_handle_completion(queue, cqe);
        io_uring_cq_advance(&queue->ring, 1);
    }
    if (ret < 0) {
        return ret;
    }

    urev_handle_completions(queue);
    return 0;
}

#endif
