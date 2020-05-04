#include <errno.h>
#include <stdio.h>
#include "urev.h"

static int urev_get_sqe_safe(urev_queue_t *queue, struct io_uring_sqe **sqe)
{
    int ret;

    *sqe = io_uring_get_sqe(&queue->ring);
    if (*sqe != NULL) {
        queue->sqe_count++;
        return 0;
    }

    ret = urev_submit(queue);
    if (ret < 0) {
        return ret;
    }
    *sqe = io_uring_get_sqe(&queue->ring);
    if (*sqe == NULL) {
        fprintf(stderr, "failed to get sqe right after submit\n");
        return -EAGAIN;
    }
    queue->sqe_count++;
    return 0;
}

int urev_queue_prep_accept(urev_queue_t *queue, urev_accept_op_t *op)
{
    struct io_uring_sqe* sqe;
    int ret;
    
    ret = urev_get_sqe_safe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_accept(sqe, op->fd, op->addr, op->addrlen, op->flags);
    op->common.opcode = sqe->opcode;
    op->common.queue = queue;
    io_uring_sqe_set_data(sqe, op);
    return 0;
}

int urev_prep_read(urev_queue_t *queue, urev_read_or_write_op_t *op)
{
    struct io_uring_sqe* sqe;
    int ret;
    
    ret = urev_get_sqe_safe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_read(sqe, op->fd, op->buf, op->nbytes, op->offset);
    op->common.opcode = sqe->opcode;
    op->common.queue = queue;
    io_uring_sqe_set_data(sqe, op);
    return 0;
}

int urev_prep_write(urev_queue_t *queue, urev_read_or_write_op_t *op)
{
    struct io_uring_sqe* sqe;
    int ret;
    
    ret = urev_get_sqe_safe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_write(sqe, op->fd, op->buf, op->nbytes, op->offset);
    op->common.opcode = sqe->opcode;
    op->common.queue = queue;
    io_uring_sqe_set_data(sqe, op);
    return 0;
}

int urev_prep_readv(urev_queue_t *queue, urev_readv_or_writev_op_t *op)
{
    struct io_uring_sqe* sqe;
    int ret;
    
    ret = urev_get_sqe_safe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_readv(sqe, op->fd, op->iovecs, op->nr_vecs, op->offset);
    op->common.opcode = sqe->opcode;
    op->common.queue = queue;
    io_uring_sqe_set_data(sqe, op);
    return 0;
}

int urev_prep_writev(urev_queue_t *queue, urev_readv_or_writev_op_t *op)
{
    struct io_uring_sqe* sqe;
    int ret;
    
    ret = urev_get_sqe_safe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_writev(sqe, op->fd, op->iovecs, op->nr_vecs, op->offset);
    op->common.opcode = sqe->opcode;
    op->common.queue = queue;
    io_uring_sqe_set_data(sqe, op);
    return 0;
}

int urev_prep_timeout(urev_queue_t *queue, urev_timeout_op_t *op)
{
    struct io_uring_sqe* sqe;
    int ret;
    
    ret = urev_get_sqe_safe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_timeout(sqe, (struct __kernel_timespec *) &op->ts, op->count, op->flags);
    op->common.opcode = sqe->opcode;
    op->common.queue = queue;
    io_uring_sqe_set_data(sqe, op);
    return 0;
}

int urev_prep_timeout_cancel(urev_queue_t *queue, urev_timeout_cancel_op_t *op)
{
    struct io_uring_sqe* sqe;
    int ret;
    
    ret = urev_get_sqe_safe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_timeout_remove(sqe, (__u64) op->target_op, op->flags);
    op->common.opcode = sqe->opcode;
    op->common.queue = queue;
    io_uring_sqe_set_data(sqe, op);
    return 0;
}

static inline void urev_handle_read(struct io_uring_cqe *cqe, void *cqe_data)
{
    urev_read_or_write_op_t *op = (urev_read_or_write_op_t *) cqe_data;
    op->handler(op, cqe);
}

static inline void urev_handle_write(struct io_uring_cqe *cqe, void *cqe_data)
{
    urev_read_or_write_op_t *op = (urev_read_or_write_op_t *) cqe_data;
    op->handler(op, cqe);
}

static inline void urev_handle_readv(struct io_uring_cqe *cqe, void *cqe_data)
{
    urev_readv_or_writev_op_t *op = (urev_readv_or_writev_op_t *) cqe_data;
    op->handler(op, cqe);
}

static inline void urev_handle_writev(struct io_uring_cqe *cqe, void *cqe_data)
{
    urev_readv_or_writev_op_t *op = (urev_readv_or_writev_op_t *) cqe_data;
    op->handler(op, cqe);
}

static inline void urev_handle_timeout(struct io_uring_cqe *cqe, void *cqe_data)
{
    urev_timeout_op_t *op = (urev_timeout_op_t *) cqe_data;
    op->handler(op, cqe);
}

static inline void urev_handle_timeout_remove(struct io_uring_cqe *cqe, void *cqe_data)
{
    urev_timeout_cancel_op_t *op = (urev_timeout_cancel_op_t *) cqe_data;
    op->handler(op, cqe);
}

void urev_handle_completion(urev_queue_t *queue, struct io_uring_cqe *cqe)
{
    void *cqe_data;
    int opcode;

    cqe_data = io_uring_cqe_get_data(cqe);
    opcode = ((urev_op_common_t *) cqe_data)->opcode;
    switch (opcode) {
    case IORING_OP_READ:
        urev_handle_read(cqe, cqe_data);
        break;
    case IORING_OP_WRITE:
        urev_handle_write(cqe, cqe_data);
        break;
    case IORING_OP_READV:
        urev_handle_readv(cqe, cqe_data);
        break;
    case IORING_OP_WRITEV:
        urev_handle_writev(cqe, cqe_data);
        break;
    case IORING_OP_TIMEOUT:
        urev_handle_timeout(cqe, cqe_data);
        break;
    case IORING_OP_TIMEOUT_REMOVE:
        urev_handle_timeout_remove(cqe, cqe_data);
        break;
    default:
        fprintf(stderr, "unsupported opcode in urev_handle_completion, opcode=%d\n", opcode);
        break;
    }
}
