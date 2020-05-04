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
    op->nbytes_left = op->nbytes;
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
    op->nbytes_left = op->nbytes;
    io_uring_sqe_set_data(sqe, op);
    return 0;
}

void urev_handle_short_read(urev_read_or_write_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_read(op->common.queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }
    
    op->nbytes_left -= res;
    if (op->nbytes_left) {
        if (op->saved_buf == NULL) {
            op->saved_buf = op->buf;
            op->saved_nbytes = op->nbytes;
            op->saved_offset = op->offset;
        }
        op->buf += res;
        op->nbytes -= res;
        op->offset += res;
        res = urev_prep_read(op->common.queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes == 0 && op->saved_buf != NULL) {
        op->buf = op->saved_buf;
        op->nbytes = op->saved_nbytes;
        op->offset = op->saved_offset;
    }
}

void urev_handle_short_write(urev_read_or_write_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_write(op->common.queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }
    
    op->nbytes_left -= res;
    if (op->nbytes_left) {
        if (op->saved_buf == NULL) {
            op->saved_buf = op->buf;
            op->saved_nbytes = op->nbytes;
            op->saved_offset = op->offset;
        }
        op->buf += res;
        op->nbytes -= res;
        op->offset += res;
        res = urev_prep_write(op->common.queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes == 0 && op->saved_buf != NULL) {
        op->buf = op->saved_buf;
        op->nbytes = op->saved_nbytes;
        op->offset = op->saved_offset;
    }
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

static inline void urev_handle_read(urev_op_common_t *common)
{
    urev_read_or_write_op_t *op = (urev_read_or_write_op_t *) common;
    op->handler(op);
}

static inline void urev_handle_write(urev_op_common_t *common)
{
    urev_read_or_write_op_t *op = (urev_read_or_write_op_t *) common;
    op->handler(op);
}

static inline void urev_handle_readv(urev_op_common_t *common)
{
    urev_readv_or_writev_op_t *op = (urev_readv_or_writev_op_t *) common;
    op->handler(op);
}

static inline void urev_handle_writev(urev_op_common_t *common)
{
    urev_readv_or_writev_op_t *op = (urev_readv_or_writev_op_t *) common;
    op->handler(op);
}

static inline void urev_handle_timeout(urev_op_common_t *common)
{
    urev_timeout_op_t *op = (urev_timeout_op_t *) common;
    op->handler(op);
}

static inline void urev_handle_timeout_remove(urev_op_common_t *common)
{
    urev_timeout_cancel_op_t *op = (urev_timeout_cancel_op_t *) common;
    op->handler(op);
}

void urev_handle_completion(urev_queue_t *queue, struct io_uring_cqe *cqe)
{
    urev_op_common_t *op;

    op = (urev_op_common_t *) io_uring_cqe_get_data(cqe);
    op->cqe_res = cqe->res;
    if (cqe->res < 0) {
        urev_op_set_err_code(op, -cqe->res);
    }

    switch (op->opcode) {
    case IORING_OP_READ:
        urev_handle_read(op);
        break;
    case IORING_OP_WRITE:
        urev_handle_write(op);
        break;
    case IORING_OP_READV:
        urev_handle_readv(op);
        break;
    case IORING_OP_WRITEV:
        urev_handle_writev(op);
        break;
    case IORING_OP_TIMEOUT:
        urev_handle_timeout(op);
        break;
    case IORING_OP_TIMEOUT_REMOVE:
        urev_handle_timeout_remove(op);
        break;
    default:
        fprintf(stderr, "unsupported opcode in urev_handle_completion, opcode=%d\n", op->opcode);
        break;
    }
}
