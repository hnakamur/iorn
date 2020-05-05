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

static size_t urev_iovecs_total_len(int nr_vecs, struct iovec *iovecs)
{
    int i;
    size_t len;

    len = 0;
    for (i = 0; i < nr_vecs; i++) {
        len += iovecs[i].iov_len;
    }
    return len;
}

int urev_prep_accept(urev_queue_t *queue, urev_accept_op_t *op)
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

int urev_prep_fsync(urev_queue_t *queue, urev_fsync_op_t *op)
{
    struct io_uring_sqe* sqe;
    int ret;
    
    ret = urev_get_sqe_safe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_fsync(sqe, op->fd, op->fsync_flags);
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

static void urev_adjust_after_short_read_or_write(urev_read_or_write_op_t *op, int32_t nr_advance)
{
    if (op->saved_buf == NULL) {
        op->saved_buf = op->buf;
        op->saved_nbytes = op->nbytes;
        op->saved_offset = op->offset;
    }
    op->buf += nr_advance;
    op->nbytes -= nr_advance;
    op->offset += nr_advance;
}

static void urev_restore_after_short_read_or_write(urev_read_or_write_op_t *op)
{
    if (op->nbytes_left == 0 && op->saved_buf != NULL) {
        op->buf = op->saved_buf;
        op->nbytes = op->saved_nbytes;
        op->offset = op->saved_offset;
    }
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
        urev_adjust_after_short_read_or_write(op, res);
        res = urev_prep_read(op->common.queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    urev_restore_after_short_read_or_write(op);
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
        urev_adjust_after_short_read_or_write(op, res);
        res = urev_prep_write(op->common.queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    urev_restore_after_short_read_or_write(op);
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
    op->nbytes_left = urev_iovecs_total_len(op->nr_vecs, op->iovecs);
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
    op->nbytes_left = urev_iovecs_total_len(op->nr_vecs, op->iovecs);
    io_uring_sqe_set_data(sqe, op);
    return 0;
}

/* NOTE: This function is not static for testing. */
void _urev_adjust_after_short_readv_or_writev(urev_readv_or_writev_op_t *op, size_t nr_advance)
{
    struct iovec *vec;

    if (op->saved_iovecs == NULL) {
        op->saved_nr_vecs = op->nr_vecs;
        op->saved_iovecs = op->iovecs;
        op->saved_offset = op->offset;
    }
    op->offset += nr_advance;

    vec = &op->iovecs[0];
    fprintf(stderr, "adjust start nr_advance=%ld, first iov_len=%ld\n", nr_advance, vec->iov_len);
    if (nr_advance >= vec->iov_len && op->saved_iov_base != NULL) {
        nr_advance -= vec->iov_len;

        vec->iov_len += vec->iov_base - op->saved_iov_base;
        fprintf(stderr, "restoring iov_len=%ld, iov_base=%p, nr_vecs=%d\n", vec->iov_len, op->saved_iov_base, op->nr_vecs);
        vec->iov_base = op->saved_iov_base;
        op->saved_iov_base = NULL;

        op->nr_vecs--;
        vec++;
    }
    while (nr_advance > 0 && op->nr_vecs > 0 && nr_advance > vec->iov_len) {
        op->nr_vecs--;
        vec++;
        nr_advance -= vec->iov_len;
    }

    if (nr_advance != 0 && op->saved_iov_base == NULL) {
        op->saved_iov_base = vec->iov_base;
        fprintf(stderr, "saving iov_base=%p, nr_vecs=%d, nr_advance=%ld\n", vec->iov_base, op->nr_vecs, nr_advance);
    }
    vec->iov_base += nr_advance;
    vec->iov_len -= nr_advance;
    op->iovecs = vec;

    int i;
    fprintf(stderr, "after adjust nr_vecs=%d\n", op->nr_vecs);
    for (i = 0; i < op->nr_vecs; i++) {
        fprintf(stderr, "after adjust i=%d, iov_len=%ld, iov_base=%p\n", i, op->iovecs[i].iov_len, op->iovecs[i].iov_base);
    }

    fprintf(stderr, "after adjust saved_nr_vecs=%d\n", op->saved_nr_vecs);
    for (i = 0; i < op->saved_nr_vecs; i++) {
        fprintf(stderr, "after adjust, saved i=%d, iov_len=%ld, iov_base=%p\n", i, op->saved_iovecs[i].iov_len, op->saved_iovecs[i].iov_base);
    }
}

/* NOTE: This function is not static for testing. */
void _urev_restore_after_short_readv_or_writev(urev_readv_or_writev_op_t *op)
{
    if (op->nbytes_left == 0 && op->saved_iovecs != NULL) {
        if (op->saved_iov_base != NULL) {
            op->iovecs[0].iov_len += op->iovecs[0].iov_base - op->saved_iov_base;
            op->iovecs[0].iov_base = op->saved_iov_base;
            op->saved_iov_base = NULL;
        }
        op->iovecs = op->saved_iovecs;
        op->nr_vecs = op->saved_nr_vecs;
        op->offset = op->saved_offset;
    }
}

void urev_handle_short_readv(urev_readv_or_writev_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_readv(op->common.queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }
    
    op->nbytes_left -= res;
    if (op->nbytes_left) {
        _urev_adjust_after_short_readv_or_writev(op, res);
        res = urev_prep_readv(op->common.queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    _urev_restore_after_short_readv_or_writev(op);
}

void urev_handle_short_writev(urev_readv_or_writev_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_writev(op->common.queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }
    
    op->nbytes_left -= res;
    if (op->nbytes_left) {
        _urev_adjust_after_short_readv_or_writev(op, res);
        res = urev_prep_writev(op->common.queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    _urev_restore_after_short_readv_or_writev(op);
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

static inline void urev_handle_accept(urev_op_common_t *common)
{
    urev_accept_op_t *op = (urev_accept_op_t *) common;
    op->handler(op);
}

static inline void urev_handle_fsync(urev_op_common_t *common)
{
    urev_fsync_op_t *op = (urev_fsync_op_t *) common;
    op->handler(op);
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
    case IORING_OP_ACCEPT:
        urev_handle_accept(op);
        break;
    case IORING_OP_FSYNC:
        urev_handle_fsync(op);
        break;
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
