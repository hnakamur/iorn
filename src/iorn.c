#include <errno.h>
#include <stdio.h>
#include "iorn.h"

static int iorn_get_sqe(iorn_queue_t *queue, struct io_uring_sqe **sqe)
{
    int ret;

    for (;;) {
        *sqe = io_uring_get_sqe(&queue->ring);
        if (*sqe != NULL) {
            return 0;
        }

        ret = iorn_submit(queue);
        if (ret < 0) {
            return ret;
        }
    }
}

static inline void iorn_prep_common(iorn_op_common_t *common, struct io_uring_sqe *sqe)
{
    common->opcode = sqe->opcode;
    io_uring_sqe_set_flags(sqe, common->sqe_flags);
    io_uring_sqe_set_data(sqe, common);
}

int iorn_prep_accept(iorn_queue_t *queue, iorn_accept_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_accept(sqe, op->fd, op->addr, op->addrlen, op->flags);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_connect(iorn_queue_t *queue, iorn_connect_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_connect(sqe, op->fd, op->addr, op->addrlen);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_close(iorn_queue_t *queue, iorn_close_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_close(sqe, op->fd);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_fadvise(iorn_queue_t *queue, iorn_fadvise_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_fadvise(sqe, op->fd, op->offset, op->len, op->advice);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_fallocate(iorn_queue_t *queue, iorn_fallocate_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_fallocate(sqe, op->fd, op->mode, op->offset, op->len);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_fsync(iorn_queue_t *queue, iorn_fsync_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_fsync(sqe, op->fd, op->fsync_flags);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_madvise(iorn_queue_t *queue, iorn_madvise_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_madvise(sqe, op->addr, op->length, op->advice);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_openat(iorn_queue_t *queue, iorn_openat_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_openat(sqe, op->dfd, op->path, op->flags, op->mode);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_openat2(iorn_queue_t *queue, iorn_openat2_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_openat2(sqe, op->dfd, op->path, op->how);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_splice(iorn_queue_t *queue, iorn_splice_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_splice(sqe, op->fd_in, op->off_in,
        op->fd_out, op->off_out, op->nbytes, op->splice_flags);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_statx(iorn_queue_t *queue, iorn_statx_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_statx(sqe, op->dfd, op->path, op->flags, op->mask, op->statxbuf);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_recv(iorn_queue_t *queue, iorn_recv_or_send_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_recv(sqe, op->sockfd, op->buf, op->len, op->flags);
    iorn_prep_common(&op->common, sqe);
    op->nbytes_total = op->len;
    op->nbytes_done = 0;
    op->saved_buf = NULL;
    return 0;
}

int iorn_prep_send(iorn_queue_t *queue, iorn_recv_or_send_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_send(sqe, op->sockfd, op->buf, op->len, op->flags);
    iorn_prep_common(&op->common, sqe);
    op->nbytes_total = op->len;
    op->nbytes_done = 0;
    op->saved_buf = NULL;
    return 0;
}

int iorn_prep_recvmsg(iorn_queue_t *queue, iorn_recvmsg_or_sendmsg_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_recvmsg(sqe, op->fd, op->msg, op->flags);
    iorn_prep_common(&op->common, sqe);
    op->nbytes_total = iorn_iovec_array_total_byte_len(op->msg->msg_iovlen, op->msg->msg_iov);
    op->nbytes_done = 0;
    op->saved_iov = NULL;
    op->saved_iov_base = NULL;
    return 0;
}

int iorn_prep_sendmsg(iorn_queue_t *queue, iorn_recvmsg_or_sendmsg_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_sendmsg(sqe, op->fd, op->msg, op->flags);
    iorn_prep_common(&op->common, sqe);
    op->nbytes_total = iorn_iovec_array_total_byte_len(op->msg->msg_iovlen, op->msg->msg_iov);
    op->nbytes_done = 0;
    op->saved_iov = NULL;
    op->saved_iov_base = NULL;
    return 0;
}

int iorn_prep_read(iorn_queue_t *queue, iorn_read_or_write_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_read(sqe, op->fd, op->buf, op->nbytes, op->offset);
    iorn_prep_common(&op->common, sqe);
    op->nbytes_total = op->nbytes;
    op->nbytes_done = 0;
    op->saved_buf = NULL;
    return 0;
}

int iorn_prep_write(iorn_queue_t *queue, iorn_read_or_write_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_write(sqe, op->fd, op->buf, op->nbytes, op->offset);
    iorn_prep_common(&op->common, sqe);
    op->nbytes_total = op->nbytes;
    op->nbytes_done = 0;
    op->saved_buf = NULL;
    return 0;
}

int iorn_prep_readv(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_readv(sqe, op->fd, op->iovecs, op->nr_vecs, op->offset);
    iorn_prep_common(&op->common, sqe);
    op->nbytes_total = iorn_iovec_array_total_byte_len(op->nr_vecs, op->iovecs);
    op->nbytes_done = 0;
    op->saved_iovecs = NULL;
    op->saved_iov_base = NULL;
    op->saved_offset = 0;
    return 0;
}

int iorn_prep_writev(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_writev(sqe, op->fd, op->iovecs, op->nr_vecs, op->offset);
    iorn_prep_common(&op->common, sqe);
    op->nbytes_total = iorn_iovec_array_total_byte_len(op->nr_vecs, op->iovecs);
    op->nbytes_done = 0;
    op->saved_iovecs = NULL;
    op->saved_iov_base = NULL;
    op->saved_offset = 0;
    return 0;
}

int iorn_prep_timeout(iorn_queue_t *queue, iorn_timeout_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_timeout(sqe, (struct __kernel_timespec *) &op->ts, op->count, op->flags);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

int iorn_prep_timeout_cancel(iorn_queue_t *queue, iorn_timeout_cancel_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = iorn_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_timeout_remove(sqe, (__u64) op->target_op, op->flags);
    iorn_prep_common(&op->common, sqe);
    return 0;
}

static inline void iorn_handle_accept(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_accept_op_t *op = (iorn_accept_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_connect(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_connect_op_t *op = (iorn_connect_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_close(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_close_op_t *op = (iorn_close_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_fadvise(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_fadvise_op_t *op = (iorn_fadvise_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_fallocate(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_fallocate_op_t *op = (iorn_fallocate_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_fsync(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_fsync_op_t *op = (iorn_fsync_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_madvise(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_madvise_op_t *op = (iorn_madvise_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_openat(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_openat_op_t *op = (iorn_openat_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_openat2(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_openat2_op_t *op = (iorn_openat2_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_read_or_write(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_read_or_write_op_t *op = (iorn_read_or_write_op_t *) common;
    if (common->cqe_res > 0) {
        op->nbytes_done += common->cqe_res;
    }
    op->handler(queue, op);
}

static inline void iorn_handle_readv_or_writev(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_readv_or_writev_op_t *op = (iorn_readv_or_writev_op_t *) common;
    if (common->cqe_res > 0) {
        op->nbytes_done += common->cqe_res;
    }
    op->handler(queue, op);
}

static inline void iorn_handle_recv_or_send(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_recv_or_send_op_t *op = (iorn_recv_or_send_op_t *) common;
    if (common->cqe_res > 0) {
        op->nbytes_done += common->cqe_res;
    }
    op->handler(queue, op);
}

static inline void iorn_handle_recvmsg_or_sendmsg(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_recvmsg_or_sendmsg_op_t *op = (iorn_recvmsg_or_sendmsg_op_t *) common;
    if (common->cqe_res > 0) {
        op->nbytes_done += common->cqe_res;
    }
    op->handler(queue, op);
}

static inline void iorn_handle_splice(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_splice_op_t *op = (iorn_splice_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_statx(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_statx_op_t *op = (iorn_statx_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_timeout(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_timeout_op_t *op = (iorn_timeout_op_t *) common;
    op->handler(queue, op);
}

static inline void iorn_handle_timeout_cancel(iorn_queue_t *queue, iorn_op_common_t *common)
{
    iorn_timeout_cancel_op_t *op = (iorn_timeout_cancel_op_t *) common;
    op->handler(queue, op);
}

static void iorn_handle_completion(iorn_queue_t *queue, struct io_uring_cqe *cqe)
{
    iorn_op_common_t *op;

    op = (iorn_op_common_t *) io_uring_cqe_get_data(cqe);
    op->cqe_res = cqe->res;
    if (cqe->res < 0) {
        iorn_op_set_err_code(op, -cqe->res);
    }
    op->cqe_flags = cqe->flags;

    switch (op->opcode) {
    case IORING_OP_ACCEPT:
        iorn_handle_accept(queue, op);
        break;
    case IORING_OP_CONNECT:
        iorn_handle_connect(queue, op);
        break;
    case IORING_OP_CLOSE:
        iorn_handle_close(queue, op);
        break;
    case IORING_OP_FADVISE:
        iorn_handle_fadvise(queue, op);
        break;
    case IORING_OP_FALLOCATE:
        iorn_handle_fallocate(queue, op);
        break;
    case IORING_OP_FSYNC:
        iorn_handle_fsync(queue, op);
        break;
    case IORING_OP_MADVISE:
        iorn_handle_madvise(queue, op);
        break;
    case IORING_OP_OPENAT:
        iorn_handle_openat(queue, op);
        break;
    case IORING_OP_OPENAT2:
        iorn_handle_openat2(queue, op);
        break;
    case IORING_OP_READ:
    case IORING_OP_WRITE:
        iorn_handle_read_or_write(queue, op);
        break;
    case IORING_OP_READV:
    case IORING_OP_WRITEV:
        iorn_handle_readv_or_writev(queue, op);
        break;
    case IORING_OP_RECV:
    case IORING_OP_SEND:
        iorn_handle_recv_or_send(queue, op);
        break;
    case IORING_OP_RECVMSG:
    case IORING_OP_SENDMSG:
        iorn_handle_recvmsg_or_sendmsg(queue, op);
        break;
    case IORING_OP_SPLICE:
        iorn_handle_splice(queue, op);
        break;
    case IORING_OP_STATX:
        iorn_handle_statx(queue, op);
        break;
    case IORING_OP_TIMEOUT:
        iorn_handle_timeout(queue, op);
        break;
    case IORING_OP_TIMEOUT_REMOVE:
        iorn_handle_timeout_cancel(queue, op);
        break;
    default:
        fprintf(stderr, "unsupported opcode in iorn_handle_completion, opcode=%d\n", op->opcode);
        break;
    }
}

int iorn_wait_and_handle_completion(iorn_queue_t *queue)
{
    int ret;
    struct io_uring_cqe *cqe;

    ret = io_uring_wait_cqe(&queue->ring, &cqe);
    if (cqe != NULL) {
        iorn_handle_completion(queue, cqe);
    }
    io_uring_cqe_seen(&queue->ring, cqe);
    return ret;
}

void iorn_peek_and_handle_completions(iorn_queue_t *queue)
{
    struct io_uring_cqe *cqe;
    unsigned head;
    unsigned cqe_count;

    cqe_count = 0;
    io_uring_for_each_cqe(&queue->ring, head, cqe) {
        cqe_count++;
        iorn_handle_completion(queue, cqe);
    }
    io_uring_cq_advance(&queue->ring, cqe_count);
}

int iorn_wait_and_handle_completions(iorn_queue_t *queue)
{
    int ret;

    ret = iorn_wait_and_handle_completion(queue);
    if (ret < 0) {
        return ret;
    }

    iorn_peek_and_handle_completions(queue);
    return 0;
}

int iorn_submit(iorn_queue_t *queue)
{
    int ret;

    for (;;) {
        ret = io_uring_submit(&queue->ring);
        if (ret >= 0) {
            return ret;
        }

        if (ret == -EAGAIN || ret == -EBUSY) {
            ret = iorn_wait_and_handle_completion(queue);
            if (ret < 0) {
                return ret;
            }
        } else {
            return ret;
        }
    }
}

void iorn_handle_short_read(iorn_queue_t *queue, iorn_read_or_write_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = iorn_prep_read(queue, op);
        }
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        op->offset += res;
        op->nbytes = iorn_iovec_adjust_after_short(op->nbytes, (void **) &op->buf, res, &op->saved_buf);
        res = iorn_prep_read(queue, op);
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done == op->nbytes_total) {
        if (op->saved_buf != NULL) {
            op->offset -= (char *) op->saved_buf - (char *) op->buf;
        }
        op->nbytes = iorn_iovec_restore_from_short_adjust(op->nbytes, (void **) &op->buf, &op->saved_buf);
    }
}

void iorn_handle_short_write(iorn_queue_t *queue, iorn_read_or_write_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = iorn_prep_write(queue, op);
        }
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        op->offset += res;
        op->nbytes = iorn_iovec_adjust_after_short(op->nbytes, (void **) &op->buf, res, &op->saved_buf);
        res = iorn_prep_write(queue, op);
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done == op->nbytes_total) {
        if (op->saved_buf != NULL) {
            op->offset -= (char *) op->saved_buf - (char *) op->buf;
        }
        op->nbytes = iorn_iovec_restore_from_short_adjust(op->nbytes, (void **) &op->buf, &op->saved_buf);
    }
}

void iorn_handle_short_recv(iorn_queue_t *queue, iorn_recv_or_send_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = iorn_prep_recv(queue, op);
        }
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        op->len = iorn_iovec_adjust_after_short(op->len, (void **) &op->buf, res, &op->saved_buf);
        res = iorn_prep_recv(queue, op);
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done == op->nbytes_total) {
        op->len = iorn_iovec_restore_from_short_adjust(op->len, (void **) &op->buf, &op->saved_buf);
    }
}

void iorn_handle_short_send(iorn_queue_t *queue, iorn_recv_or_send_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = iorn_prep_send(queue, op);
        }
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        op->len = iorn_iovec_adjust_after_short(op->len, (void **) &op->buf, res, &op->saved_buf);
        res = iorn_prep_send(queue, op);
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done == op->nbytes_total) {
        op->len = iorn_iovec_restore_from_short_adjust(op->len, (void **) &op->buf, &op->saved_buf);
    }
}

void iorn_handle_short_readv(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = iorn_prep_readv(queue, op);
        }
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        if (op->saved_iovecs == NULL) {
            op->saved_offset = op->offset;
        }
        op->offset += res;
        op->nr_vecs = iorn_iovec_array_adjust_after_short(op->nr_vecs, &op->iovecs, res, &op->saved_iovecs, &op->saved_iov_base);
        res = iorn_prep_readv(queue, op);
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done == op->nbytes_total) {
        if (op->saved_iovecs != NULL) {
            op->offset = op->saved_offset;
        }
        op->nr_vecs = iorn_iovec_array_restore_from_short_adjust(op->nr_vecs, &op->iovecs, &op->saved_iovecs, &op->saved_iov_base);
    }
}

void iorn_handle_short_writev(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = iorn_prep_writev(queue, op);
        }
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        if (op->saved_iovecs == NULL) {
            op->saved_offset = op->offset;
        }
        op->offset += res;
        op->nr_vecs = iorn_iovec_array_adjust_after_short(op->nr_vecs, &op->iovecs, res, &op->saved_iovecs, &op->saved_iov_base);
        res = iorn_prep_writev(queue, op);
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done == op->nbytes_total) {
        if (op->saved_iovecs != NULL) {
            op->offset = op->saved_offset;
        }
        op->nr_vecs = iorn_iovec_array_restore_from_short_adjust(op->nr_vecs, &op->iovecs, &op->saved_iovecs, &op->saved_iov_base);
    }
}

void iorn_handle_short_recvmsg(iorn_queue_t *queue, iorn_recvmsg_or_sendmsg_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = iorn_prep_recvmsg(queue, op);
        }
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        op->msg->msg_iovlen = iorn_iovec_array_adjust_after_short(op->msg->msg_iovlen, &op->msg->msg_iov, res, &op->saved_iov, &op->saved_iov_base);
        res = iorn_prep_recvmsg(queue, op);
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done == op->nbytes_total) {
        op->msg->msg_iovlen = iorn_iovec_array_restore_from_short_adjust(op->msg->msg_iovlen, &op->msg->msg_iov, &op->saved_iov, &op->saved_iov_base);
    }
}

void iorn_handle_short_sendmsg(iorn_queue_t *queue, iorn_recvmsg_or_sendmsg_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = iorn_prep_sendmsg(queue, op);
        }
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        op->msg->msg_iovlen = iorn_iovec_array_adjust_after_short(op->msg->msg_iovlen, &op->msg->msg_iov, res, &op->saved_iov, &op->saved_iov_base);
        res = iorn_prep_sendmsg(queue, op);
        if (res < 0) {
            iorn_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done == op->nbytes_total) {
        op->msg->msg_iovlen = iorn_iovec_array_restore_from_short_adjust(op->msg->msg_iovlen, &op->msg->msg_iov, &op->saved_iov, &op->saved_iov_base);
    }
}
