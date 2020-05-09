#include <errno.h>
#include <stdio.h>
#include "urev.h"

static int urev_get_sqe(urev_queue_t *queue, struct io_uring_sqe **sqe)
{
    int ret;

    for (;;) {
        *sqe = io_uring_get_sqe(&queue->ring);
        if (*sqe != NULL) {
            return 0;
        }

        ret = urev_submit(queue);
        if (ret < 0) {
            return ret;
        }
    }
}

static size_t urev_iovecs_total_len(size_t nr_vecs, struct iovec *iovecs)
{
    size_t i;
    size_t len;

    len = 0;
    for (i = 0; i < nr_vecs; i++) {
        len += iovecs[i].iov_len;
    }
    return len;
}

static inline void urev_prep_common(urev_op_common_t *common, struct io_uring_sqe *sqe)
{
    common->opcode = sqe->opcode;
    io_uring_sqe_set_flags(sqe, common->sqe_flags);
    io_uring_sqe_set_data(sqe, common);
}

int urev_prep_accept(urev_queue_t *queue, urev_accept_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_accept(sqe, op->fd, op->addr, op->addrlen, op->flags);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_connect(urev_queue_t *queue, urev_connect_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_connect(sqe, op->fd, op->addr, op->addrlen);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_close(urev_queue_t *queue, urev_close_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_close(sqe, op->fd);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_fadvise(urev_queue_t *queue, urev_fadvise_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_fadvise(sqe, op->fd, op->offset, op->len, op->advice);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_fallocate(urev_queue_t *queue, urev_fallocate_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_fallocate(sqe, op->fd, op->mode, op->offset, op->len);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_fsync(urev_queue_t *queue, urev_fsync_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_fsync(sqe, op->fd, op->fsync_flags);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_madvise(urev_queue_t *queue, urev_madvise_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_madvise(sqe, op->addr, op->length, op->advice);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_openat(urev_queue_t *queue, urev_openat_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_openat(sqe, op->dfd, op->path, op->flags, op->mode);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_openat2(urev_queue_t *queue, urev_openat2_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_openat2(sqe, op->dfd, op->path, op->how);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_splice(urev_queue_t *queue, urev_splice_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_splice(sqe, op->fd_in, op->off_in,
        op->fd_out, op->off_out, op->nbytes, op->splice_flags);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_statx(urev_queue_t *queue, urev_statx_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_statx(sqe, op->dfd, op->path, op->flags, op->mask, op->statxbuf);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_recv(urev_queue_t *queue, urev_recv_or_send_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_recv(sqe, op->sockfd, op->buf, op->len, op->flags);
    urev_prep_common(&op->common, sqe);
    op->nbytes_total = op->len;
    op->nbytes_done = 0;
    op->saved_buf = NULL;
    op->saved_len = 0;
    return 0;
}

int urev_prep_send(urev_queue_t *queue, urev_recv_or_send_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_send(sqe, op->sockfd, op->buf, op->len, op->flags);
    urev_prep_common(&op->common, sqe);
    op->nbytes_total = op->len;
    op->nbytes_done = 0;
    op->saved_buf = NULL;
    op->saved_len = 0;
    return 0;
}

int urev_prep_recvmsg(urev_queue_t *queue, urev_recvmsg_or_sendmsg_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_recvmsg(sqe, op->fd, op->msg, op->flags);
    urev_prep_common(&op->common, sqe);
    op->nbytes_total = urev_iovecs_total_len(op->msg->msg_iovlen, op->msg->msg_iov);
    op->nbytes_done = 0;
    op->saved_iovlen = 0;
    op->saved_iov = NULL;
    op->saved_iov_base = NULL;
    return 0;
}

int urev_prep_sendmsg(urev_queue_t *queue, urev_recvmsg_or_sendmsg_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_sendmsg(sqe, op->fd, op->msg, op->flags);
    urev_prep_common(&op->common, sqe);
    op->nbytes_total = urev_iovecs_total_len(op->msg->msg_iovlen, op->msg->msg_iov);
    op->nbytes_done = 0;
    op->saved_iovlen = 0;
    op->saved_iov = NULL;
    op->saved_iov_base = NULL;
    return 0;
}

int urev_prep_read(urev_queue_t *queue, urev_read_or_write_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_read(sqe, op->fd, op->buf, op->nbytes, op->offset);
    urev_prep_common(&op->common, sqe);
    op->nbytes_total = op->nbytes;
    op->nbytes_done = 0;
    op->saved_buf = NULL;
    op->saved_nbytes = 0;
    op->saved_offset = 0;
    return 0;
}

int urev_prep_write(urev_queue_t *queue, urev_read_or_write_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_write(sqe, op->fd, op->buf, op->nbytes, op->offset);
    urev_prep_common(&op->common, sqe);
    op->nbytes_total = op->nbytes;
    op->nbytes_done = 0;
    op->saved_buf = NULL;
    op->saved_nbytes = 0;
    op->saved_offset = 0;
    return 0;
}

int urev_prep_readv(urev_queue_t *queue, urev_readv_or_writev_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_readv(sqe, op->fd, op->iovecs, op->nr_vecs, op->offset);
    urev_prep_common(&op->common, sqe);
    op->nbytes_total = urev_iovecs_total_len(op->nr_vecs, op->iovecs);
    op->nbytes_done = 0;
    op->saved_nr_vecs = 0;
    op->saved_iovecs = NULL;
    op->saved_iov_base = NULL;
    op->saved_offset = 0;
    return 0;
}

int urev_prep_writev(urev_queue_t *queue, urev_readv_or_writev_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_writev(sqe, op->fd, op->iovecs, op->nr_vecs, op->offset);
    urev_prep_common(&op->common, sqe);
    op->nbytes_total = urev_iovecs_total_len(op->nr_vecs, op->iovecs);
    op->nbytes_done = 0;
    op->saved_nr_vecs = 0;
    op->saved_iovecs = NULL;
    op->saved_iov_base = NULL;
    op->saved_offset = 0;
    return 0;
}

int urev_prep_timeout(urev_queue_t *queue, urev_timeout_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_timeout(sqe, (struct __kernel_timespec *) &op->ts, op->count, op->flags);
    urev_prep_common(&op->common, sqe);
    return 0;
}

int urev_prep_timeout_cancel(urev_queue_t *queue, urev_timeout_cancel_op_t *op)
{
    struct io_uring_sqe *sqe;
    int ret;

    ret = urev_get_sqe(queue, &sqe);
    if (ret < 0) {
        return ret;
    }
    io_uring_prep_timeout_remove(sqe, (__u64) op->target_op, op->flags);
    urev_prep_common(&op->common, sqe);
    return 0;
}

static inline void urev_handle_accept(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_accept_op_t *op = (urev_accept_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_connect(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_connect_op_t *op = (urev_connect_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_close(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_close_op_t *op = (urev_close_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_fadvise(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_fadvise_op_t *op = (urev_fadvise_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_fallocate(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_fallocate_op_t *op = (urev_fallocate_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_fsync(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_fsync_op_t *op = (urev_fsync_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_madvise(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_madvise_op_t *op = (urev_madvise_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_openat(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_openat_op_t *op = (urev_openat_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_openat2(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_openat2_op_t *op = (urev_openat2_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_read_or_write(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_read_or_write_op_t *op = (urev_read_or_write_op_t *) common;
    if (common->cqe_res > 0) {
        op->nbytes_done += common->cqe_res;
    }
    op->handler(queue, op);
}

static inline void urev_handle_readv_or_writev(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_readv_or_writev_op_t *op = (urev_readv_or_writev_op_t *) common;
    if (common->cqe_res > 0) {
        op->nbytes_done += common->cqe_res;
    }
    op->handler(queue, op);
}

static inline void urev_handle_recv_or_send(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_recv_or_send_op_t *op = (urev_recv_or_send_op_t *) common;
    if (common->cqe_res > 0) {
        op->nbytes_done += common->cqe_res;
    }
    op->handler(queue, op);
}

static inline void urev_handle_recvmsg_or_sendmsg(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_recvmsg_or_sendmsg_op_t *op = (urev_recvmsg_or_sendmsg_op_t *) common;
    if (common->cqe_res > 0) {
        op->nbytes_done += common->cqe_res;
    }
    op->handler(queue, op);
}

static inline void urev_handle_splice(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_splice_op_t *op = (urev_splice_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_statx(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_statx_op_t *op = (urev_statx_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_timeout(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_timeout_op_t *op = (urev_timeout_op_t *) common;
    op->handler(queue, op);
}

static inline void urev_handle_timeout_cancel(urev_queue_t *queue, urev_op_common_t *common)
{
    urev_timeout_cancel_op_t *op = (urev_timeout_cancel_op_t *) common;
    op->handler(queue, op);
}

static void urev_handle_completion(urev_queue_t *queue, struct io_uring_cqe *cqe)
{
    urev_op_common_t *op;

    op = (urev_op_common_t *) io_uring_cqe_get_data(cqe);
    op->cqe_res = cqe->res;
    if (cqe->res < 0) {
        urev_op_set_err_code(op, -cqe->res);
    }
    op->cqe_flags = cqe->flags;

    switch (op->opcode) {
    case IORING_OP_ACCEPT:
        urev_handle_accept(queue, op);
        break;
    case IORING_OP_CONNECT:
        urev_handle_connect(queue, op);
        break;
    case IORING_OP_CLOSE:
        urev_handle_close(queue, op);
        break;
    case IORING_OP_FADVISE:
        urev_handle_fadvise(queue, op);
        break;
    case IORING_OP_FALLOCATE:
        urev_handle_fallocate(queue, op);
        break;
    case IORING_OP_FSYNC:
        urev_handle_fsync(queue, op);
        break;
    case IORING_OP_MADVISE:
        urev_handle_madvise(queue, op);
        break;
    case IORING_OP_OPENAT:
        urev_handle_openat(queue, op);
        break;
    case IORING_OP_OPENAT2:
        urev_handle_openat2(queue, op);
        break;
    case IORING_OP_READ:
    case IORING_OP_WRITE:
        urev_handle_read_or_write(queue, op);
        break;
    case IORING_OP_READV:
    case IORING_OP_WRITEV:
        urev_handle_readv_or_writev(queue, op);
        break;
    case IORING_OP_RECV:
    case IORING_OP_SEND:
        urev_handle_recv_or_send(queue, op);
        break;
    case IORING_OP_RECVMSG:
    case IORING_OP_SENDMSG:
        urev_handle_recvmsg_or_sendmsg(queue, op);
        break;
    case IORING_OP_SPLICE:
        urev_handle_splice(queue, op);
        break;
    case IORING_OP_STATX:
        urev_handle_statx(queue, op);
        break;
    case IORING_OP_TIMEOUT:
        urev_handle_timeout(queue, op);
        break;
    case IORING_OP_TIMEOUT_REMOVE:
        urev_handle_timeout_cancel(queue, op);
        break;
    default:
        fprintf(stderr, "unsupported opcode in urev_handle_completion, opcode=%d\n", op->opcode);
        break;
    }
}

int urev_wait_and_handle_completion(urev_queue_t *queue)
{
    int ret;
    struct io_uring_cqe *cqe;

    ret = io_uring_wait_cqe(&queue->ring, &cqe);
    if (cqe != NULL) {
        urev_handle_completion(queue, cqe);
    }
    io_uring_cqe_seen(&queue->ring, cqe);
    return ret;
}

void urev_peek_and_handle_completions(urev_queue_t *queue)
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

int urev_wait_and_handle_completions(urev_queue_t *queue)
{
    int ret;

    ret = urev_wait_and_handle_completion(queue);
    if (ret < 0) {
        return ret;
    }

    urev_peek_and_handle_completions(queue);
    return 0;
}

int urev_submit(urev_queue_t *queue)
{
    int ret;

    for (;;) {
        ret = io_uring_submit(&queue->ring);
        if (ret >= 0) {
            return ret;
        }

        if (ret == -EAGAIN || ret == -EBUSY) {
            ret = urev_wait_and_handle_completion(queue);
            if (ret < 0) {
                return ret;
            }
        } else {
            return ret;
        }
    }
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
    if (op->nbytes_done == op->nbytes_total && op->saved_buf != NULL) {
        op->buf = op->saved_buf;
        op->nbytes = op->saved_nbytes;
        op->offset = op->saved_offset;
    }
}

void urev_handle_short_read(urev_queue_t *queue, urev_read_or_write_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_read(queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        urev_adjust_after_short_read_or_write(op, res);
        res = urev_prep_read(queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    urev_restore_after_short_read_or_write(op);
}

void urev_handle_short_write(urev_queue_t *queue, urev_read_or_write_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_write(queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        urev_adjust_after_short_read_or_write(op, res);
        res = urev_prep_write(queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    urev_restore_after_short_read_or_write(op);
}

static void urev_adjust_after_short_recv_or_send(urev_recv_or_send_op_t *op, size_t nr_advance)
{
    if (op->saved_buf == NULL) {
        op->saved_buf = op->buf;
        op->saved_len = op->len;
    }
    op->buf += nr_advance;
    op->len -= nr_advance;
}

static void urev_restore_after_short_recv_or_send(urev_recv_or_send_op_t *op)
{
    if (op->nbytes_done == op->nbytes_total && op->saved_buf != NULL) {
        op->buf = op->saved_buf;
        op->saved_len = op->len;
    }
}

void urev_handle_short_recv(urev_queue_t *queue, urev_recv_or_send_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_recv(queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        urev_adjust_after_short_recv_or_send(op, res);
        res = urev_prep_recv(queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    urev_restore_after_short_recv_or_send(op);
}

void urev_handle_short_send(urev_queue_t *queue, urev_recv_or_send_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_send(queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        urev_adjust_after_short_recv_or_send(op, res);
        res = urev_prep_send(queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    urev_restore_after_short_recv_or_send(op);
}

/* NOTE: This function is not static for testing. */
void __urev_adjust_after_short_readv_or_writev(urev_readv_or_writev_op_t *op, size_t nr_advance)
{
    struct iovec *vec;

    if (op->saved_iovecs == NULL) {
        op->saved_nr_vecs = op->nr_vecs;
        op->saved_iovecs = op->iovecs;
        op->saved_offset = op->offset;
    }
    op->offset += nr_advance;

    vec = &op->iovecs[0];
    if (nr_advance >= vec->iov_len && op->saved_iov_base != NULL) {
        nr_advance -= vec->iov_len;

        vec->iov_len += vec->iov_base - op->saved_iov_base;
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
    }
    vec->iov_base += nr_advance;
    vec->iov_len -= nr_advance;
    op->iovecs = vec;
}

/* NOTE: This function is not static for testing. */
void __urev_restore_after_short_readv_or_writev(urev_readv_or_writev_op_t *op)
{
    if (op->nbytes_done == op->nbytes_total && op->saved_iovecs != NULL) {
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

void urev_handle_short_readv(urev_queue_t *queue, urev_readv_or_writev_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_readv(queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        __urev_adjust_after_short_readv_or_writev(op, res);
        res = urev_prep_readv(queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    __urev_restore_after_short_readv_or_writev(op);
}

void urev_handle_short_writev(urev_queue_t *queue, urev_readv_or_writev_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_writev(queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        __urev_adjust_after_short_readv_or_writev(op, res);
        res = urev_prep_writev(queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    __urev_restore_after_short_readv_or_writev(op);
}

/* NOTE: This function is not static for testing. */
void __urev_adjust_after_short_recvmsg_or_sendmsg(urev_recvmsg_or_sendmsg_op_t *op, size_t nr_advance)
{
    struct iovec *vec;

    if (op->saved_iov == NULL) {
        op->saved_iovlen = op->msg->msg_iovlen;
        op->saved_iov = op->msg->msg_iov;
    }

    vec = &op->msg->msg_iov[0];
    if (nr_advance >= vec->iov_len && op->saved_iov_base != NULL) {
        nr_advance -= vec->iov_len;

        vec->iov_len += vec->iov_base - op->saved_iov_base;
        vec->iov_base = op->saved_iov_base;
        op->saved_iov_base = NULL;

        op->msg->msg_iovlen--;
        vec++;
    }
    while (nr_advance > 0 && op->msg->msg_iovlen > 0 && nr_advance > vec->iov_len) {
        op->msg->msg_iovlen--;
        vec++;
        nr_advance -= vec->iov_len;
    }

    if (nr_advance != 0 && op->saved_iov_base == NULL) {
        op->saved_iov_base = vec->iov_base;
    }
    vec->iov_base += nr_advance;
    vec->iov_len -= nr_advance;
    op->msg->msg_iov = vec;
}

/* NOTE: This function is not static for testing. */
void __urev_restore_after_short_recvmsg_or_sendmsg(urev_recvmsg_or_sendmsg_op_t *op)
{
    if (op->nbytes_done == op->nbytes_total && op->saved_iov != NULL) {
        if (op->saved_iov_base != NULL) {
            op->msg->msg_iov[0].iov_len += op->msg->msg_iov[0].iov_base - op->saved_iov_base;
            op->msg->msg_iov[0].iov_base = op->saved_iov_base;
            op->saved_iov_base = NULL;
        }
        op->msg->msg_iov = op->saved_iov;
        op->msg->msg_iovlen = op->saved_iovlen;
    }
}

void urev_handle_short_recvmsg(urev_queue_t *queue, urev_recvmsg_or_sendmsg_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_recvmsg(queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        __urev_adjust_after_short_recvmsg_or_sendmsg(op, res);
        res = urev_prep_recvmsg(queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    __urev_restore_after_short_recvmsg_or_sendmsg(op);
}

void urev_handle_short_sendmsg(urev_queue_t *queue, urev_recvmsg_or_sendmsg_op_t *op)
{
    int res;

    res = op->common.cqe_res;
    if (res < 0) {
        if (res == -EAGAIN) {
            res = urev_prep_sendmsg(queue, op);
        }
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    if (op->nbytes_done < op->nbytes_total) {
        __urev_adjust_after_short_recvmsg_or_sendmsg(op, res);
        res = urev_prep_sendmsg(queue, op);
        if (res < 0) {
            urev_op_set_err_code(&op->common, -res);
        }
        return;
    }

    __urev_restore_after_short_recvmsg_or_sendmsg(op);
}
