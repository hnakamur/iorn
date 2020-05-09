#ifndef IORN_H
#define IORN_H

#include <liburing.h>

typedef struct iorn_queue iorn_queue_t;

typedef struct iorn_op_common             iorn_op_common_t;
typedef struct iorn_accept_op             iorn_accept_op_t;
typedef struct iorn_connect_op            iorn_connect_op_t;
typedef struct iorn_close_op              iorn_close_op_t;
typedef struct iorn_fadvise_op            iorn_fadvise_op_t;
typedef struct iorn_fallocate_op          iorn_fallocate_op_t;
typedef struct iorn_fsync_op              iorn_fsync_op_t;
typedef struct iorn_madvise_op            iorn_madvise_op_t;
typedef struct iorn_openat_op             iorn_openat_op_t;
typedef struct iorn_openat2_op            iorn_openat2_op_t;
typedef struct iorn_recv_or_send_op       iorn_recv_or_send_op_t;
typedef struct iorn_recvmsg_or_sendmsg_op iorn_recvmsg_or_sendmsg_op_t;
typedef struct iorn_read_or_write_op      iorn_read_or_write_op_t;
typedef struct iorn_readv_or_writev_op    iorn_readv_or_writev_op_t;
typedef struct iorn_splice_op             iorn_splice_op_t;
typedef struct iorn_statx_op              iorn_statx_op_t;
typedef struct iorn_timeout_op            iorn_timeout_op_t;
typedef struct iorn_timeout_cancel_op     iorn_timeout_cancel_op_t;

struct iorn_queue {
    struct io_uring ring;
};

static inline int iorn_queue_init(unsigned entries, iorn_queue_t *queue,
    unsigned flags)
{
    return io_uring_queue_init(entries, &queue->ring, flags);
}

static inline void iorn_queue_exit(iorn_queue_t *queue)
{
    io_uring_queue_exit(&queue->ring);
}

/**
 * completion handler type for a accept operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         an accept operation.
 */
typedef void (*iorn_accept_handler_t)(iorn_queue_t *queue, iorn_accept_op_t *op);

/**
 * completion handler type for a connect operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a connect operation.
 */
typedef void (*iorn_connect_handler_t)(iorn_queue_t *queue, iorn_connect_op_t *op);

/**
 * completion handler type for a close operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a close operation.
 */
typedef void (*iorn_close_handler_t)(iorn_queue_t *queue, iorn_close_op_t *op);

/**
 * completion handler type for a fadvise operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a fadvise operation.
 */
typedef void (*iorn_fadvise_handler_t)(iorn_queue_t *queue, iorn_fadvise_op_t *op);

/**
 * completion handler type for a fallocate operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a fallocate operation.
 */
typedef void (*iorn_fallocate_handler_t)(iorn_queue_t *queue, iorn_fallocate_op_t *op);

/**
 * completion handler type for a fsync operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a fsync operation.
 */
typedef void (*iorn_fsync_handler_t)(iorn_queue_t *queue, iorn_fsync_op_t *op);

/**
 * completion handler type for a madvise operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a madvise operation.
 */
typedef void (*iorn_madvise_handler_t)(iorn_queue_t *queue, iorn_madvise_op_t *op);

/**
 * completion handler type for a openat operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a openat operation.
 */
typedef void (*iorn_openat_handler_t)(iorn_queue_t *queue, iorn_openat_op_t *op);

/**
 * completion handler type for a openat2 operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a openat2 operation.
 */
typedef void (*iorn_openat2_handler_t)(iorn_queue_t *queue, iorn_openat2_op_t *op);

/**
 * completion handler type for a read or write operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a read or write operation.
 */
typedef void (*iorn_read_or_write_handler_t)(iorn_queue_t *queue, iorn_read_or_write_op_t *op);

/**
 * completion handler type for a readv or writev operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a readv or writev operation.
 */
typedef void (*iorn_readv_or_writev_handler_t)(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op);

/**
 * completion handler type for a recv or send operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a recv or send operation.
 */
typedef void (*iorn_recv_or_send_handler_t)(iorn_queue_t *queue, iorn_recv_or_send_op_t *op);

/**
 * completion handler type for a recvmsg or sendmsg operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a recvmsg or sendmsg operation.
 */
typedef void (*iorn_recvmsg_or_sendmsg_handler_t)(iorn_queue_t *queue, iorn_recvmsg_or_sendmsg_op_t *op);

/**
 * completion handler type for a splice operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a splice operation.
 */
typedef void (*iorn_splice_handler_t)(iorn_queue_t *queue, iorn_splice_op_t *op);

/**
 * completion handler type for a statx operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a statx operation.
 */
typedef void (*iorn_statx_handler_t)(iorn_queue_t *queue, iorn_statx_op_t *op);

/**
 * completion handler type for a timeout operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a timeout operation.
 */
typedef void (*iorn_timeout_handler_t)(iorn_queue_t *queue, iorn_timeout_op_t *op);
/**
 * completion handler type for a timeout_remove operation.
 * @param [in,out] queue      a queue.
 * @param [in,out] op         a timeout_remove operation.
 */
typedef void (*iorn_timeout_cancel_handler_t)(iorn_queue_t *queue, iorn_timeout_cancel_op_t *op);

struct iorn_op_common {
    int           opcode;
    unsigned      sqe_flags;
    void         *op_ctx;
    int32_t       cqe_res;
    uint32_t      cqe_flags;
    int           err_code;
};

struct iorn_accept_op {
    iorn_op_common_t      common; // must be the first field
    iorn_accept_handler_t handler;

    int              fd;
    struct sockaddr *addr;
    socklen_t       *addrlen;
    int              flags;
};

struct iorn_connect_op {
    iorn_op_common_t       common; // must be the first field
    iorn_connect_handler_t handler;

    int              fd;
    struct sockaddr *addr;
    socklen_t        addrlen;
};

struct iorn_close_op {
    iorn_op_common_t     common; // must be the first field
    iorn_close_handler_t handler;

    int fd;
};

struct iorn_fadvise_op {
    iorn_op_common_t       common; // must be the first field
    iorn_fadvise_handler_t handler;

    int   fd;
    off_t offset;
    off_t len;
    int   advice;
};

struct iorn_fallocate_op {
    iorn_op_common_t         common; // must be the first field
    iorn_fallocate_handler_t handler;

    int   fd;
    int   mode;
    off_t offset;
    off_t len;
};

struct iorn_fsync_op {
    iorn_op_common_t     common; // must be the first field
    iorn_fsync_handler_t handler;

    int      fd;
    unsigned fsync_flags;
};

struct iorn_madvise_op {
    iorn_op_common_t       common; // must be the first field
    iorn_madvise_handler_t handler;

    void  *addr;
    off_t  length;
    int    advice;
};

struct iorn_openat_op {
    iorn_op_common_t      common; // must be the first field
    iorn_openat_handler_t handler;

    int         dfd;
    const char *path;
    int         flags;
    mode_t      mode;
};

struct iorn_openat2_op {
    iorn_op_common_t       common; // must be the first field
    iorn_openat2_handler_t handler;

    int              dfd;
    const char      *path;
    struct open_how *how;
};

struct iorn_read_or_write_op {
    iorn_op_common_t             common; // must be the first field
    iorn_read_or_write_handler_t handler;

    int       fd;
    void     *buf;
    unsigned  nbytes;
    off_t     offset;

    unsigned  nbytes_total;
    unsigned  nbytes_done;
    void     *saved_buf;
    unsigned  saved_nbytes;
    off_t     saved_offset;
};

struct iorn_readv_or_writev_op {
    iorn_op_common_t               common; // must be the first field
    iorn_readv_or_writev_handler_t handler;

    int           fd;
    int           nr_vecs;
    struct iovec *iovecs;
    off_t         offset;

    size_t        nbytes_total;
    size_t        nbytes_done;
    int           saved_nr_vecs;
    struct iovec *saved_iovecs;
    void         *saved_iov_base;
    off_t         saved_offset;
};

struct iorn_recv_or_send_op {
    iorn_op_common_t            common; // must be the first field
    iorn_recv_or_send_handler_t handler;

    int     sockfd;
    void   *buf;
    size_t  len;
    int     flags;

    size_t  nbytes_total;
    size_t  nbytes_done;
    void   *saved_buf;
    size_t  saved_len;
};

struct iorn_recvmsg_or_sendmsg_op {
    iorn_op_common_t                  common; // must be the first field
    iorn_recvmsg_or_sendmsg_handler_t handler;

    int            fd;
    struct msghdr *msg;
    unsigned       flags;

    size_t        nbytes_total;
    size_t        nbytes_done;
    size_t        saved_iovlen;
    struct iovec *saved_iov;
    void         *saved_iov_base;
};

struct iorn_splice_op {
    iorn_op_common_t      common; // must be the first field
    iorn_splice_handler_t handler;

    int          fd_in;
    uint64_t     off_in;
    int          fd_out;
    uint64_t     off_out;
    unsigned int nbytes;
    unsigned int splice_flags;
};

struct iorn_statx_op {
    iorn_op_common_t     common; // must be the first field
    iorn_statx_handler_t handler;

    int           dfd;
    const char   *path;
    int           flags;
    unsigned      mask;
    struct statx *statxbuf;
};

struct iorn_timeout_op {
    iorn_op_common_t       common; // must be the first field
    iorn_timeout_handler_t handler;

    struct timespec ts;
    unsigned        count;
    unsigned        flags;
};

struct iorn_timeout_cancel_op {
    iorn_op_common_t              common; // must be the first field
    iorn_timeout_cancel_handler_t handler;

    iorn_timeout_op_t *target_op;
    unsigned           flags;
};

static inline void iorn_op_set_err_code(iorn_op_common_t *common, int err_code)
{
    if (common->err_code == 0) {
        common->err_code = err_code;
    }
}

/**
 * Get a sqe and prepare an accept operation.
 *
 * If the submission queue is full, this function tries to make room
 * with calling iorn_submit and iorn_wait_and_handle_completion repeatedly.
 *
 * @param [in,out] queue a queue.
 * @param [in,out] op    an accept operation.
 * @return zero if success, -errno from iorn_submit or iorn_wait_and_handle_completion if error.
 */
int iorn_prep_accept(iorn_queue_t *queue, iorn_accept_op_t *op);
int iorn_prep_connect(iorn_queue_t *queue, iorn_connect_op_t *op);
int iorn_prep_close(iorn_queue_t *queue, iorn_close_op_t *op);
int iorn_prep_fsync(iorn_queue_t *queue, iorn_fsync_op_t *op);
int iorn_prep_openat(iorn_queue_t *queue, iorn_openat_op_t *op);
int iorn_prep_openat2(iorn_queue_t *queue, iorn_openat2_op_t *op);
int iorn_prep_read(iorn_queue_t *queue, iorn_read_or_write_op_t *op);
int iorn_prep_readv(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op);
int iorn_prep_recv(iorn_queue_t *queue, iorn_recv_or_send_op_t *op);
int iorn_prep_recvmsg(iorn_queue_t *queue, iorn_recvmsg_or_sendmsg_op_t *op);
int iorn_prep_send(iorn_queue_t *queue, iorn_recv_or_send_op_t *op);
int iorn_prep_sendmsg(iorn_queue_t *queue, iorn_recvmsg_or_sendmsg_op_t *op);
int iorn_prep_statx(iorn_queue_t *queue, iorn_statx_op_t *op);
int iorn_prep_timeout(iorn_queue_t *queue, iorn_timeout_op_t *op);
/**
 * Get a sqe and prepare a timeout_cancel operation.
 *
 * If the submission queue is full, this function tries to make room
 * with calling iorn_submit and iorn_wait_and_handle_completion repeatedly.
 *
 * @param [in,out] queue a queue.
 * @param [in,out] op    a timeout_cancel operation.
 *                       op->target_op must be set to the target
 *                       timeout operation.
 * @return zero if success, -errno from iorn_submit or iorn_wait_and_handle_completion if error.
 */
int iorn_prep_timeout_cancel(iorn_queue_t *queue, iorn_timeout_cancel_op_t *op);
int iorn_prep_write(iorn_queue_t *queue, iorn_read_or_write_op_t *op);
int iorn_prep_writev(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op);

void iorn_peek_and_handle_completions(iorn_queue_t *queue);
int iorn_wait_and_handle_completion(iorn_queue_t *queue);
int iorn_wait_and_handle_completions(iorn_queue_t *queue);

/**
 * Submit entries in the submission queue.
 *
 * NOTE: If -EAGAIN or -EBUSY is returned from io_uring_submit,
 * this function calls iorn_wait_and_handle_completion
 * and retries io_uring_submit in a loop.
 *
 * See EAGAIN and EBUSY in man io_uring_enter(2) for detail.
 * https://github.com/axboe/liburing/blob/fe500488190ff39716346ee1c0fe66bde300d0fb/man/io_uring_enter.2#L751
 *
 * @param [in,out] queue a queue.
 * @return number of submitted entries if success, -errno if error.
 */
int iorn_submit(iorn_queue_t *queue);

void iorn_handle_short_read(iorn_queue_t *queue, iorn_read_or_write_op_t *op);
void iorn_handle_short_write(iorn_queue_t *queue, iorn_read_or_write_op_t *op);
void iorn_handle_short_readv(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op);
void iorn_handle_short_writev(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op);
void iorn_handle_short_recv(iorn_queue_t *queue, iorn_recv_or_send_op_t *op);
void iorn_handle_short_send(iorn_queue_t *queue, iorn_recv_or_send_op_t *op);
void iorn_handle_short_recvmsg(iorn_queue_t *queue, iorn_recvmsg_or_sendmsg_op_t *op);
void iorn_handle_short_sendmsg(iorn_queue_t *queue, iorn_recvmsg_or_sendmsg_op_t *op);

/* NOTE: These functions are exported just for testing. */
void __iorn_adjust_after_short_readv_or_writev(iorn_readv_or_writev_op_t *op, size_t nr_advance);
void __iorn_restore_after_short_readv_or_writev(iorn_readv_or_writev_op_t *op);
void __iorn_adjust_after_short_recvmsg_or_sendmsg(iorn_recvmsg_or_sendmsg_op_t *op, size_t nr_advance);
void __iorn_restore_after_short_recvmsg_or_sendmsg(iorn_recvmsg_or_sendmsg_op_t *op);

#endif
