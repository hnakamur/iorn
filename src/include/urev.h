#ifndef UREV_H
#define UREV_H

#include <liburing.h>

typedef struct urev_queue urev_queue_t;

typedef struct urev_op_common             urev_op_common_t;
typedef struct urev_accept_op             urev_accept_op_t;
typedef struct urev_connect_op            urev_connect_op_t;
typedef struct urev_close_op              urev_close_op_t;
typedef struct urev_fadvise_op            urev_fadvise_op_t;
typedef struct urev_fallocate_op          urev_fallocate_op_t;
typedef struct urev_fsync_op              urev_fsync_op_t;
typedef struct urev_madvise_op            urev_madvise_op_t;
typedef struct urev_openat_op             urev_openat_op_t;
typedef struct urev_openat2_op            urev_openat2_op_t;
typedef struct urev_recv_or_send_op       urev_recv_or_send_op_t;
typedef struct urev_recvmsg_or_sendmsg_op urev_recvmsg_or_sendmsg_op_t;
typedef struct urev_read_or_write_op      urev_read_or_write_op_t;
typedef struct urev_readv_or_writev_op    urev_readv_or_writev_op_t;
typedef struct urev_splice_op             urev_splice_op_t;
typedef struct urev_statx_op              urev_statx_op_t;
typedef struct urev_timeout_op            urev_timeout_op_t;
typedef struct urev_timeout_cancel_op     urev_timeout_cancel_op_t;

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

/**
 * completion handler type for a accept operation.
 * @param [in,out] op     a accept operation.
 */
typedef void (*urev_accept_handler_t)(urev_accept_op_t *op);

/**
 * completion handler type for a connect operation.
 * @param [in,out] op     a connect operation.
 */
typedef void (*urev_connect_handler_t)(urev_connect_op_t *op);

/**
 * completion handler type for a close operation.
 * @param [in,out] op     a close operation.
 */
typedef void (*urev_close_handler_t)(urev_close_op_t *op);

/**
 * completion handler type for a fadvise operation.
 * @param [in,out] op     a fadvise operation.
 */
typedef void (*urev_fadvise_handler_t)(urev_fadvise_op_t *op);

/**
 * completion handler type for a fallocate operation.
 * @param [in,out] op     a fallocate operation.
 */
typedef void (*urev_fallocate_handler_t)(urev_fallocate_op_t *op);

/**
 * completion handler type for a fsync operation.
 * @param [in,out] op     a fsync operation.
 */
typedef void (*urev_fsync_handler_t)(urev_fsync_op_t *op);

/**
 * completion handler type for a madvise operation.
 * @param [in,out] op     a madvise operation.
 */
typedef void (*urev_madvise_handler_t)(urev_madvise_op_t *op);

/**
 * completion handler type for a openat operation.
 * @param [in,out] op     a openat operation.
 */
typedef void (*urev_openat_handler_t)(urev_openat_op_t *op);

/**
 * completion handler type for a openat2 operation.
 * @param [in,out] op     a openat2 operation.
 */
typedef void (*urev_openat2_handler_t)(urev_openat2_op_t *op);

/**
 * completion handler type for a read or write operation.
 * @param [in,out] op     a read or write operation.
 */
typedef void (*urev_read_or_write_handler_t)(urev_read_or_write_op_t *op);

/**
 * completion handler type for a readv or writev operation.
 * @param [in,out] op     a readv or writev operation.
 */
typedef void (*urev_readv_or_writev_handler_t)(urev_readv_or_writev_op_t *op);

/**
 * completion handler type for a recv or send operation.
 * @param [in,out] op     a recv or send operation.
 */
typedef void (*urev_recv_or_send_handler_t)(urev_recv_or_send_op_t *op);

/**
 * completion handler type for a recvmsg or sendmsg operation.
 * @param [in,out] op     a recvmsg or sendmsg operation.
 */
typedef void (*urev_recvmsg_or_sendmsg_handler_t)(urev_recvmsg_or_sendmsg_op_t *op);

/**
 * completion handler type for a splice operation.
 * @param [in,out] op     a splice operation.
 */
typedef void (*urev_splice_handler_t)(urev_splice_op_t *op);

/**
 * completion handler type for a statx operation.
 * @param [in,out] op     a statx operation.
 */
typedef void (*urev_statx_handler_t)(urev_statx_op_t *op);

/**
 * completion handler type for a timeout operation.
 * @param [in,out] op     a timeout operation.
 */
typedef void (*urev_timeout_handler_t)(urev_timeout_op_t *op);
/**
 * completion handler type for a timeout_remove operation.
 * @param [in,out] op     a timeout_remove operation.
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
    urev_op_common_t      common; // must be the first field
    urev_accept_handler_t handler;

    int              fd;
    struct sockaddr *addr;
    socklen_t       *addrlen;
    int              flags;
};

struct urev_connect_op {
    urev_op_common_t       common; // must be the first field
    urev_connect_handler_t handler;

    int              fd;
    struct sockaddr *addr;
    socklen_t        addrlen;
};

struct urev_close_op {
    urev_op_common_t     common; // must be the first field
    urev_close_handler_t handler;

    int fd;
};

struct urev_fadvise_op {
    urev_op_common_t       common; // must be the first field
    urev_fadvise_handler_t handler;

    int   fd;
    off_t offset;
    off_t len;
    int   advice;
};

struct urev_fallocate_op {
    urev_op_common_t         common; // must be the first field
    urev_fallocate_handler_t handler;

    int   fd;
    int   mode;
    off_t offset;
    off_t len;
};

struct urev_fsync_op {
    urev_op_common_t     common; // must be the first field
    urev_fsync_handler_t handler;

    int      fd;
    unsigned fsync_flags;
};

struct urev_madvise_op {
    urev_op_common_t       common; // must be the first field
    urev_madvise_handler_t handler;

    void  *addr;
    off_t  length;
    int    advice;
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
    urev_op_common_t             common; // must be the first field
    urev_read_or_write_handler_t handler;

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

struct urev_readv_or_writev_op {
    urev_op_common_t               common; // must be the first field
    urev_readv_or_writev_handler_t handler;

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

struct urev_recv_or_send_op {
    urev_op_common_t            common; // must be the first field
    urev_recv_or_send_handler_t handler;

    int     sockfd;
    void   *buf;
    size_t  len;
    int     flags;

    size_t  nbytes_total;
    size_t  nbytes_done;
    void   *saved_buf;
    size_t  saved_len;
};

struct urev_recvmsg_or_sendmsg_op {
    urev_op_common_t                  common; // must be the first field
    urev_recvmsg_or_sendmsg_handler_t handler;

    int            fd;
    struct msghdr *msg;
    unsigned       flags;

    size_t        nbytes_total;
    size_t        nbytes_done;
    size_t        saved_iovlen;
    struct iovec *saved_iov;
    void         *saved_iov_base;
};

struct urev_splice_op {
    urev_op_common_t      common; // must be the first field
    urev_splice_handler_t handler;

    int          fd_in;
    uint64_t     off_in;
    int          fd_out;
    uint64_t     off_out;
    unsigned int nbytes;
    unsigned int splice_flags;
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
 * @param [in,out] op    an accept operation.
 * @return zero if success, -errno from urev_submit or urev_wait_and_handle_completion if error.
 */
int urev_prep_accept(urev_queue_t *queue, urev_accept_op_t *op);
int urev_prep_connect(urev_queue_t *queue, urev_connect_op_t *op);
int urev_prep_close(urev_queue_t *queue, urev_close_op_t *op);
int urev_prep_fsync(urev_queue_t *queue, urev_fsync_op_t *op);
int urev_prep_openat(urev_queue_t *queue, urev_openat_op_t *op);
int urev_prep_openat2(urev_queue_t *queue, urev_openat2_op_t *op);
int urev_prep_read(urev_queue_t *queue, urev_read_or_write_op_t *op);
int urev_prep_readv(urev_queue_t *queue, urev_readv_or_writev_op_t *op);
int urev_prep_recv(urev_queue_t *queue, urev_recv_or_send_op_t *op);
int urev_prep_recvmsg(urev_queue_t *queue, urev_recvmsg_or_sendmsg_op_t *op);
int urev_prep_send(urev_queue_t *queue, urev_recv_or_send_op_t *op);
int urev_prep_sendmsg(urev_queue_t *queue, urev_recvmsg_or_sendmsg_op_t *op);
int urev_prep_statx(urev_queue_t *queue, urev_statx_op_t *op);
int urev_prep_timeout(urev_queue_t *queue, urev_timeout_op_t *op);
/**
 * Get a sqe and prepare a timeout_cancel operation.
 *
 * If the submission queue is full, this function tries to make room
 * with calling urev_submit and urev_wait_and_handle_completion repeatedly.
 *
 * @param [in,out] queue a queue.
 * @param [in,out] op    a timeout_cancel operation.
 *                       op->target_op must be set to the target
 *                       timeout operation.
 * @return zero if success, -errno from urev_submit or urev_wait_and_handle_completion if error.
 */
int urev_prep_timeout_cancel(urev_queue_t *queue, urev_timeout_cancel_op_t *op);
int urev_prep_write(urev_queue_t *queue, urev_read_or_write_op_t *op);
int urev_prep_writev(urev_queue_t *queue, urev_readv_or_writev_op_t *op);

void urev_peek_and_handle_completions(urev_queue_t *queue);
int urev_wait_and_handle_completion(urev_queue_t *queue);
int urev_wait_and_handle_completions(urev_queue_t *queue);

/**
 * Submit entries in the submission queue.
 *
 * NOTE: If -EAGAIN or -EBUSY is returned from io_uring_submit,
 * this function calls urev_wait_and_handle_completion
 * and retries io_uring_submit in a loop.
 *
 * See EAGAIN and EBUSY in man io_uring_enter(2) for detail.
 * https://github.com/axboe/liburing/blob/fe500488190ff39716346ee1c0fe66bde300d0fb/man/io_uring_enter.2#L751
 *
 * @param [in,out] queue a queue.
 * @return number of submitted entries if success, -errno if error.
 */
int urev_submit(urev_queue_t *queue);

void urev_handle_short_read(urev_read_or_write_op_t *op);
void urev_handle_short_write(urev_read_or_write_op_t *op);
void urev_handle_short_readv(urev_readv_or_writev_op_t *op);
void urev_handle_short_writev(urev_readv_or_writev_op_t *op);
void urev_handle_short_recv(urev_recv_or_send_op_t *op);
void urev_handle_short_send(urev_recv_or_send_op_t *op);
void urev_handle_short_recvmsg(urev_recvmsg_or_sendmsg_op_t *op);
void urev_handle_short_sendmsg(urev_recvmsg_or_sendmsg_op_t *op);

/* NOTE: These functions are exported just for testing. */
void __urev_adjust_after_short_readv_or_writev(urev_readv_or_writev_op_t *op, size_t nr_advance);
void __urev_restore_after_short_readv_or_writev(urev_readv_or_writev_op_t *op);
void __urev_adjust_after_short_recvmsg_or_sendmsg(urev_recvmsg_or_sendmsg_op_t *op, size_t nr_advance);
void __urev_restore_after_short_recvmsg_or_sendmsg(urev_recvmsg_or_sendmsg_op_t *op);

#endif
