/* SPDX-License-Identifier: MIT */
/*
 * gcc -Wall -O2 -D_GNU_SOURCE -o urev-cp-vecs urev-cp-vecs.c -luring -lurev
 */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <liburing.h>
#include "urev.h"

#define QD    64
#define NR_VECS 8
#define BUF_LEN 4096
#define BS    (NR_VECS*BUF_LEN)

typedef struct copy_ctx {
    int    infd;
    int    outfd;
    off_t  inmode;
    off_t  insize;
    off_t  read_left;
    off_t  write_left;
    int    err_code;
    int    all_done;
} copy_ctx_t;

static int setup_context(unsigned entries, urev_queue_t *queue, copy_ctx_t *ctx)
{
    int ret;

    ret = urev_queue_init(entries, queue, 0);
    if (ret < 0) {
        fprintf(stderr, "queue_init: %s\n", strerror(-ret));
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));

    return 0;
}

static inline void set_err_code(copy_ctx_t *ctx, int err_code)
{
    if (err_code && !ctx->err_code) {
        ctx->err_code = err_code;
    }
}

static void on_src_closed(urev_close_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    set_err_code(ctx, op->common.err_code);
    ctx->infd = 0;
    free(op);

    if (ctx->infd == 0 && ctx->outfd == 0) {
        ctx->all_done = 1;
    }
}

static int queue_close_src(urev_queue_t *queue, copy_ctx_t *ctx)
{
    urev_close_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op));
    if (!op) {
        return -ENOMEM;
    }
    op->common.ctx = ctx;
    op->handler = on_src_closed;
    op->fd = ctx->infd;
    ret = urev_prep_close(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_close: %s\n", strerror(-ret));
        return ret;
    }
    return 0;
}

static void on_dest_closed(urev_close_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    set_err_code(ctx, op->common.err_code);
    ctx->outfd = 0;
    free(op);

    if (ctx->infd == 0 && ctx->outfd == 0) {
        ctx->all_done = 1;
    }
}

static int queue_close_dest(urev_queue_t *queue, copy_ctx_t *ctx)
{
    urev_close_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op));
    if (!op) {
        return -ENOMEM;
    }
    op->common.ctx = ctx;
    op->handler = on_dest_closed;
    op->fd = ctx->outfd;
    ret = urev_prep_close(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_close: %s\n", strerror(-ret));
        return ret;
    }
    return 0;
}

static void close_src_and_dest(urev_queue_t *queue, copy_ctx_t *ctx)
{
    int ret;

    ret = queue_close_src(queue, ctx);
    if (ret < 0) {
        fprintf(stderr, "queue_close_src: %s\n", strerror(-ret));
        return;
    }
    ret = queue_close_dest(queue, ctx);
    if (ret < 0) {
        fprintf(stderr, "queue_close_dest: %s\n", strerror(-ret));
        return;
    }
    ret = urev_submit(queue);
    if (ret < 0) {
        fprintf(stderr, "urev_submit: %s\n", strerror(-ret));
        return;
    }
}

static void handle_fsync_completion(urev_fsync_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    set_err_code(ctx, op->common.err_code);

    close_src_and_dest(op->common.queue, ctx);
}

static void queue_fsync(urev_queue_t *queue, copy_ctx_t *ctx)
{
    urev_fsync_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op));
    if (!op) {
        fprintf(stderr, "calloc in queue_fsync: %s\n", strerror(ENOMEM));
    }

    op->common.ctx = ctx;
    op->handler = handle_fsync_completion;
    op->fd = ctx->outfd;
    ret = urev_prep_fsync(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_fsync: %s\n", strerror(-ret));
    }
}

static void handle_writev_completion(urev_readv_or_writev_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    if (op->common.cqe_res > 0) {
        ctx->write_left -= op->common.cqe_res;
    }
    fprintf(stderr, "handle_writev_completion, cqe_res=%d, write_left=%ld\n", op->common.cqe_res, ctx->write_left);
    urev_handle_short_writev(op);
    set_err_code(ctx, op->common.err_code);
    if (op->nbytes_done < op->nbytes_total) {
        return;
    }

    /*
     * All done. nothing else to do for write.
     */
    free(op);
    if (ctx->write_left == 0) {
        queue_fsync(op->common.queue, ctx);
    }
}

static void queue_writev(urev_queue_t *queue, urev_readv_or_writev_op_t *op)
{
    copy_ctx_t *ctx;
    int ret;

    // fprintf(stderr, "queue_write start, op=%p\n", op);
    ctx = op->common.ctx;
    op->handler = handle_writev_completion;
    op->fd = ctx->outfd;
    // fprintf(stderr, "before urev_prep_write, op=%p, buf=%p, offset=%ld, nbytes=%d\n", op, op->buf, op->offset, op->nbytes);
    ret = urev_prep_writev(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_write: %s\n", strerror(-ret));
    }
}

static void handle_readv_completion(urev_readv_or_writev_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    if (op->common.cqe_res > 0) {
        ctx->read_left -= op->common.cqe_res;
    }
    fprintf(stderr, "handle_readv_completion, cqe_res=%d, read_left=%ld\n", op->common.cqe_res, ctx->read_left);
    urev_handle_short_readv(op);
    set_err_code(ctx, op->common.err_code);
    if (op->nbytes_done < op->nbytes_total) {
        return;
    }

    /*
     * All done.  queue up corresponding write.
     */
    queue_writev(op->common.queue, op);
}

static int queue_readv(urev_queue_t *queue, copy_ctx_t *ctx, off_t size, off_t offset)
{
    urev_readv_or_writev_op_t *op;
    int i, nr_vecs;
    struct iovec *vec;
    char *buf;
    int ret;

    nr_vecs = (size + BUF_LEN - 1) / BUF_LEN;
    op = calloc(1, sizeof(*op) + nr_vecs * sizeof(*vec) + size);
    if (!op) {
        return -ENOMEM;
    }

    op->common.ctx = ctx;
    op->handler = handle_readv_completion;
    op->fd = ctx->infd;
    op->nr_vecs = nr_vecs;
    op->iovecs = vec = (struct iovec *) (op + 1);
    buf = (char *) (vec + nr_vecs);
    for (i = 0; i < nr_vecs; i++) {
        vec[i].iov_len = size > BUF_LEN ? BUF_LEN : size;
        vec[i].iov_base = buf + i * BUF_LEN;
        size -= vec[i].iov_len;
    }
    op->offset = offset;
    ret = urev_prep_readv(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_readv: %s\n", strerror(-ret));
        return ret;
    }
    return 0;
}

static int copy_file(urev_queue_t *queue, copy_ctx_t *ctx)
{
    off_t insize;
    off_t offset;
    int ret;

    offset = 0;
    ctx->read_left = ctx->write_left = insize = ctx->insize;
    while (!ctx->all_done) {
        /*
         * Queue up as many reads as we can
         */
        while (insize) {
            off_t this_size = insize;

            if (this_size > BS)
                this_size = BS;
            else if (!this_size)
                break;

            ret = queue_readv(queue, ctx, this_size, offset);
            if (ret < 0) {
                fprintf(stderr, "queue_read: %s\n", strerror(-ret));
                break;
            }

            insize -= this_size;
            offset += this_size;
        }
        ret = urev_submit(queue);
        if (ret < 0) {
            fprintf(stderr, "urev_submit: %s\n", strerror(-ret));
            break;
        }

        /*
         * Queue may be full at this point. Find at least one completion.
         */
        ret = urev_wait_and_handle_completions(queue);
        if (ret < 0) {
            fprintf(stderr, "urev_wait_and_handle_completions: %s\n",
                        strerror(-ret));
            return ret;
        }
    }
    if (ctx->err_code != 0) {
        fprintf(stderr, "got error in handlers: %s", strerror(ctx->err_code));
        return -ctx->err_code;
    }

    return 0;
}

static void handle_open_src_completion(urev_openat_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    set_err_code(ctx, op->common.err_code);
    if (op->common.cqe_res > 0) {
        ctx->infd = op->common.cqe_res;
    }
    free(op);
}

static int queue_open_src(urev_queue_t *queue, copy_ctx_t *ctx, const char *path)
{
    urev_openat_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op));
    if (!op) {
        return -ENOMEM;
    }
    op->common.ctx = ctx;
    op->handler = handle_open_src_completion;
    op->dfd = AT_FDCWD;
    op->path = path;
    op->flags = O_RDONLY;
    ret = urev_prep_openat(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_openat: %s\n", strerror(-ret));
        return ret;
    }
    return 0;
}

static void handle_open_dest_completion(urev_openat_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    set_err_code(ctx, op->common.err_code);
    if (op->common.cqe_res > 0) {
        ctx->outfd = op->common.cqe_res;
    }
    free(op);
}

static int queue_open_dest(urev_queue_t *queue, copy_ctx_t *ctx, const char *path)
{
    urev_openat_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op));
    if (!op) {
        return -ENOMEM;
    }
    op->common.ctx = ctx;
    op->handler = handle_open_dest_completion;
    op->dfd = AT_FDCWD;
    op->path = path;
    op->flags = O_WRONLY | O_CREAT | O_TRUNC;
    op->mode = 0644;
    ret = urev_prep_openat(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_openat: %s\n", strerror(-ret));
        return ret;
    }

    return 0;
}

static void handle_src_file_size_completion(urev_statx_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    set_err_code(ctx, op->common.err_code);
    ctx->inmode = op->statxbuf->stx_mode;
    ctx->insize = op->statxbuf->stx_size;
    free(op);
}

static int queue_get_src_size(urev_queue_t *queue, copy_ctx_t *ctx, const char *path)
{
    urev_statx_op_t *op;
    struct statx *st;
    int ret;

    op = calloc(1, sizeof(*op) + sizeof(*st));
    if (!op) {
        return -ENOMEM;
    }
    op->common.ctx = ctx;
    op->handler = handle_src_file_size_completion;
    op->dfd = AT_FDCWD;
    op->path = path;
    op->flags = 0;
    op->mask = STATX_MODE | STATX_SIZE | STATX_BLOCKS;
    op->statxbuf = (struct statx *)(op + 1);
    ret = urev_prep_statx(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_statx: %s\n", strerror(-ret));
        return ret;
    }

    return 0;
}

static int open_src_and_dest_and_get_src_size(urev_queue_t *queue, copy_ctx_t *ctx, const char *src_path, const char *dest_path)
{
    int ret;

    ret = queue_open_src(queue, ctx, src_path);
    if (ret < 0) {
        fprintf(stderr, "queue_open_src: %s\n", strerror(-ret));
        return 1;
    }
    ret = queue_get_src_size(queue, ctx, src_path);
    if (ret < 0) {
        fprintf(stderr, "queue_get_src_size: %s\n", strerror(-ret));
        return 1;
    }
    ret = queue_open_dest(queue, ctx, dest_path);
    if (ret < 0) {
        fprintf(stderr, "queue_open_dest: %s\n", strerror(-ret));
        return 1;
    }
    ret = urev_submit(queue);
    if (ret < 0) {
        fprintf(stderr, "urev_submit: %s\n", strerror(-ret));
        return 1;
    }

    while ((ctx->infd == 0 || ctx->outfd == 0 || ctx->insize == -1) && ctx->err_code == 0) {
        ret = urev_wait_and_handle_completions(queue);
        if (ret < 0) {
            fprintf(stderr, "handle completions for open: %s\n",
                        strerror(-ret));
            return 1;
        }
    }

    if (S_ISBLK(ctx->inmode)) {
        unsigned long long bytes;

        if (ioctl(ctx->infd, BLKGETSIZE64, &bytes) != 0)
            return -1;

        ctx->insize = bytes;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    urev_queue_t queue;
    copy_ctx_t ctx;
    int ret;

    if (argc < 3) {
        printf("%s: infile outfile\n", argv[0]);
        return 1;
    }

    if (setup_context(QD, &queue, &ctx))
        return 1;

    ret = open_src_and_dest_and_get_src_size(&queue, &ctx, argv[1], argv[2]);
    if (ret < 0) {
        fprintf(stderr, "open_src_and_dst: %s\n", strerror(-ret));
        return 1;
    }

    if (copy_file(&queue, &ctx))
        return 1;

    urev_queue_exit(&queue);
    return 0;
}
