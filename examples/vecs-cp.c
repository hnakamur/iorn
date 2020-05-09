/* SPDX-License-Identifier: MIT */
/*
 * gcc -Wall -O2 -D_GNU_SOURCE -o vecs-cp vecs-cp.c -luring -liorn
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
#include "iorn.h"

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

static int setup_context(unsigned entries, iorn_queue_t *queue, copy_ctx_t *ctx)
{
    int ret;

    ret = iorn_queue_init(entries, queue, 0);
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

static void on_src_closed(iorn_queue_t *queue, iorn_close_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.op_ctx;
    set_err_code(ctx, op->common.err_code);
    ctx->infd = 0;
    free(op);

    if (ctx->infd == 0 && ctx->outfd == 0) {
        ctx->all_done = 1;
    }
}

static int queue_close_src(iorn_queue_t *queue, copy_ctx_t *ctx)
{
    iorn_close_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op));
    if (!op) {
        return -ENOMEM;
    }
    op->common.op_ctx = ctx;
    op->handler = on_src_closed;
    op->fd = ctx->infd;
    ret = iorn_prep_close(queue, op);
    if (ret < 0) {
        fprintf(stderr, "iorn_prep_close: %s\n", strerror(-ret));
        return ret;
    }
    return 0;
}

static void on_dest_close(iorn_queue_t *queue, iorn_close_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.op_ctx;
    set_err_code(ctx, op->common.err_code);
    ctx->outfd = 0;
    free(op);

    if (ctx->infd == 0 && ctx->outfd == 0) {
        ctx->all_done = 1;
    }
}

static int queue_close_dest(iorn_queue_t *queue, copy_ctx_t *ctx)
{
    iorn_close_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op));
    if (!op) {
        return -ENOMEM;
    }
    op->common.op_ctx = ctx;
    op->handler = on_dest_close;
    op->fd = ctx->outfd;
    ret = iorn_prep_close(queue, op);
    if (ret < 0) {
        fprintf(stderr, "iorn_prep_close: %s\n", strerror(-ret));
        return ret;
    }
    return 0;
}

static void close_src_and_dest(iorn_queue_t *queue, copy_ctx_t *ctx)
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
    ret = iorn_submit(queue);
    if (ret < 0) {
        fprintf(stderr, "iorn_submit: %s\n", strerror(-ret));
        return;
    }
}

static void on_fsync(iorn_queue_t *queue, iorn_fsync_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.op_ctx;
    set_err_code(ctx, op->common.err_code);

    close_src_and_dest(queue, ctx);
}

static void queue_fsync(iorn_queue_t *queue, copy_ctx_t *ctx)
{
    iorn_fsync_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op));
    if (!op) {
        fprintf(stderr, "calloc in queue_fsync: %s\n", strerror(ENOMEM));
    }

    op->common.op_ctx = ctx;
    op->handler = on_fsync;
    op->fd = ctx->outfd;
    ret = iorn_prep_fsync(queue, op);
    if (ret < 0) {
        fprintf(stderr, "iorn_prep_fsync: %s\n", strerror(-ret));
    }
}

static void on_writev(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.op_ctx;
    if (op->common.cqe_res > 0) {
        ctx->write_left -= op->common.cqe_res;
    }
    fprintf(stderr, "on_writev, cqe_res=%d, write_left=%ld\n", op->common.cqe_res, ctx->write_left);
    iorn_handle_short_writev(queue, op);
    set_err_code(ctx, op->common.err_code);
    if (op->nbytes_done < op->nbytes_total) {
        return;
    }

    /*
     * All done. nothing else to do for write.
     */
    free(op);
    if (ctx->write_left == 0) {
        queue_fsync(queue, ctx);
    }
}

static void queue_writev(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op)
{
    copy_ctx_t *ctx;
    int ret;

    // fprintf(stderr, "queue_write start, op=%p\n", op);
    ctx = op->common.op_ctx;
    op->handler = on_writev;
    op->fd = ctx->outfd;
    // fprintf(stderr, "before iorn_prep_write, op=%p, buf=%p, offset=%ld, nbytes=%d\n", op, op->buf, op->offset, op->nbytes);
    ret = iorn_prep_writev(queue, op);
    if (ret < 0) {
        fprintf(stderr, "iorn_prep_write: %s\n", strerror(-ret));
    }
}

static void on_readv(iorn_queue_t *queue, iorn_readv_or_writev_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.op_ctx;
    if (op->common.cqe_res > 0) {
        ctx->read_left -= op->common.cqe_res;
    }
    fprintf(stderr, "on_readv, cqe_res=%d, read_left=%ld\n", op->common.cqe_res, ctx->read_left);
    iorn_handle_short_readv(queue, op);
    set_err_code(ctx, op->common.err_code);
    if (op->nbytes_done < op->nbytes_total) {
        return;
    }

    /*
     * All done.  queue up corresponding write.
     */
    queue_writev(queue, op);
}

static int queue_readv(iorn_queue_t *queue, copy_ctx_t *ctx, off_t size, off_t offset)
{
    iorn_readv_or_writev_op_t *op;
    int i, nr_vecs;
    struct iovec *vec;
    char *buf;
    int ret;

    nr_vecs = (size + BUF_LEN - 1) / BUF_LEN;
    op = calloc(1, sizeof(*op) + nr_vecs * sizeof(*vec) + size);
    if (!op) {
        return -ENOMEM;
    }

    op->common.op_ctx = ctx;
    op->handler = on_readv;
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
    ret = iorn_prep_readv(queue, op);
    if (ret < 0) {
        fprintf(stderr, "iorn_prep_readv: %s\n", strerror(-ret));
        return ret;
    }
    return 0;
}

static int copy_file(iorn_queue_t *queue, copy_ctx_t *ctx)
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
        ret = iorn_submit(queue);
        if (ret < 0) {
            fprintf(stderr, "iorn_submit: %s\n", strerror(-ret));
            break;
        }

        /*
         * Queue may be full at this point. Find at least one completion.
         */
        ret = iorn_wait_and_handle_completions(queue);
        if (ret < 0) {
            fprintf(stderr, "iorn_wait_and_handle_completions: %s\n",
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

static void on_src_open(iorn_queue_t *queue, iorn_openat_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.op_ctx;
    set_err_code(ctx, op->common.err_code);
    if (op->common.cqe_res > 0) {
        ctx->infd = op->common.cqe_res;
    }
    free(op);
}

static int queue_open_src(iorn_queue_t *queue, copy_ctx_t *ctx, const char *path)
{
    iorn_openat_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op));
    if (!op) {
        return -ENOMEM;
    }
    op->common.op_ctx = ctx;
    op->handler = on_src_open;
    op->dfd = AT_FDCWD;
    op->path = path;
    op->flags = O_RDONLY;
    ret = iorn_prep_openat(queue, op);
    if (ret < 0) {
        fprintf(stderr, "iorn_prep_openat: %s\n", strerror(-ret));
        return ret;
    }
    return 0;
}

static void on_dest_open(iorn_queue_t *queue, iorn_openat_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.op_ctx;
    set_err_code(ctx, op->common.err_code);
    if (op->common.cqe_res > 0) {
        ctx->outfd = op->common.cqe_res;
    }
    free(op);
}

static int queue_open_dest(iorn_queue_t *queue, copy_ctx_t *ctx, const char *path)
{
    iorn_openat_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op));
    if (!op) {
        return -ENOMEM;
    }
    op->common.op_ctx = ctx;
    op->handler = on_dest_open;
    op->dfd = AT_FDCWD;
    op->path = path;
    op->flags = O_WRONLY | O_CREAT | O_TRUNC;
    op->mode = 0644;
    ret = iorn_prep_openat(queue, op);
    if (ret < 0) {
        fprintf(stderr, "iorn_prep_openat: %s\n", strerror(-ret));
        return ret;
    }

    return 0;
}

static void on_get_src_size(iorn_queue_t *queue, iorn_statx_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.op_ctx;
    set_err_code(ctx, op->common.err_code);
    ctx->inmode = op->statxbuf->stx_mode;
    ctx->insize = op->statxbuf->stx_size;
    free(op);
}

static int queue_get_src_size(iorn_queue_t *queue, copy_ctx_t *ctx, const char *path)
{
    iorn_statx_op_t *op;
    struct statx *st;
    int ret;

    op = calloc(1, sizeof(*op) + sizeof(*st));
    if (!op) {
        return -ENOMEM;
    }
    op->common.op_ctx = ctx;
    op->handler = on_get_src_size;
    op->dfd = AT_FDCWD;
    op->path = path;
    op->flags = 0;
    op->mask = STATX_MODE | STATX_SIZE | STATX_BLOCKS;
    op->statxbuf = (struct statx *)(op + 1);
    ret = iorn_prep_statx(queue, op);
    if (ret < 0) {
        fprintf(stderr, "iorn_prep_statx: %s\n", strerror(-ret));
        return ret;
    }

    return 0;
}

static int open_src_and_dest_and_get_src_size(iorn_queue_t *queue, copy_ctx_t *ctx, const char *src_path, const char *dest_path)
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
    ret = iorn_submit(queue);
    if (ret < 0) {
        fprintf(stderr, "iorn_submit: %s\n", strerror(-ret));
        return 1;
    }

    while ((ctx->infd == 0 || ctx->outfd == 0 || ctx->insize == -1) && ctx->err_code == 0) {
        ret = iorn_wait_and_handle_completions(queue);
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
    iorn_queue_t queue;
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

    iorn_queue_exit(&queue);
    return 0;
}
