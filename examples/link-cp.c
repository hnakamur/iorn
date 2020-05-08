/* SPDX-License-Identifier: MIT */
/*
 * gcc -Wall -O2 -D_GNU_SOURCE -o link-cp link-cp.c -luring -llink
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
#define BS    (32*1024)

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

static int queue_rw_pair_helper(urev_queue_t *queue,
    urev_read_or_write_op_t *r_op, urev_read_or_write_op_t *w_op)
{
    int ret;

    ret = urev_prep_read(queue, r_op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_read: %s\n", strerror(-ret));
        return ret;
    }

    ret = urev_prep_write(queue, w_op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_write: %s\n", strerror(-ret));
        return ret;
    }
    return 0;
}

static void handle_write_completion(urev_read_or_write_op_t *w_op)
{
    copy_ctx_t *ctx;
    urev_queue_t *queue;
    urev_read_or_write_op_t *r_op;

    r_op = w_op + 1;
    queue = w_op->common.queue;
    ctx = w_op->common.ctx;
    if (w_op->common.cqe_res < 0) {
        if (w_op->common.cqe_res == -ECANCELED) {
            queue_rw_pair_helper(queue, r_op, w_op);
            return;
        }

        set_err_code(ctx, w_op->common.err_code);
    }

    /*
     * All done for this write.
     */
    ctx->write_left -= w_op->nbytes;
    free(w_op);

    if (ctx->write_left == 0) {
        queue_fsync(queue, ctx);
    }
}

static void handle_read_completion(urev_read_or_write_op_t *op)
{
    /* do nothing */
}

static int queue_rw_pair(urev_queue_t *queue, copy_ctx_t *ctx, off_t size, off_t offset)
{
    urev_read_or_write_op_t *w_op, *r_op;
    void *buf;

    w_op = calloc(1, 2 * sizeof(urev_read_or_write_op_t) + size);
    if (!w_op) {
        return -ENOMEM;
    }

    r_op = w_op + 1;
    buf = (void *) (r_op + 1);

    r_op->common.ctx = ctx;
    r_op->handler = handle_read_completion;
    r_op->fd = ctx->infd;
    r_op->buf = buf;
    r_op->nbytes = size;
    r_op->offset = offset;
    r_op->common.sqe_flags = IOSQE_IO_LINK;

    w_op->common.ctx = ctx;
    w_op->handler = handle_write_completion;
    w_op->fd = ctx->outfd;
    w_op->buf = buf;
    w_op->nbytes = size;
    w_op->offset = offset;

    return queue_rw_pair_helper(queue, r_op, w_op);
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

            ret = queue_rw_pair(queue, ctx, this_size, offset);
            if (ret < 0) {
                fprintf(stderr, "queue_rw_pair: %s\n", strerror(-ret));
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
