/* SPDX-License-Identifier: MIT */
/*
 * gcc -Wall -O2 -D_GNU_SOURCE -o urev-cp urev-cp.c -luring -lurev
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
    int   infd;
    int   outfd;
    off_t insize;
    off_t read_left;
    off_t write_left;
    int   fsync_completed;
    int   err_code;
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

static int get_file_size(int fd, off_t *size)
{
    struct stat st;

    if (fstat(fd, &st) < 0)
        return -1;
    if (S_ISREG(st.st_mode)) {
        *size = st.st_size;
        return 0;
    } else if (S_ISBLK(st.st_mode)) {
        unsigned long long bytes;

        if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
            return -1;

        *size = bytes;
        return 0;
    }

    return -1;
}

static inline void set_err_code(copy_ctx_t *ctx, int err_code)
{
    if (err_code && !ctx->err_code) {
        ctx->err_code = err_code;
    }
}

static void handle_fsync_completion(urev_fsync_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    set_err_code(ctx, op->common.err_code);
    ctx->fsync_completed = 1;
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

static void handle_write_completion(urev_read_or_write_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    urev_handle_short_write(op);
    set_err_code(ctx, op->common.err_code);
    if (op->nbytes_left) {
        return;
    }

    /*
     * All done. nothing else to do for write.
     */
    ctx->write_left -= op->nbytes;
    free(op);

    if (ctx->write_left == 0) {
        queue_fsync(op->common.queue, ctx);
    }
}

static void queue_write(urev_queue_t *queue, urev_read_or_write_op_t *op)
{
    copy_ctx_t *ctx;
    int ret;

    // fprintf(stderr, "queue_write start, op=%p\n", op);
    ctx = op->common.ctx;
    op->handler = handle_write_completion;
    op->fd = ctx->outfd;
    // fprintf(stderr, "before urev_prep_write, op=%p, buf=%p, offset=%ld, nbytes=%d\n", op, op->buf, op->offset, op->nbytes);
    ret = urev_prep_write(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_write: %s\n", strerror(-ret));
    }
}

static void handle_read_completion(urev_read_or_write_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    urev_handle_short_read(op);
    set_err_code(ctx, op->common.err_code);
    if (op->nbytes_left) {
        return;
    }

    /*
     * All done.  queue up corresponding write.
     */
    ctx->read_left -= op->nbytes;
    queue_write(op->common.queue, op);
}

static int queue_read(urev_queue_t *queue, copy_ctx_t *ctx, off_t size, off_t offset)
{
    urev_read_or_write_op_t *op;
    int ret;

    op = calloc(1, sizeof(*op) + size);
    if (!op) {
        return -ENOMEM;
    }

    op->common.ctx = ctx;
    op->handler = handle_read_completion;
    op->fd = ctx->infd;
    op->buf = op + 1;
    op->nbytes = size;
    op->offset = offset;
    ret = urev_prep_read(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_read: %s\n", strerror(-ret));
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
    while (ctx->fsync_completed == 0) {
        fprintf(stderr, "copy_file loop insize=%ld, write_left=%ld\n", insize, ctx->write_left);
        /*
         * Queue up as many reads as we can
         */
        while (insize) {
            off_t this_size = insize;

            if (this_size > BS)
                this_size = BS;
            else if (!this_size)
                break;

            ret = queue_read(queue, ctx, this_size, offset);
            fprintf(stderr, "after queue_read, ret=%d\n", ret);
            if (ret < 0) {
                fprintf(stderr, "queue_read: %s\n", strerror(-ret));
                break;
            }

            insize -= this_size;
            offset += this_size;
        }
        fprintf(stderr, "after queueing reads\n");
        ret = urev_submit(queue);
        fprintf(stderr, "submit reads, ret=%d\n", ret);
        if (ret < 0) {
            fprintf(stderr, "urev_submit: %s\n", strerror(-ret));
            break;
        }

        /*
         * Queue is full at this point. Find at least one completion.
         */
        ret = urev_wait_and_handle_completions(queue);
        fprintf(stderr, "after urev_wait_and_handle_completions, ret=%d\n", ret);
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

static int open_src_and_dest(urev_queue_t *queue, copy_ctx_t *ctx, const char *src_path, const char *dest_path)
{
    int ret;

    ret = queue_open_src(queue, ctx, src_path);
    if (ret < 0) {
        fprintf(stderr, "queue_open_src: %s\n", strerror(-ret));
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

    while ((ctx->infd == 0 || ctx->outfd == 0) && ctx->err_code == 0) {
        ret = urev_wait_and_handle_completions(queue);
        if (ret < 0) {
            fprintf(stderr, "handle completions for open: %s\n",
                        strerror(-ret));
            return 1;
        }
    }
    fprintf(stderr, "ctx->infd=%d, ctx->outfd=%d, ctx->err_code=%d\n", ctx->infd, ctx->outfd, ctx->err_code);
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

    ret = open_src_and_dest(&queue, &ctx, argv[1], argv[2]);
    if (ret < 0) {
        fprintf(stderr, "open_src_and_dst: %s\n", strerror(-ret));
        return 1;
    }

    if (get_file_size(ctx.infd, &ctx.insize))
        return 1;

    ret = copy_file(&queue, &ctx);

    close(ctx.infd);
    close(ctx.outfd);
    urev_queue_exit(&queue);
    return ret;
}
