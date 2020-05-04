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
    int   err_code;
} copy_ctx_t;

static int setup_context(unsigned entries, urev_queue_t *queue)
{
    int ret;

    ret = urev_queue_init(entries, queue, 0);
    if (ret < 0) {
        fprintf(stderr, "queue_init: %s\n", strerror(-ret));
        return -1;
    }

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

static inline void copy_err_code_from_op(copy_ctx_t *ctx, urev_read_or_write_op_t *op)
{
    set_err_code(ctx, op->common.err_code);
}

static void handle_write_completion(urev_read_or_write_op_t *op)
{
    copy_ctx_t *ctx;

    ctx = op->common.ctx;
    urev_handle_short_write(op);
    copy_err_code_from_op(ctx, op);
    if (op->nbytes_left) {
        return;
    }

    /*
     * All done. nothing else to do for write.
     */
    ctx->write_left -= op->nbytes;
    free(op);
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
    copy_err_code_from_op(ctx, op);
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
    while (ctx->read_left || ctx->write_left) {
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
        ret = urev_submit(queue);
        if (ret < 0) {
            return ret;
        }
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

    ctx.infd = open(argv[1], O_RDONLY);
    if (ctx.infd < 0) {
        perror("open infile");
        return 1;
    }
    ctx.outfd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (ctx.outfd < 0) {
        perror("open outfile");
        return 1;
    }

    if (setup_context(QD, &queue))
        return 1;
    if (get_file_size(ctx.infd, &ctx.insize))
        return 1;

    ret = copy_file(&queue, &ctx);

    fsync(ctx.outfd);
    close(ctx.infd);
    close(ctx.outfd);
    urev_queue_exit(&queue);
    return ret;
}
