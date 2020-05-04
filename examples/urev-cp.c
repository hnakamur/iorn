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
    int infd;
    int outfd;
    off_t insize;
    off_t read_left;
    off_t write_left;
} copy_ctx_t;

static int queue_write(urev_queue_t *queue, urev_read_or_write_op_t *op);

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

/**
 * Helper function for handling common part of read or write operation completion.
 * @param [in,out] op   a read or write operation.
 * @return 1 if handled, 0 if not handled, < 0 if error.
 */
static int handle_read_write_common(urev_read_or_write_op_t *op)
{
    int ret;

    // fprintf(stderr, "handle_read_write_common start, op=%p\n", op);
    ret = op->common.cqe_res;
    if (ret < 0) {
        if (ret == -EAGAIN) {
            if (op->common.opcode == IORING_OP_READ) {
                ret = urev_prep_read(op->common.queue, op);
            } else {
                ret = urev_prep_write(op->common.queue, op);
            }
            if (ret < 0) {
                fprintf(stderr, "urev_prep_read after EAGAIN: %s\n",
                        strerror(-ret));
                return ret;
            }
        }
        fprintf(stderr, "read failed: %s\n",
                strerror(-ret));
        return ret;
    }

    if (ret > 0 && ret != op->nbytes) {
        /* Short read, adjust and requeue */
        fprintf(stderr, "short read/write optype=%d, cqe->res=%d, op->nbytes=%d\n", op->common.opcode, ret, op->nbytes);
        if (op->saved_buf == NULL) {
            op->saved_buf = op->buf;
            op->saved_nbytes = op->nbytes;
            op->saved_offset = op->offset;
        }
        op->buf += ret;
        op->nbytes -= ret;
        op->offset += ret;
        if (op->common.opcode == IORING_OP_READ) {
            ret = urev_prep_read(op->common.queue, op);
        } else {
            ret = urev_prep_write(op->common.queue, op);
        }
        if (ret < 0) {
            fprintf(stderr, "urev_prep_read after short read: %s\n",
                    strerror(-ret));
            return ret;
        }
        return 1;
    }

    if (op->nbytes == 0 && op->saved_buf != NULL) {
        op->buf = op->saved_buf;
        op->nbytes = op->saved_nbytes;
        op->offset = op->saved_offset;
    }

    // fprintf(stderr, "full read/write in handle_read_write_common, opcode=%d\n",  op->opcode);
    return 0;
}

static void handle_read_completion(urev_read_or_write_op_t *op)
{
    int ret;
    copy_ctx_t *ctx;

    // fprintf(stderr, "handle_read_completion start, op=%p\n", op);
    ret = handle_read_write_common(op);
    if (ret != 0) {
        return;
    }

    /*
     * All done.  queue up corresponding write.
     */
    ctx = op->common.ctx;
    ctx->read_left -= op->nbytes;
    ret = queue_write(op->common.queue, op);
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
    }
    return 0;
}

static void handle_write_completion(urev_read_or_write_op_t *op)
{
    int ret;
    copy_ctx_t *ctx;

    // fprintf(stderr, "handle_write_completion start, op=%p\n", op);
    ret = handle_read_write_common(op);
    // fprintf(stderr, "handle_write_completion, ret from common=%d\n", ret);
    if (ret != 0) {
        return;
    }

    /*
     * All done. nothing else to do for write.
     */
    ctx = op->common.ctx;
    ctx->write_left -= op->nbytes;
    free(op);
}

static int queue_write(urev_queue_t *queue, urev_read_or_write_op_t *op)
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
    return ret;
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
