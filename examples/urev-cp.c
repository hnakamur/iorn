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

typedef struct read_or_write_ctx {
    off_t first_offset;
    size_t first_len;
} read_or_write_ctx_t;

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
 * @param [in] cqe      a completion queue entry.
 * @return 1 if handled, 0 if not handled, < 0 if error.
 */
static int handle_read_write_common(urev_read_or_write_op_t *op, struct io_uring_cqe *cqe)
{
    int ret;
    copy_ctx_t *ctx;

    // fprintf(stderr, "handle_read_write_common start, op=%p\n", op);
    ret = cqe->res;
    if (ret < 0) {
        if (ret == -EAGAIN) {
            if (op->opcode == IORING_OP_READ) {
                ret = urev_prep_read(op->queue, op);
            } else {
                ret = urev_prep_write(op->queue, op);
            }
            if (ret < 0) {
                fprintf(stderr, "urev_prep_read after EAGAIN: %s\n",
                        strerror(-ret));
                return ret;
            }
        }
        fprintf(stderr, "read failed: %s\n",
                strerror(-cqe->res));
        return ret;
    }

    ctx = op->ctx;
    if (op->opcode == IORING_OP_READ) {
        ctx->read_left -= ret;
        fprintf(stderr, "handle_read_read_common, read_left=%ld\n", ctx->read_left);
    } else {
        ctx->write_left -= ret;
        fprintf(stderr, "handle_read_write_common, write_left=%ld\n", ctx->write_left);
    }

    if (ret != op->nbytes) {
        /* Short read, adjust and requeue */
        fprintf(stderr, "short read/write op->optype=%d, cqe->res=%d, op->nbytes=%d\n", op->opcode, ret, op->nbytes);
        op->buf += ret;
        op->nbytes -= ret;
        op->offset += ret;
        if (op->opcode == IORING_OP_READ) {
            ret = urev_prep_read(op->queue, op);
        } else {
            ret = urev_prep_write(op->queue, op);
        }
        if (ret < 0) {
            fprintf(stderr, "urev_prep_read after short read: %s\n",
                    strerror(-ret));
            return ret;
        }
        return 1;
    }

    // fprintf(stderr, "full read/write in handle_read_write_common, opcode=%d\n",  op->opcode);
    return 0;
}

static void handle_read_completion(urev_read_or_write_op_t *op, struct io_uring_cqe *cqe)
{
    int ret;

    // fprintf(stderr, "handle_read_completion start, op=%p\n", op);
    ret = handle_read_write_common(op, cqe);
    if (ret != 0) {
        return;
    }

    /*
     * All done.  queue up corresponding write.
     */
    ret = queue_write(op->queue, op);
}

static int queue_read(urev_queue_t *queue, copy_ctx_t *ctx, off_t size, off_t offset)
{
    urev_read_or_write_op_t *op;
    read_or_write_ctx_t *rw_ctx;
    int ret;

    op = malloc(sizeof(*op) + sizeof(*rw_ctx) + size);
    if (!op) {
        return -ENOMEM;
    }

    rw_ctx = (read_or_write_ctx_t *)(op + 1);
    op->ctx = ctx;
    op->handler = handle_read_completion;
    op->fd = ctx->infd;
    op->buf = rw_ctx + 1;
    op->nbytes = rw_ctx->first_len = size;
    fprintf(stderr, "queue_read, op->nbytes=%d, rw_ctx->first_len=%ld, size=%ld\n", op->nbytes, rw_ctx->first_len, size);
    op->offset = rw_ctx->first_offset = offset;
    ret = urev_prep_read(queue, op);
    if (ret < 0) {
        fprintf(stderr, "urev_prep_read: %s\n", strerror(-ret));
    }
    return 0;
}

static void handle_write_completion(urev_read_or_write_op_t *op, struct io_uring_cqe *cqe)
{
    int ret;

    // fprintf(stderr, "handle_write_completion start, op=%p\n", op);
    ret = handle_read_write_common(op, cqe);
    // fprintf(stderr, "handle_write_completion, ret from common=%d\n", ret);
    if (ret != 0) {
        return;
    }

    /*
     * All done. nothing else to do for write.
     */
    free(op);
}

static int queue_write(urev_queue_t *queue, urev_read_or_write_op_t *op)
{
    read_or_write_ctx_t *rw_ctx;
    copy_ctx_t *ctx;
    int ret;

    // fprintf(stderr, "queue_write start, op=%p\n", op);
    rw_ctx = (read_or_write_ctx_t *)(op + 1);
    ctx = op->ctx;
    op->handler = handle_write_completion;
    op->fd = ctx->outfd;
    op->buf = rw_ctx + 1;
    op->offset = rw_ctx->first_offset;
    op->nbytes = rw_ctx->first_len;
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
