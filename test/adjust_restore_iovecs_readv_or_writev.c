#include <stdio.h>
#include <string.h>
#include "urev.h"

#define ENTRIES 20
#define BUF_LEN 10
#define NR_VECS 5

static size_t copy_to_iovecs(unsigned nr_vecs, struct iovec *vecs, void *src, size_t nbytes)
{
    size_t copied;
    size_t n;

    copied = 0;
    //fprintf(stderr, "copy_to_iovecs start, nr_vecs=%d, nbytes=%ld\n", nr_vecs, nbytes);
    while (nbytes > 0 && nr_vecs > 0) {
        n = nbytes;
        if (n > vecs[0].iov_len) {
            n = vecs[0].iov_len;
        }
        memcpy(vecs[0].iov_base, src, n);
        //fprintf(stderr, "memcpy to %p, n=%ld\n", vecs[0].iov_base, n);
        nbytes -= n;
        copied += n;
        src += n;
        if (nbytes > 0) {
            nr_vecs--;
            vecs++;
        }
        //fprintf(stderr, "loop continues, nr_vecs=%d, nbytes=%ld\n", nr_vecs, nbytes);
    }
    return copied;
}

static int test_adjut_restore_iovecs_readv_or_writev(void)
{
    int i, j;
    unsigned char src_buf[BUF_LEN * NR_VECS], dst_buf[BUF_LEN * NR_VECS];
    struct iovec vecs[NR_VECS];
    urev_readv_or_writev_op_t op;
    size_t n, copied, total_length, total_copied;
    size_t lengths[] = { 5, 16, 0, 9, 11, 9 };

    for (i = 0; i < NR_VECS; i++) {
        src_buf[i * BUF_LEN] = '0' + i;
        for (j = 1; j < BUF_LEN - 1; j++) {
            src_buf[i * BUF_LEN + j] = 'a' + j;
        }
        src_buf[i * BUF_LEN + BUF_LEN - 1] = i != NR_VECS - 1 ? '\n' : '\0';
    }
    //fprintf(stderr, "%s\n", src_buf);
    //fprintf(stderr, "---\n");

    memset(&op, 0, sizeof(urev_readv_or_writev_op_t));
    memset(dst_buf, 0, sizeof(dst_buf));
    op.nr_vecs = NR_VECS;
    op.iovecs = vecs;
    for (i = 0; i < NR_VECS; i++) {
        vecs[i].iov_len = BUF_LEN;
        vecs[i].iov_base = dst_buf + BUF_LEN * i;
        //fprintf(stderr, "i=%d, iov_base=%p\n", i, vecs[i].iov_base);
    }

    total_length = total_copied = 0;
    for (i = 0; i < sizeof(lengths) / sizeof(size_t); i++) {
        n = lengths[i];
        copied = copy_to_iovecs(op.nr_vecs, op.iovecs, src_buf + total_length, n);
        total_length += n;
        if (copied != n) {
            fprintf(stderr, "unexpected copied=%ld, n=%ld\n", copied, n);
        }
        //fprintf(stderr, "after copy i=%d, dst_buf=[%s]\n", i, dst_buf);
        __urev_adjust_after_short_readv_or_writev(&op, n);
    }
    __urev_restore_after_short_readv_or_writev(&op);

    //for (i = 0; i < NR_VECS; i++) {
    //    if (memcmp(src_buf + BUF_LEN * i, op.iovecs[i].iov_base, op.iovecs[i].iov_len) != 0) {
    //        fprintf(stderr, "unmatched bytes in vec %i, [%s], [%s]\n", i, src_buf + BUF_LEN * i, (const char *) op.iovecs[i].iov_base);
    //    }
    //}

    return 0;
}

int main(int argc, char *argv[])
{
    int ret;
    urev_queue_t queue;

    ret = urev_queue_init(ENTRIES, &queue, 0);
    if (ret < 0) {
        fprintf(stderr, "queue_init: %s\n", strerror(-ret));
        return -1;
    }

    ret = test_adjut_restore_iovecs_readv_or_writev();
    if (ret) {
        fprintf(stderr, "test_adjut_restore_iovecs_readv_or_writev failed\n");
        return ret;
    }

    return 0;
}
