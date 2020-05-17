#include <stdio.h>
#include <string.h>
#include "iorn.h"

#define ENTRIES 20
#define BUF_LEN 10
#define NR_VECS 5

static size_t copy_to_iovecs(unsigned nr_vecs, struct iovec *vecs, void *src, size_t nbytes)
{
    size_t copied;
    size_t n;

    copied = 0;
    fprintf(stderr, "copy_to_iovecs start, nr_vecs=%d, nbytes=%ld\n", nr_vecs, nbytes);
    while (nbytes > 0 && nr_vecs > 0) {
        n = nbytes;
        if (n > vecs[0].iov_len) {
            n = vecs[0].iov_len;
        }
        fprintf(stderr, "before memcpy to %p, n=%ld\n", vecs[0].iov_base, n);
        memcpy(vecs[0].iov_base, src, n);
        fprintf(stderr, "memcpy to %p, n=%ld\n", vecs[0].iov_base, n);
        nbytes -= n;
        copied += n;
        src += n;
        if (nbytes > 0) {
            nr_vecs--;
            vecs++;
        }
        fprintf(stderr, "loop continues, nr_vecs=%d, nbytes=%ld\n", nr_vecs, nbytes);
    }
    return copied;
}

static int test_iorn_iovec_adjust_after_short(void)
{
    unsigned char src_buf[BUF_LEN * NR_VECS], dst_buf[BUF_LEN * NR_VECS];
    struct iovec vecs[NR_VECS];
    struct msghdr h;

    for (int i = 0; i < NR_VECS; i++) {
        src_buf[i * BUF_LEN] = '0' + i;
        for (int j = 1; j < BUF_LEN - 1; j++) {
            src_buf[i * BUF_LEN + j] = 'a' + j;
        }
        src_buf[i * BUF_LEN + BUF_LEN - 1] = i != NR_VECS - 1 ? '\n' : '\0';
    }
    fprintf(stderr, "%s\n", src_buf);
    fprintf(stderr, "---\n");

    memset(dst_buf, 0, sizeof(dst_buf));
    memset(&h, 0, sizeof(h));
    h.msg_iovlen = NR_VECS;
    h.msg_iov = vecs;
    fprintf(stderr, "vecs=%p\n", vecs);
    fprintf(stderr, "vecs + 1=%p\n", vecs + 1);
    for (int i = 0; i < NR_VECS; i++) {
        vecs[i].iov_len = BUF_LEN;
        vecs[i].iov_base = dst_buf + BUF_LEN * i;
        fprintf(stderr, "i=%d, iov_len=%ld, iov_base=%p\n", i, vecs[i].iov_len, vecs[i].iov_base);
    }

    iorn_iovec_t *save_vecs = NULL;
    void *save_iov_base = NULL;
    size_t total_copied = 0;
    size_t advances[] = { 5, 16, 0, 9, 11, 9 };
    for (int i = 0; i < sizeof(advances) / sizeof(size_t); i++) {
        size_t advance = advances[i];
        size_t copied = copy_to_iovecs(h.msg_iovlen, h.msg_iov, src_buf + total_copied, advance);
        total_copied += advance;
        if (copied != advance) {
            fprintf(stderr, "unexpected copied=%ld, advance=%ld\n", copied, advance);
        }
        //fprintf(stderr, "after copy i=%d, dst_buf=[%s]\n", i, dst_buf);
        fprintf(stderr, "before adjust i=%d\n", i);
        h.msg_iovlen = iorn_iovec_array_adjust_after_short(h.msg_iovlen, &h.msg_iov, advance, &save_vecs, &save_iov_base);
        fprintf(stderr, "after adjust i=%d, iovlen=%ld, iov=%p\n", i, h.msg_iovlen, h.msg_iov);
    }
    fprintf(stderr, "before restore\n");
    h.msg_iovlen = iorn_iovec_array_restore_from_short_adjust(h.msg_iovlen, &h.msg_iov, &save_vecs, &save_iov_base);
    fprintf(stderr, "after restore\n");

    for (int i = 0; i < NR_VECS; i++) {
        fprintf(stderr, "before memcmp i=%d\n", i);
        if (memcmp(src_buf + BUF_LEN * i, h.msg_iov[i].iov_base, h.msg_iov[i].iov_len) != 0) {
            fprintf(stderr, "unmatched bytes in vec %i, [%.*s], [%.*s]\n",
                    i, BUF_LEN, src_buf + BUF_LEN * i,
                    (int) h.msg_iov[i].iov_len, (const char *) h.msg_iov[i].iov_base);
            return 1;
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (test_iorn_iovec_adjust_after_short() != 0) {
        fprintf(stderr, "test_adjut_restore_iovecs_recvmsg_or_sendmsg failed\n");
        return 1;
    }

    return 0;
}
