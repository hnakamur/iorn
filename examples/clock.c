#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "iorn.h"

#define QUEUE_DEPTH             256

struct iorn_queue queue;

const long sec_in_nsec = 1000000000;

static void on_timeout(iorn_queue_t *queue, iorn_timeout_op_t *op) {
    struct timespec ts;
    int ret = clock_gettime(CLOCK_REALTIME, &ts);
    if (ret < 0) {
        fprintf(stderr, "clock_gettime CLOCK_REALTIME error: %s\n", strerror(errno));
        return;
    }

    op->ts.tv_nsec = sec_in_nsec - ts.tv_nsec;
    ret = iorn_prep_timeout(queue, op);
    if (ret < 0) {
        fprintf(stderr, "on_timeout err in prep_timeout, %s\n", strerror(-ret));
        return;
    }

    ret = iorn_submit(queue); 
    if (ret < 0) {
        fprintf(stderr, "on_timeout err in submit, %s\n", strerror(-ret));
        return;
    }

    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    printf("on_timeout time=%04d-%02d-%02dT%02d:%02d:%02d.%09ld\n",
            1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            ts.tv_nsec);
}

static int queue_timeout(iorn_queue_t *queue) {
    iorn_timeout_op_t *op = calloc(1, sizeof(*op));
    if (op == NULL) {
        return -ENOMEM;
    }

    struct timespec ts;
    int ret = clock_gettime(CLOCK_REALTIME, &ts);
    if (ret < 0) {
        fprintf(stderr, "clock_gettime CLOCK_REALTIME error: %s\n", strerror(errno));
        return -errno;
    }

    op->handler = on_timeout;
    op->ts.tv_sec = 0;
    op->ts.tv_nsec = sec_in_nsec - ts.tv_nsec;
    op->count = 1;

    ret = iorn_prep_timeout(queue, op);
    if (ret < 0) {
        return ret;
    }

    return iorn_submit(queue); 
}

int server_loop(iorn_queue_t *queue) {
    int ret = queue_timeout(queue);
    if (ret < 0) {
        return ret;
    }

    while (1) {
        ret = iorn_wait_and_handle_completion(queue);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

void sigint_handler(int signo) {
    printf("^C pressed. Shutting down.\n");
    iorn_queue_exit(&queue);
    exit(0);
}

int main() {
    if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        fprintf(stderr, "Error while setting a signal handler, err=%s.\n", strerror(errno));
        return 1;
    }
    int ret = iorn_queue_init(QUEUE_DEPTH, &queue, 0);
    if (ret < 0) {
        fprintf(stderr, "Error in iorn_queue_init, err=%s.\n", strerror(-ret));
        return 1;
    }
    ret = server_loop(&queue);
    if (ret < 0) {
        fprintf(stderr, "Error in server_loop, err=%s.\n", strerror(-ret));
        return 1;
    }

    return 0;
}
