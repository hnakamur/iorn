CFLAGS ?= -g -O2
XCFLAGS =
override CFLAGS += -Wall -D_GNU_SOURCE -L../src/ -I../src/include/

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

all_targets += urev-cp urev-cp-vecs link-cp

all: $(all_targets)

test_srcs := urev-cp.c urev-cp-vecs.c link-cp.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

%: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $< -luring -lurev $(XCFLAGS)

clean:
	@rm -f $(all_targets) $(test_objs)
