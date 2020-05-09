CFLAGS ?= -g -O2
XCFLAGS =
override CFLAGS += -Wall -D_GNU_SOURCE -L../src/ -I../src/include/

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

all_targets += base-cp vecs-cp link-cp webserver clock

all: $(all_targets)

test_srcs := base-cp.c vecs-cp.c link-cp.c webserver.c clock.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

%: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $< -luring -liorn $(XCFLAGS)

clean:
	@rm -f $(all_targets) $(test_objs)
