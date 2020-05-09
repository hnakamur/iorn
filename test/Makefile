prefix ?= /usr
datadir ?= $(prefix)/share

INSTALL=install

CFLAGS ?= -g -O2
XCFLAGS =
#override CFLAGS += -Wall -D_GNU_SOURCE -L../src/ -I../src/include/ -include ../config-host.h -D__SANE_USERSPACE_TYPES__
override CFLAGS += -Wall -D_GNU_SOURCE -L../src/ -I../src/include/

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

all_targets += adjust_restore_iovecs_readv_or_writev \
               adjust_restore_iovecs_recvmsg_or_sendmsg

all: $(all_targets)

test_srcs := adjust_restore_iovecs_readv_or_writev.c \
             adjust_restore_iovecs_recvmsg_or_sendmsg.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

%: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $< -luring -liorn $(XCFLAGS)

clean:
	@rm -f $(all_targets) $(test_objs)

runtests: all
	@./runtests.sh $(all_targets)
