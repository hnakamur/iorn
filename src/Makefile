prefix ?= /usr
includedir ?= $(prefix)/include
libdir ?= $(prefix)/lib
libdevdir ?= $(prefix)/lib

CPPFLAGS ?=
override CPPFLAGS += -Iinclude/ -include ../config-host.h
CFLAGS ?= -g -fomit-frame-pointer -O2
override CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
SO_CFLAGS=-fPIC $(CFLAGS)
L_CFLAGS=$(CFLAGS)
LINK_FLAGS=
LINK_FLAGS+=$(LDFLAGS)
ENABLE_SHARED ?= 1

soname=libiorn.so.0
minor=0
micro=1
libname=$(soname).$(minor).$(micro)
all_targets += libiorn.a

ifeq ($(ENABLE_SHARED),1)
all_targets += $(libname)
endif

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

all: $(all_targets)

libiorn_headers := include/iorn.h \
	include/iorn/error.h \
	include/iorn/iovec_array.h \
	include/iorn/malloc.h \
	include/iorn/uring.h

libiorn_srcs := iorn.c iorn_iovec_array.c iorn_malloc.c

libiorn_objs := $(patsubst %.c,%.ol,$(libiorn_srcs))
libiorn_sobjs := $(patsubst %.c,%.os,$(libiorn_srcs))

$(libiorn_objs) $(libiorn_sobjs):

%.os: %.c $(libiorn_headers)
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(SO_CFLAGS) -c -o $@ $<

%.ol: %.c $(libiorn_headers)
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(L_CFLAGS) -c -o $@ $<

AR ?= ar
RANLIB ?= ranlib
libiorn.a: $(libiorn_objs)
	@rm -f libiorn.a
	$(QUIET_AR)$(AR) r libiorn.a $^
	$(QUIET_RANLIB)$(RANLIB) libiorn.a

$(libname): $(libiorn_sobjs) libiorn.map
	$(QUIET_CC)$(CC) $(SO_CFLAGS) -shared -Wl,--version-script=libiorn.map -Wl,-soname=$(soname) -o $@ $(libiorn_sobjs) $(LINK_FLAGS)

install: $(all_targets)
	install -D -m 644 include/iorn.h $(includedir)/iorn.h
	install -D -m 644 libiorn.a $(libdevdir)/libiorn.a
ifeq ($(ENABLE_SHARED),1)
	install -D -m 755 $(libname) $(libdir)/$(libname)
	ln -sf $(libname) $(libdir)/$(soname)
	ln -sf $(relativelibdir)$(libname) $(libdevdir)/libiorn.so
endif

$(libiorn_objs): include/iorn.h

clean:
	@rm -f $(all_targets) $(libiorn_objs) $(libiorn_sobjs) $(soname).new
	@rm -f *.so* *.a *.o core
