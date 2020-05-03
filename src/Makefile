prefix ?= /usr
includedir ?= $(prefix)/include
libdir ?= $(prefix)/lib
libdevdir ?= $(prefix)/lib

CFLAGS ?= -g -fomit-frame-pointer -O2
override CFLAGS += -Wall -Iinclude/ -include ../config-host.h
SO_CFLAGS=-shared -fPIC $(CFLAGS)
L_CFLAGS=$(CFLAGS)
LINK_FLAGS=
LINK_FLAGS+=$(LDFLAGS)
ENABLE_SHARED ?= 1

soname=liburev.so.0
minor=0
micro=1
libname=$(soname).$(minor).$(micro)
all_targets += liburev.a

ifeq ($(ENABLE_SHARED),1)
all_targets += $(libname)
endif

include ../Makefile.quiet

all: $(all_targets)

liburev_srcs := urev.c

liburev_objs := $(patsubst %.c,%.ol,$(liburev_srcs))
liburev_sobjs := $(patsubst %.c,%.os,$(liburev_srcs))

$(liburev_objs) $(liburev_sobjs): include/urev.h

%.os: %.c
	$(QUIET_CC)$(CC) $(SO_CFLAGS) -c -o $@ $<

%.ol: %.c
	$(QUIET_CC)$(CC) $(L_CFLAGS) -c -o $@ $<

AR ?= ar
RANLIB ?= ranlib
liburev.a: $(liburev_objs)
	@rm -f liburev.a
	$(QUIET_AR)$(AR) r liburev.a $^
	$(QUIET_RANLIB)$(RANLIB) liburev.a

$(libname): $(liburev_sobjs) liburev.map
	$(QUIET_CC)$(CC) $(SO_CFLAGS) -Wl,--version-script=liburev.map -Wl,-soname=$(soname) -o $@ $(liburev_sobjs) $(LINK_FLAGS)

install: $(all_targets)
	install -D -m 644 include/urev.h $(includedir)/urev.h
	install -D -m 644 liburev.a $(libdevdir)/liburev.a
ifeq ($(ENABLE_SHARED),1)
	install -D -m 755 $(libname) $(libdir)/$(libname)
	ln -sf $(libname) $(libdir)/$(soname)
	ln -sf $(relativelibdir)$(libname) $(libdevdir)/liburev.so
endif

$(liburev_objs): include/urev.h

clean:
	@rm -f $(all_targets) $(liburev_objs) $(liburev_sobjs) $(soname).new
	@rm -f *.so* *.a *.o
