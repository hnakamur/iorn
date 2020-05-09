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

soname=libiorn.so.0
minor=0
micro=1
libname=$(soname).$(minor).$(micro)
all_targets += libiorn.a

ifeq ($(ENABLE_SHARED),1)
all_targets += $(libname)
endif

include ../Makefile.quiet

all: $(all_targets)

libiorn_srcs := iorn.c

libiorn_objs := $(patsubst %.c,%.ol,$(libiorn_srcs))
libiorn_sobjs := $(patsubst %.c,%.os,$(libiorn_srcs))

$(libiorn_objs) $(libiorn_sobjs): include/iorn.h

%.os: %.c
	$(QUIET_CC)$(CC) $(SO_CFLAGS) -c -o $@ $<

%.ol: %.c
	$(QUIET_CC)$(CC) $(L_CFLAGS) -c -o $@ $<

AR ?= ar
RANLIB ?= ranlib
libiorn.a: $(libiorn_objs)
	@rm -f libiorn.a
	$(QUIET_AR)$(AR) r libiorn.a $^
	$(QUIET_RANLIB)$(RANLIB) libiorn.a

$(libname): $(libiorn_sobjs) libiorn.map
	$(QUIET_CC)$(CC) $(SO_CFLAGS) -Wl,--version-script=libiorn.map -Wl,-soname=$(soname) -o $@ $(libiorn_sobjs) $(LINK_FLAGS)

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
