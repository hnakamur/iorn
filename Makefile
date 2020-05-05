NAME=liburev

default: all

all:
	@$(MAKE) -C src
	@$(MAKE) -C examples
	@$(MAKE) -C test

clean:
	@$(MAKE) -C src clean
	@$(MAKE) -C examples clean
	@$(MAKE) -C test clean
