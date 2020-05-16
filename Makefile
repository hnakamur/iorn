NAME=libiorn

default: test

test: all
	@$(MAKE) -C test runtests

all:
	@$(MAKE) -C src
	@$(MAKE) -C examples
	@$(MAKE) -C test

clean:
	@$(MAKE) -C src clean
	@$(MAKE) -C examples clean
	@$(MAKE) -C test clean
