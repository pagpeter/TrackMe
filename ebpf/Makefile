CLANG   ?= clang
CFLAGS  := -O2 -g -target bpf -Wall -Werror

ARCH_INCLUDE := $(shell uname -m | sed 's/x86_64/x86_64-linux-gnu/;s/aarch64/aarch64-linux-gnu/')
INCLUDE ?= -I/usr/include -I/usr/include/$(ARCH_INCLUDE)

.PHONY: all clean

all: syn_capture.o

syn_capture.o: syn_capture.c syn_capture.h
	$(CLANG) $(CFLAGS) $(INCLUDE) -c $< -o $@

clean:
	rm -f syn_capture.o
