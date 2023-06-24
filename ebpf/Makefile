LLC ?= llc
CLANG ?= clang
CC = gcc

BPF_CFLAGS ?= -I/usr/include/bpf/
CFLAGS = -g -Wall -Wpedantic -std=c17 -I/usr/include/bpf/
LDLIBS = -lbpf
LDFLAGS = -L/usr/lib64

.PHONY: all clean

all: test parser.o

test: rocksdb_parser.h

parser.o: parser.c rocksdb_parser.h ebpf_internal.h
	$(CLANG) -S -g\
		-target bpf \
		-D __BPF_TRACING__ \
		-DROCKSDB_EBPF \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

clean:
	rm -f -- *.o *.ll test
