LLC ?= llc
CLANG ?= clang
CC ?= gcc

BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/
CFLAGS = -g -Wall -Wpedantic -std=c17 -I/usr/aarch64-linux-gnu/include/
LDLIBS = -lbpf

.PHONY: all clean

test: rocksdb_parser.h ebpf.h

# 	    -Wno-unused-value  -Werror 
parser.o: parser.c rocksdb_parser.h data_block_footer.h ebpf.h
	$(CLANG) -S -g\
	    -target bpf \
	    -D __BPF_TRACING__ \
		-DROCKSDB_EBPF \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

all: test parser.o

clean:
	rm -f *.o test
