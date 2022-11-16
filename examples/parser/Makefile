CC = gcc
CFLAGS = -g -Wall -Wpedantic -std=c17

.PHONY: all clean

sst-parser: varint.o
sst-parser.o: varint.h rocksdb_parser.h data_block_footer.h

varint-test: varint.o
varint-test.o: varint.h

varint.o: varint.h

all: sst-parser varint-test

clean:
	rm -f *.o sst-parser varint-test
