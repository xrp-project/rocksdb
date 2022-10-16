#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>

#include "varint.h"

int main(void) {
    unsigned char index[2] = {0x68, 0x0D};
    unsigned char metaindex[3] = {0xD3, 0x07, 0x20};

    uint64_t index_val;
    uint64_t index_size_val;
    uint64_t metaindex_val;

    const unsigned char *index_ptr = decode_varint64(index, &index_val, sizeof(index));
    const unsigned char *index_size_ptr = decode_varint64(index_ptr, &index_size_val, sizeof(index) - 1);
    const unsigned char *metaindex_ptr = decode_varint64(metaindex, &metaindex_val, sizeof(metaindex));

    printf("Index val: %"PRIu64"; Ptr index %td\n", index_val, index_ptr - index);
    printf("Index size val: %"PRIu64"; Ptr index size %td\n", index_size_val, index_size_ptr - index_ptr);
    printf("Metaindex val: %"PRIu64"; Ptr metaindex %td\n", metaindex_val, metaindex_ptr - metaindex);

    unsigned char test_val[3];
    unsigned char *test_ptr = encode_varint64(test_val, 150, sizeof(test_val));
    printf("Converting %d to varint: should be 0x960d\n", 150);
    printf("Test val: %x %x\n", test_val[0], test_val[1]);
    printf("Test len: %td\n", test_ptr - test_val);

}
