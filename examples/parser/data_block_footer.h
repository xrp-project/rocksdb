#ifndef _PARSER_DATA_BLOCK_FOOTER_H_
#define _PARSER_DATA_BLOCK_FOOTER_H_

#include "rocksdb_parser.h"

#define BLOCK_FOOTER_CHECKSUM_LEN 4
#define BLOCK_FOOTER_TYPE_LEN 1
#define BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN 4
#define BLOCK_FOOTER_FIXED_LEN                         \
  (BLOCK_FOOTER_CHECKSUM_LEN + BLOCK_FOOTER_TYPE_LEN + \
   BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN)

#define kBlockTrailerSize BLOCK_FOOTER_TYPE_LEN + BLOCK_FOOTER_CHECKSUM_LEN

#define kDataBlockIndexTypeBitShift 31

#define kMaxNumRestarts ((uint32_t)(1u << kDataBlockIndexTypeBitShift) - 1u)
#define kNumRestartsMask ((uint32_t)(1u << kDataBlockIndexTypeBitShift) - 1u)

static inline void unpack_index_type_and_num_restarts(uint32_t block_footer,
                                                      uint8_t* index_type,
                                                      uint32_t* num_restarts) {
    if (index_type) {
        if (block_footer & 1u << kDataBlockIndexTypeBitShift)
            *index_type = kDataBlockBinaryAndHash;
        else
            *index_type = kDataBlockBinarySearch;
    }

    if (num_restarts)
        *num_restarts = block_footer & kNumRestartsMask;

    // TODO: check that num_restarts <= kNumMaxRestarts
}

#endif  // _PARSER_DATA_BLOCK_FOOTER_H_
