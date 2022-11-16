#include <cinttypes>

#include "rocksdb/sst_file_writer.h"

using ROCKSDB_NAMESPACE::Options;
using ROCKSDB_NAMESPACE::SstFileWriter;
using ROCKSDB_NAMESPACE::EnvOptions;
using ROCKSDB_NAMESPACE::Status;

const uint64_t kNumKeys = 300;

std::string EncodeAsString(uint64_t v) {
  char buf[16];
  snprintf(buf, sizeof(buf), "%08" PRIu64, v);
  return std::string(buf);
}

int main() {
  Options options;
  options.compression = rocksdb::CompressionType::kNoCompression;

  std::vector<std::string> keys;
  for (uint64_t i = 0; i < kNumKeys; i++) {
    keys.emplace_back(EncodeAsString(i));
  }

  SstFileWriter sst_file_writer(EnvOptions(), options);
  // Path to where we will write the SST file
  std::string file_path = "./larger.sst";

  // Open the file for writing
  Status s = sst_file_writer.Open(file_path);
  if (!s.ok()) {
    printf("Error while opening file %s, Error: %s\n", file_path.c_str(),
           s.ToString().c_str());
    return 1;
  }

  for (size_t i = 0; i < keys.size(); i++) {
    s = sst_file_writer.Put(keys[i], keys[i]);
    if (!s.ok()) {
      printf("Error while adding Key: %s, Error: %s\n", keys[i], keys[i]);
      return 1;
    }
  }

  // Close the file
  s = sst_file_writer.Finish();
  if (!s.ok()) {
    printf("Error while finishing file %s, Error: %s\n", file_path.c_str(),
           s.ToString().c_str());
    return 1;
  }
  return 0;
}
