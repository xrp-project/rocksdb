#include <cstdio>
#include <string>
#include <vector>

#include "rocksdb/db.h"
#include "rocksdb/slice.h"
#include "rocksdb/options.h"
#include "rocksdb/sst_file_writer.h"

using ROCKSDB_NAMESPACE::Options;
using ROCKSDB_NAMESPACE::SstFileWriter;
using ROCKSDB_NAMESPACE::EnvOptions;
using ROCKSDB_NAMESPACE::Status;


int main() {

    Options options;
    options.compression = rocksdb::CompressionType::kNoCompression;

    SstFileWriter sst_file_writer(EnvOptions(), options);
    // Path to where we will write the SST file
    std::string file_path = "./file1.sst";

    // Open the file for writing
    Status s = sst_file_writer.Open(file_path);
    if (!s.ok()) {
        printf("Error while opening file %s, Error: %s\n", file_path.c_str(),
            s.ToString().c_str());
        return 1;
    }

    // Insert rows into the SST file, note that inserted keys must be 
    // strictly increasing (based on options.comparator)
    int value = 0;
    std::vector<std::string> v{"a", "b", "c", "d", "e", "f", "g"};

    for (auto& key : v) {
        s = sst_file_writer.Put(key, std::to_string(value++));
        if (!s.ok()) {
            printf("Error while adding Key: %s, Error: %s\n", key.c_str(),
                s.ToString().c_str());
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
