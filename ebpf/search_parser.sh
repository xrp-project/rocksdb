#!/bin/bash

# Check if the required number of arguments are provided
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <key>"
  exit 1
fi

directory="/mydata/data/ycsb_c"
key="$1"

# Loop through all the *.sst files in the directory
for file in "$directory"/*.sst; do
  if [ -f "$file" ]; then
    sudo ./sst-parser "$file" "$key"
    echo "$file"
  fi
done
