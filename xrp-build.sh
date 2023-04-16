LIB_MODE=shared make -j$(nproc) release
LIB_MODE=shared sudo make install
cd ebpf
make all
