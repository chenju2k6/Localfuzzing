# build the project
./build/autogen.sh
./configure
make -j$(nproc) all


# build fuzzer(s)
$CXX $CXXFLAGS -Ilibarchive \
    ./contrib/oss-fuzz/libarchive_fuzzer.cc \
     -o $OUT/libarchive_fuzzer $LIB_FUZZING_ENGINE \
    .libs/libarchive.a -Wl,-Bdynamic -lbz2 -llzo2  \
    -lxml2 -llzma -lz -lcrypto -llz4 -licuuc -pthread \
    -licudata -Wl,-Bdynamic -ldl
