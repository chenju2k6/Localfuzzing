# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ubuntu:18.04
# Install wget to download afl_driver.cpp. Install libstdc++ to use llvm_mode.
RUN apt-get update && \
    apt-get install -y wget libstdc++-5-dev libtool-bin automake flex bison \
                       libglib2.0-dev libpixman-1-dev python3-setuptools unzip \
                       apt-utils apt-transport-https ca-certificates git
RUN apt-get install -y lsb-release software-properties-common
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 10
RUN apt install -y git cargo clang-10 cmake g++ git libz3-dev llvm-10-dev llvm-10-tools ninja-build python3-pip zlib1g-dev && pip3 install lit


RUN ln -s /usr/bin/llvm-config-10 /usr/bin/llvm-config
RUN ln -s /usr/bin/clang-10 /usr/bin/clang
RUN ln -s /usr/bin/clang++-10 /usr/bin/clang++
# Download and compile afl++ (v2.62d).
# Build without Python support as we don't need it.
# Set AFL_NO_X86 to skip flaky tests.
#RUN git clone https://github.com/AFLplusplus/AFLplusplus.git /afl && \
#    cd /afl && \
#    git checkout 3.12c && \
#    unset CFLAGS && unset CXXFLAGS && export CC=clang && \
#    AFL_NO_X86=1 PYTHON_INCLUDE=/ make && make install && \
#    make -C utils/aflpp_driver && \
#    cp utils/aflpp_driver/libAFLDriver.a /

RUN git clone https://github.com/google/AFL.git /afl && \
    cd /afl && \
    git checkout v256b && \
    unset CFLAGS && unset CXXFLAGS && export CC=clang && \
    AFL_NO_X86=1 PYTHON_INCLUDE=/ make && make install
   #make -C utils/aflpp_driver && \
   #cp utils/aflpp_driver/libAFLDriver.a /



COPY libarchive-3.5.2.bak /src/libarchive-afl
RUN mkdir /src/tcpdump-afl
COPY  tcpdump /src/tcpdump-afl/tcpdump
COPY  libpcap /src/tcpdump-afl/libpcap
COPY  tiff-4.3.0.zip /src
COPY  openjpeg-2.4.0 /src/openjpeg-afl
RUN   cd /src && unzip /src/tiff-4.3.0.zip
RUN mv /src/tiff-4.3.0 /src/tiff-afl
COPY  input_tcpdump /out/input_tcpdump
COPY  input_openjpeg /out/input_openjpeg
COPY  input_tiff /out/input_tiff
COPY  input_libarchive /out/input_libarchive
ENV SRC=/src
ENV OUT=/out
ENV AFL_MAP_SIZE=65536
#tiff
RUN cd /src/tiff-afl && CC=/afl/afl-clang ./configure --disable-shared && make -j
RUN cp /src/tiff-afl/tools/tiff2pdf /out/

COPY standaloneengine.c /src 

RUN  cd /src && /afl/afl-clang  -c standaloneengine.c -o driver_afl.o && \
     ar r driver_afl.a driver_afl.o
RUN cp /src/driver_afl.a /usr/lib/libFuzzingEngine.a
ENV LIB_FUZZING_ENGINE=/usr/lib/libFuzzingEngine.a
##openjpeg
RUN cd /src/openjpeg-afl && mkdir build && cd build && CC=/afl/afl-clang cmake .. && make -j
RUN cd /src/openjpeg-afl/tests/fuzzers && CXX=/afl/afl-clang++ ./build_google_oss_fuzzers.sh
RUN cp /out/opj_decompress_fuzzer /out/openjpeg
#
RUN apt-get update && apt-get install -y make autoconf automake libtool pkg-config \
        libbz2-dev liblzo2-dev liblzma-dev liblz4-dev libz-dev \
        libxml2-dev libssl-dev libacl1-dev libattr1-dev


#tcpdump 
RUN cd /src/tcpdump-afl && cd libpcap && CC=/afl/afl-clang ./configure --disable-shared && make -j && cd ../tcpdump && \
    CC=/afl/afl-clang ./configure && make -j  && cp tcpdump /out/tcpdump
RUN mv /out/input_tiff /out/input_tiff2pdf

RUN mkdir /src/tcpdump-symcc
COPY  tcpdump /src/tcpdump-symcc/tcpdump
COPY  libpcap /src/tcpdump-symcc/libpcap
COPY  openjpeg-2.4.0 /src/openjpeg-symcc
RUN cd /src && unzip /src/tiff-4.3.0.zip
RUN cp -r /src/tiff-4.3.0 /src/tiff-symcc


RUN apt-get -y install cmake
RUN git clone https://github.com/Z3Prover/z3.git /z3 && \
		cd /z3 && git checkout z3-4.8.12 && mkdir -p build && cd build && \
		cmake .. && make -j && make install
		#cmake .. && make -j && make install
RUN ldconfig




RUN git clone https://github.com/eurecom-s3/symcc.git /src/symcc

RUN apt install -y cargo cmake g++ git libz3-dev python ninja-build python3-pip zlib1g-dev && pip3 install lit


RUN  cd /src/symcc && git submodule update --init && mkdir build && cd build && cmake -G Ninja -DQSYM_BACKEND=ON -DZ3_DIR=/z3/build .. && ninja all
RUN ldconfig

RUN  export CFLAGS= && cd /src && SYMCC_NO_SYMBOLIC_INPUT=1 /src/symcc/build/symcc  -c standaloneengine.c -o driver_symcc.o && \
     ar r driver_symcc.a driver_symcc.o
#
RUN cd /src/tiff-symcc && CC=/src/symcc/build/symcc SYMCC_NO_SYMBOLIC_INPUT=1 ./configure --disable-shared && SYMCC_NO_SYMBOLIC_INPUT=1 make -j
RUN cp /src/tiff-symcc/tools/tiff2pdf /out/tiff2pdf.symcc
#
##openjpeg
#RUN cd /src/openjpeg-symcc && mkdir build && cd build && CC=/src/symcc/build/symcc SYMCC_NO_SYMBOLIC_INPUT=1 cmake .. && SYMCC_NO_SYMBOLIC_INPUT=1 make -j
#RUN cd /src/openjpeg-track/tests/fuzzers && SYMCC_NO_SYMBOLIC_INPUT=1 CXX=/src/symcc/build/sym++ ./build_google_oss_fuzzers.sh
#RUN cp /out/opj_decompress_fuzzer /out/openjpeg.symcc
#
#
#
##tcpdump 
RUN cd /src/tcpdump-symcc && cd libpcap && CC=/src/symcc/build/symcc SYMCC_NO_SYMBOLIC_INPUT=1 ./configure --disable-shared && SYMCC_NO_SYMBOLIC_INPUT=1 make -j && cd ../tcpdump && \
    CC=/src/symcc/build/symcc SYMCC_NO_SYMBOLIC_INPUT=1 ./configure && SYMCC_NO_SYMBOLIC_INPUT=1 make -j  && cp tcpdump /out/tcpdump.symcc
#
#
##libarchive
#
COPY libarchive-3.5.2.bak /src/libarchive-symcc
RUN cp /src/driver_symcc.a /usr/lib/libFuzzingEngine.a
RUN cd /src/libarchive-symcc && CC=/src/symcc/build/symcc CXX=/src/symcc/build/sym++ SYMCC_REGULAR_LIBCXX=1 SYMCC_NO_SYMBOLIC_INPUT=1 ./contrib/oss-fuzz/oss-fuzz-build.sh
RUN cp /out/libarchive_fuzzer /out/libarchive.symcc

#libarchive
RUN cp /src/driver_afl.a /usr/lib/libFuzzingEngine.a
RUN cd /src/libarchive-afl && CC=/afl/afl-clang CXX=/afl/afl-clang++ ./contrib/oss-fuzz/oss-fuzz-build.sh
RUN cp /out/libarchive_fuzzer /out/libarchive

COPY binutils-2.33.1.tar.gz /src
RUN  cd /src && tar xf binutils-2.33.1.tar.gz && mv binutils-2.33.1 binutils-symcc
RUN  cd /src && tar xf binutils-2.33.1.tar.gz && mv binutils-2.33.1 binutils-afl
#binutils
RUN cd /src/binutils-symcc  && CC=/src/symcc/build/symcc SYMCC_NO_SYMBOLIC_INPUT=1 ./configure --disable-shared && SYMCC_NO_SYMBOLIC_INPUT=1 make -j && \
    cd binutils && cp objdump /out/objdump.symcc && cp size /out/size.symcc && cp nm-new /out/nm.symcc && cp readelf /out/readelf.symcc
RUN cd /src/binutils-afl  && CC=/afl/afl-clang ./configure --disable-shared && make -j && \
    cd binutils && cp objdump /out/objdump && cp size /out/size && cp nm-new /out/nm && cp readelf /out/readelf
RUN cd /src/symcc && cargo install --path util/symcc_fuzzing_helper

COPY fuzz_symcc.sh /out
COPY  input_readelf /out/input_readelf
COPY  input_objdump /out/input_objdump
COPY  input_size /out/input_size
COPY  input_nm /out/input_nm
WORKDIR /out
