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

FROM ubuntu:bionic


# Install wget to download afl_driver.cpp. Install libstdc++ to use llvm_mode.
RUN apt-get update && \
    apt-get install -y wget libstdc++-5-dev libtool-bin automake flex bison \
                       libglib2.0-dev cmake libpixman-1-dev git python3-setuptools unzip \
                       apt-utils apt-transport-https ca-certificates llvm-6.0 llvm-6.0-dev clang-6.0 llvm-6.0-tools clang-10 cargo llvm-10-dev llvm-10-tools

RUN mkdir /src && mkdir /out
ENV SRC=/src
ENV OUT=/out
# Download and compile afl++ (v2.62d).
# Build without Python support as we don't need it.
# Set AFL_NO_X86 to skip flaky tests.

RUN ln -s /usr/bin/llvm-config-10 /usr/bin/llvm-config
RUN ln -s /usr/bin/clang-10 /usr/bin/clang
RUN ln -s /usr/bin/clang++-10 /usr/bin/clang++

RUN git clone https://github.com/google/AFL.git /afl && \
    cd /afl && \
    git checkout v256b && \
    unset CFLAGS && unset CXXFLAGS && \
    AFL_NO_X86=1 PYTHON_INCLUDE=/ make && make install

COPY standaloneengine.c /src 

RUN  cd /src && /afl/afl-clang  -c standaloneengine.c -o driver_afl.o && \
     ar r driver_afl.a driver_afl.o
RUN cp /src/driver_afl.a /usr/lib/libFuzzingEngine.a
ENV LIB_FUZZING_ENGINE=/usr/lib/libFuzzingEngine.a

#RUN git clone https://github.com/AFLplusplus/AFLplusplus.git /afl && \
#    cd /afl && \
#    git checkout 3.12c && \
#    unset CFLAGS && unset CXXFLAGS && export CC=clang && \
#    AFL_NO_X86=1 PYTHON_INCLUDE=/ make && make install && \
#    make -C utils/aflpp_driver && \
#    cp utils/aflpp_driver/libAFLDriver.a /

COPY libarchive-3.5.2.bak /src/libarchive-afl
RUN mkdir /src/tcpdump-afl
COPY  tcpdump /src/tcpdump-afl/tcpdump
COPY  libpcap /src/tcpdump-afl/libpcap
COPY  tiff-4.3.0.zip /src
COPY  openjpeg-2.4.0 /src/openjpeg-afl
RUN cd /src/ && unzip /src/tiff-4.3.0.zip
RUN mv /src/tiff-4.3.0 /src/tiff-afl
COPY  input_tcpdump /out/input_tcpdump
COPY  input_openjpeg /out/input_openjpeg
COPY  input_tiff /out/input_tiff
COPY  input_libarchive /out/input_libarchive

COPY standaloneengine.c /src 
RUN  cd /src && /afl/afl-clang  -c standaloneengine.c -o driver_afl.o && \
     ar r driver_afl.a driver_afl.o
RUN cp /src/driver_afl.a /usr/lib/libFuzzingEngine.a

#tiff
RUN cd /src/tiff-afl && CC=/afl/afl-clang ./configure --disable-shared && make -j
RUN cp /src/tiff-afl/tools/tiff2pdf /out/

#openjpeg
RUN cd /src/openjpeg-afl && mkdir build && cd build && CC=/afl/afl-clang cmake .. && make -j
RUN cd /src/openjpeg-afl/tests/fuzzers && CXX=/afl/afl-clang++ ./build_google_oss_fuzzers.sh
RUN cp /out/opj_decompress_fuzzer /out/openjpeg

RUN apt-get update && apt-get install -y make autoconf automake libtool pkg-config \
        libbz2-dev liblzo2-dev liblzma-dev liblz4-dev libz-dev \
        libxml2-dev libssl-dev libacl1-dev libattr1-dev

#libarchive
RUN cd /src/libarchive-afl && CC=/afl/afl-clang CXX=/afl/afl-clang++ ./contrib/oss-fuzz/oss-fuzz-build.sh
RUN cp /out/libarchive_fuzzer /out/libarchive

#tcpdump 
RUN cd /src/tcpdump-afl && cd libpcap && CC=/afl/afl-clang ./configure --disable-shared && make -j && cd ../tcpdump && \
    CC=/afl/afl-clang ./configure && make -j  && cp tcpdump /out/tcpdump
RUN mv /out/input_tiff /out/input_tiff2pdf


RUN mkdir /src/tcpdump-track
RUN mkdir /src/tcpdump-fast
COPY  tcpdump /src/tcpdump-track/tcpdump
COPY  libpcap /src/tcpdump-track/libpcap
COPY  libpcap /src/tcpdump-fast/libpcap
COPY  tcpdump /src/tcpdump-fast/tcpdump
COPY  openjpeg-2.4.0 /src/openjpeg-track
COPY  openjpeg-2.4.0 /src/openjpeg-fast
RUN cd /src && unzip /src/tiff-4.3.0.zip
RUN cp -r /src/tiff-4.3.0 /src/tiff-track
RUN mv /src/tiff-4.3.0 /src/tiff-fast


RUN git clone https://github.com/Z3Prover/z3.git /z3 && \
		cd /z3 && git checkout z3-4.8.12 && mkdir -p build && cd build && \
		cmake .. && make -j && make install
		#cmake .. && make -j && make install
RUN ldconfig


RUN git clone https://github.com/protocolbuffers/protobuf.git /protobuf  && \
    cd /protobuf && \
    git submodule update --init --recursive && \
    unset CFLAGS && \
    unset CXXFLAGS && \
    ./autogen.sh && \
    ./configure  && \
   # ./configure  && \
    make -j && \
    make install && \
    ldconfig


#RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 12
#RUN ln -s /usr/bin/llvm-config-12 /usr/bin/llvm-config
#RUN ln -s /usr/bin/clang-12 /usr/bin/clang
#RUN ln -s /usr/bin/clang++-12 /usr/bin/clang++

RUN rm -rf /usr/local/include/llvm && rm -rf /usr/local/include/llvm-c
RUN rm -rf /usr/include/llvm && rm -rf /usr/include/llvm-c
RUN ln -s /usr/lib/llvm-6.0/include/llvm /usr/include/llvm
RUN ln -s /usr/lib/llvm-6.0/include/llvm-c /usr/include/llvm-c
# build kirenenko
#RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
#ENV PATH="/root/.cargo/bin:${PATH}"
RUN apt-get -y install libc++-dev libc++abi-dev
RUN git clone https://github.com/r-fuzz/fastgen /Kirenenko

RUN apt-get update -y &&  \
    apt-get -y install wget python-pip python3-setuptools apt-transport-https \
    llvm-6.0 llvm-6.0-dev clang-6.0 llvm-6.0-tools libboost-all-dev texinfo \
    lsb-release software-properties-common autoconf curl zlib1g-dev flex bison git

RUN cd /Kirenenko && \
    unset CFLAGS && \
    unset CXXFLAGS && \
    ./build/build.sh


RUN  export CFLAGS= && cd /src && KO_CC=clang-6.0 USE_TRACK=1 /Kirenenko/bin/ko-clang  -c standaloneengine.c -o driver_track.o && \
     ar r driver_track.a driver_track.o
RUN  export CFLAGS= && cd /src && KO_CC=clang-6.0 USE_FAST=1 /Kirenenko/bin/ko-clang  -c standaloneengine.c -o driver_fast.o && \
     ar r driver_fast.a driver_fast.o 


#tiff
RUN cd /src/tiff-track && CC=/Kirenenko/bin/ko-clang USE_TRACK=1 KO_CC=clang-6.0 ./configure --disable-shared && USE_TRACK=1 KO_CC=clang-6.0 make -j
RUN cd /src/tiff-fast && CC=/Kirenenko/bin/ko-clang KO_CC=clang-6.0 ./configure --disable-shared && KO_CC=clang-6.0 make -j
RUN cp /src/tiff-track/tools/tiff2pdf /out/tiff2pdf.track
RUN cp /src/tiff-fast/tools/tiff2pdf /out/tiff2pdf.fast

#openjpeg
RUN cp /src/driver_track.a /usr/lib/libFuzzingEngine.a
RUN cd /src/openjpeg-track && mkdir build && cd build && CC=/Kirenenko/bin/ko-clang USE_TRACK=1 KO_CC=clang-6.0 cmake .. && USE_TRACK=1 KO_CC=clang-6.0 make -j
RUN cd /src/openjpeg-track/tests/fuzzers && USE_TRACK=1 KO_CXX=clang++-6.0 CXX=/Kirenenko/bin/ko-clang++ ./build_google_oss_fuzzers.sh
RUN cp /out/opj_decompress_fuzzer /out/openjpeg.track
RUN cp /src/driver_fast.a /usr/lib/libFuzzingEngine.a
RUN cd /src/openjpeg-fast && mkdir build && cd build && CC=/Kirenenko/bin/ko-clang KO_CC=clang-6.0 cmake .. && KO_CC=clang-6.0 make -j
RUN cd /src/openjpeg-fast/tests/fuzzers &&  KO_CXX=clang++-6.0 CXX=/Kirenenko/bin/ko-clang++ ./build_google_oss_fuzzers.sh
RUN cp /out/opj_decompress_fuzzer /out/openjpeg.fast



#tcpdump 
RUN cd /src/tcpdump-track && cd libpcap && CC=/Kirenenko/bin/ko-clang KO_CC=clang-6.0 USE_TRACK=1 ./configure --disable-shared && KO_CC=clang-6.0 USE_TRACK=1 make -j && cd ../tcpdump && \
    CC=/Kirenenko/bin/ko-clang KO_CC=clang-6.0 USE_TRACK=1 ./configure && KO_CC=clang-6.0 USE_TRACK=1 make -j  && cp tcpdump /out/tcpdump.track
RUN cd /src/tcpdump-fast && cd libpcap && CC=/Kirenenko/bin/ko-clang KO_CC=clang-6.0 ./configure --disable-shared && KO_CC=clang-6.0 make -j && cd ../tcpdump && \
    CC=/Kirenenko/bin/ko-clang KO_CC=clang-6.0 ./configure && KO_CC=clang-6.0 make -j  && cp tcpdump /out/tcpdump.fast


#libarchive

COPY libarchive-3.5.2.symsan /src/libarchive-track
COPY libarchive-3.5.2.bak /src/libarchive-fast
RUN cp /src/driver_track.a /usr/lib/libFuzzingEngine.a
RUN cd /src/libarchive-track && CC=/Kirenenko/bin/ko-clang CXX=/Kirenenko/bin/ko-clang++ USE_TRACK=1 KO_CC=clang-6.0 KO_CXX=clang++-6.0 ./contrib/oss-fuzz/oss-fuzz-build.sh
RUN cp /out/libarchive_fuzzer /out/libarchive.track
RUN cp /src/driver_fast.a /usr/lib/libFuzzingEngine.a
RUN cd /src/libarchive-fast && CC=/Kirenenko/bin/ko-clang CXX=/Kirenenko/bin/ko-clang++ KO_CC=clang-6.0 KO_CXX=clang++-6.0 ./contrib/oss-fuzz/oss-fuzz-build.sh
RUN cp /out/libarchive_fuzzer /out/libarchive.fast

#COPY  neuzz/programs/readelf/neuzz_in /out/input_readelf
#COPY  neuzz/programs/objdump/neuzz_in /out/input_objdump
#COPY  neuzz/programs/size/neuzz_in /out/input_size
#COPY  neuzz/programs/nm/neuzz_in /out/input_nm
#COPY  neuzz/programs/libxml/neuzz_in /out/input_xml
COPY input_objdump /out/input_objdump
COPY input_size /out/input_size
COPY input_nm /out/input_nm
COPY input_readelf /out/input_readelf

COPY binutils-2.33.1.tar.gz /src
RUN  cd /src && tar xf binutils-2.33.1.tar.gz && mv binutils-2.33.1 binutils-track
RUN  cd /src && tar xf binutils-2.33.1.tar.gz && mv binutils-2.33.1 binutils-fast
RUN  cd /src && tar xf binutils-2.33.1.tar.gz && mv binutils-2.33.1 binutils-afl

#binutils
RUN cd /src/binutils-track  && CC=/Kirenenko/bin/ko-clang USE_TRACK=1 KO_CC=clang-6.0 ./configure --disable-shared && USE_TRACK=1 KO_CC=clang-6.0 make -j && \
    cd binutils && cp objdump /out/objdump.track && cp size /out/size.track && cp nm-new /out/nm.track && cp readelf /out/readelf.track
RUN cd /src/binutils-fast  && CC=/Kirenenko/bin/ko-clang KO_CC=clang-6.0 ./configure --disable-shared && KO_CC=clang-6.0 make -j && \
    cd binutils && cp objdump /out/objdump.fast && cp size /out/size.fast && cp nm-new /out/nm.fast && cp readelf /out/readelf.fast
RUN cd /src/binutils-afl  && CC=/afl/afl-clang ./configure --disable-shared && make -j && \
    cd binutils && cp objdump /out/objdump && cp size /out/size && cp nm-new /out/nm && cp readelf /out/readelf

COPY fuzz_symsan.sh /out/
WORKDIR /out
