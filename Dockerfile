FROM ubuntu:22.04

LABEL org.a85.qlancet.image-rev="20260617-ql-user-deps-v1"

WORKDIR /

RUN apt-get update && apt-get install -y \
    git wget curl ninja-build build-essential pkg-config \
    gcc-x86-64-linux-gnu g++-x86-64-linux-gnu libc6-dev-amd64-cross \
    libglib2.0-dev libpixman-1-dev libzstd-dev \
    python3-venv python3-pip python3-setuptools python3-wheel \
    libcapstone-dev libcapstone4 libslirp-dev libslirp0 cpio libaio-dev \
    libnl-3-dev libnl-genl-3-dev tmux libxslt1.1 patchelf \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://gitlab.com/qemu-project/qemu.git
WORKDIR /qemu
RUN git submodule update --init --recursive
RUN pip install --upgrade pip setuptools wheel tomli
RUN mkdir build && cd build && \
    ../configure --target-list=x86_64-softmmu,x86_64-linux-user \
      --enable-plugins --enable-capstone --enable-slirp --enable-linux-aio && \
    make -j$(nproc) install

WORKDIR /
RUN git clone https://github.com/axboe/liburing && \
    cd liburing && ./configure && make -j$(nproc) install

RUN wget -O libmnl-1.0.5.tar.bz2 https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2 && \
    tar -xf libmnl-1.0.5.tar.bz2 && \
    cd libmnl-1.0.5 && \
    ./configure --prefix=$PWD/deps --enable-static=yes --enable-shared=no && \
    make install && \
    wget -O libnftnl-1.2.8.tar.xz https://www.netfilter.org/pub/libnftnl/libnftnl-1.2.8.tar.xz && \
    tar -xf libnftnl-1.2.8.tar.xz && \
    cd libnftnl-1.2.8 && \
    LIBMNL_CFLAGS=-I$PWD/../deps/include \
    LIBMNL_LIBS=$PWD/../deps/lib/libmnl.a \
    ./configure --prefix=$PWD/../deps --enable-static=yes --enable-shared=no && \
    make install


RUN git clone https://github.com/matrix1001/glibc-all-in-one.git /opt/glibc-all-in-one && \
    pip install -e /opt/glibc-all-in-one || true
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
RUN curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb || true
RUN ln -sf /usr/local/bin/pwndbg /usr/local/bin/gdb || true

WORKDIR /qemu/contrib/plugins/test/qemu_tcg
CMD ["/bin/bash"]
