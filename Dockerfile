FROM ethereum/solc:0.8.19-alpine as solc-0.8.19

FROM alpine:3.17

COPY --from=solc-0.8.19 /usr/local/bin/solc /usr/local/bin/solc

# # reference: https://hub.docker.com/r/ethereum/solc/dockerfile
# RUN \
#     apk --no-cache --update add build-base cmake boost-dev git                                                && \
#     sed -i -E -e 's/include <sys\/poll.h>/include <poll.h>/' /usr/include/boost/asio/detail/socket_types.hpp  && \
#     git clone --branch v0.8.19 https://github.com/ethereum/solidity                          && \
#     cd /solidity && cmake -DCMAKE_BUILD_TYPE=Release -DTESTS=0 -DSTATIC_LINKING=1                             && \
#     cd /solidity && make -j8 solc && install -s  solc/solc /usr/bin                                               && \
#     cd / && rm -rf solidity                                                                                   && \
#     apk del sed build-base git make cmake gcc g++ musl-dev curl-dev boost-dev                                 && \ 
#     rm -rf /var/cache/apk/*

RUN apk add --no-cache g++ make python3 git libffi-dev openssl-dev fontconfig-dev clang-dev 

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN set -eux; \
    apkArch="$(apk --print-arch)"; \
    case "$apkArch" in \
    x86_64) rustArch='x86_64-unknown-linux-musl' ;; \
    aarch64) rustArch='aarch64-unknown-linux-musl' ;; \
    *) echo >&2 "unsupported architecture: $apkArch"; exit 1 ;; \
    esac; \
    \
    url="https://static.rust-lang.org/rustup/dist/${rustArch}/rustup-init"; \
    wget "$url"; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain nightly-2023-01-28; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME;

# RUN wget https://github.com/ethereum/solidity/releases/download/v0.8.19/solc-static-linux

# RUN cargo install svm-rs && svm install 0.8.17 && solc --version

RUN mkdir -p /data/rocksdb ; \
    mkdir -p /data/setup 

ARG RUSTFLAGS="-C target-feature=-crt-static"

WORKDIR /app
COPY . .

RUN cd zkmpt-circuit/ && cargo build --release --verbose --jobs=8
