FROM ethereum/solc:0.8.19-alpine as solc-0.8.19

FROM alpine:3.17

COPY --from=solc-0.8.19 /usr/local/bin/solc /usr/local/bin/solc

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

RUN mkdir -p /data/rocksdb ; \
    mkdir -p /data/setup 

ARG RUSTFLAGS="-C target-feature=-crt-static"

WORKDIR /app
COPY . .

RUN cd zkmpt-circuit/ && cargo build --release --verbose --jobs=8