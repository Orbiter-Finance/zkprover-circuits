FROM rust:1.68.2-alpine3.17

RUN apk add g++ make python3 git libffi-dev openssl-dev fontconfig-dev clang-dev

ARG RUSTFLAGS="-C target-feature=-crt-static"

WORKDIR /app
COPY . .

RUN cd zkmpt-circuit/ && cargo build --release
