FROM docker.io/rust:1.96.0-alpine3.23 AS builder

WORKDIR /build

COPY . .

RUN cargo build --release && \
    mv ./target/release/yggdrasil /yggdrasil && \
    rm -rf /build


FROM docker.io/busybox:stable-uclibc AS main

COPY --from=builder /yggdrasil /usr/local/bin/yggdrasil

COPY ./entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "entrypoint.sh" ]
