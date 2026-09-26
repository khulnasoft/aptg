# syntax=docker/dockerfile:1

FROM rust:1.79-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo fetch --locked

COPY src ./src
COPY config.toml ./
RUN cargo build --release

FROM debian:12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 wget && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r aptg && useradd -r -g aptg -d /var/lib/aptg -s /sbin/nologin aptg

RUN mkdir -p /etc/aptg /var/log/aptg /var/lib/aptg && \
    chown aptg:aptg /var/log/aptg /var/lib/aptg

COPY --from=builder /build/target/release/aptg /usr/local/bin/aptg
COPY config.toml /etc/aptg/config.toml

USER aptg
WORKDIR /var/lib/aptg

EXPOSE 8080 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

STOPSIGNAL SIGTERM
ENTRYPOINT ["aptg"]
CMD ["--config", "/etc/aptg/config.toml"]
