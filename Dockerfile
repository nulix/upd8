FROM rust:1.83-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libglib2.0-dev \
    libostree-dev \
    libssl-dev \
    pkg-config

COPY Cargo.toml /
COPY src /src
COPY config.example.yml /

RUN cargo build --release

FROM scratch
COPY --from=builder /app/target/release/upd8 /upd8
COPY --from=builder /app/config.example.yml /
