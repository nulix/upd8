FROM rust:latest AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libglib2.0-dev \
    libostree-dev \
    libssl-dev \
    pkg-config

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config.example.yml ./

RUN rustup default nightly && cargo build --release

FROM scratch
COPY --from=builder /app/target/release/upd8 /upd8
COPY --from=builder /app/config.example.yml /
