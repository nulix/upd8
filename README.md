# OSTree OTA update controller

This project is a simple OTA update manager for OSTree. It is designed to be used with the NULIX OS.

## Create development container

```sh
docker run --rm -it \
  -v ./:/upd8 \
  -w /upd8 \
  rust:alpine \
  sh -c "apk add --no-cache musl-dev pkgconfig ostree-dev && \
    cargo install cargo-edit &&
    export RUSTFLAGS='-Ctarget-feature=-crt-static' && \
    sh"
```

## Build

```sh
cargo build --release
```

## Update rust dependencies

```sh
cargo update
```

## Upgrade rust dependencies

```sh
cargo upgrade
```

## Clean the build

```sh
cargo clean
```

## Run the app on a target device

```sh
scp target/release/upd8 root@192.168.1.100:~
scp config.yml root@192.168.1.100:/etc/upd8
```

```sh
./upd8
```

## Enable debug logs on a target device

```sh
RUST_LOG=debug ./upd8
```
