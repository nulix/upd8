FROM scratch

COPY target/release/upd8 /
COPY config.example.yml /
