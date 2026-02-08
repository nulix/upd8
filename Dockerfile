FROM scratch

ARG TARGETARCH
ARG TARGETVARIANT

COPY target/${TARGETARCH}${TARGETVARIANT}/release/upd8 /upd8
COPY config.example.yml /
