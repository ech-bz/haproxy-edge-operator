ARG HAPROXY_IMAGE=haproxy:3.2@sha256:59df2c5336782f5ae47161487794896a396ecbe7f2a9a60ec099cda7a07f1a76

FROM ${HAPROXY_IMAGE} AS haproxy-build
USER root
RUN apt-get install --update -y --no-install-recommends gcc libc6-dev liblua5.4-dev libpcre2-dev libssl-dev make patch wget
WORKDIR /usr/src/haproxy
RUN wget -O /tmp/haproxy.tar.gz "$HAPROXY_URL" \
    && echo "$HAPROXY_SHA256  /tmp/haproxy.tar.gz" | sha256sum -c \
    && tar -xzf /tmp/haproxy.tar.gz --strip-components=1
COPY patches/haproxy-verify-ip.patch /tmp/haproxy-verify-ip.patch
RUN patch -p1 < /tmp/haproxy-verify-ip.patch \
    && make -j"$(nproc)" all TARGET=linux-glibc USE_GETADDRINFO=1 \
        USE_LUA=1 LUA_INC=/usr/include/lua5.4 USE_OPENSSL=1 \
        USE_PCRE2=1 USE_PCRE2_JIT=1 USE_PROMEX=1 \
        USE_PTHREAD_EMULATION=1 USE_QUIC=1

FROM lukemathwalker/cargo-chef:latest-rust-1.100-bookworm AS chef
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /src/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git cargo chef cook --locked --release --recipe-path recipe.json
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git cargo build --locked --release && cp target/release/haproxy-edge-operator /usr/local/bin/haproxy-edge-operator

FROM ${HAPROXY_IMAGE}
COPY --from=haproxy-build /usr/src/haproxy/haproxy /usr/local/sbin/haproxy
COPY --from=build /usr/local/bin/haproxy-edge-operator /usr/local/bin/haproxy-edge-operator
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/haproxy-edge-operator"]
