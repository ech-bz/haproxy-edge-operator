ARG HAPROXY_IMAGE=haproxy:3.4@sha256:3e4e390ccc7208326607be371f4d14f6296af5cdb414315fadff50c5d785a478
ARG HAPROXY_SOURCE_VERSION=3.4.9
ARG HAPROXY_SOURCE_SHA256=896c55b6029ec2a841617e92a327a335f36a8968e7d51a47eada159673c2f320

FROM ${HAPROXY_IMAGE} AS octodns-build
USER root
RUN apt-get install --update -y --no-install-recommends python3-venv patch
COPY octodns/requirements.txt /tmp/octodns-requirements.txt
COPY patches/octodns-ech-validation.patch /tmp/octodns-ech-validation.patch
ARG OCTODNS_PROVIDERS=""
RUN python3 -m venv /opt/octodns \
    && /opt/octodns/bin/pip install --no-cache-dir -r /tmp/octodns-requirements.txt ${OCTODNS_PROVIDERS} \
    && cd /opt/octodns/lib/python*/site-packages \
    && patch -p1 < /tmp/octodns-ech-validation.patch

FROM ${HAPROXY_IMAGE} AS openssl-build
USER root
RUN apt-get install --update -y --no-install-recommends gcc libc6-dev liblua5.4-dev libpcre2-dev make patch perl wget
WORKDIR /usr/src/openssl
RUN wget -O /tmp/openssl.tar.gz https://github.com/openssl/openssl/releases/download/openssl-4.0.3/openssl-4.0.3.tar.gz \
    && echo '325b5c806167c13b40b1ffeadfe0248197c00eccc4cf123ec1e28d2d2fd216d9  /tmp/openssl.tar.gz' | sha256sum -c \
    && tar -xzf /tmp/openssl.tar.gz --strip-components=1 \
    && ./Configure no-shared no-tests --prefix=/opt/openssl --openssldir=/etc/ssl --libdir=lib \
    && make -j"$(nproc)" \
    && make install_sw

FROM openssl-build AS haproxy-build
ARG HAPROXY_SOURCE_VERSION
ARG HAPROXY_SOURCE_SHA256
WORKDIR /usr/src/haproxy
RUN wget -O /tmp/haproxy.tar.gz "https://www.haproxy.org/download/3.4/src/haproxy-${HAPROXY_SOURCE_VERSION}.tar.gz" \
    && echo "$HAPROXY_SOURCE_SHA256  /tmp/haproxy.tar.gz" | sha256sum -c \
    && tar -xzf /tmp/haproxy.tar.gz --strip-components=1
COPY patches/haproxy-verify-ip.patch /tmp/haproxy-verify-ip.patch
RUN patch -p1 < /tmp/haproxy-verify-ip.patch \
    && make -j"$(nproc)" all TARGET=linux-glibc USE_GETADDRINFO=1 \
        USE_LUA=1 LUA_INC=/usr/include/lua5.4 USE_OPENSSL=1 USE_ECH=1 \
        SSL_INC=/opt/openssl/include SSL_LIB=/opt/openssl/lib \
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
USER root
RUN apt-get install --update -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
ARG HAPROXY_SOURCE_VERSION
ARG HAPROXY_SOURCE_SHA256
ENV HAPROXY_VERSION=${HAPROXY_SOURCE_VERSION} \
    HAPROXY_URL=https://www.haproxy.org/download/3.4/src/haproxy-${HAPROXY_SOURCE_VERSION}.tar.gz \
    HAPROXY_SHA256=${HAPROXY_SOURCE_SHA256}
COPY --from=haproxy-build /usr/src/haproxy/haproxy /usr/local/sbin/haproxy
COPY --from=openssl-build /opt/openssl/bin/openssl /usr/local/bin/openssl
COPY --from=octodns-build /opt/octodns /opt/octodns
COPY --from=build /usr/local/bin/haproxy-edge-operator /usr/local/bin/haproxy-edge-operator
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/haproxy-edge-operator"]
