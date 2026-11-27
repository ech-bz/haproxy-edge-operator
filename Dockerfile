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

FROM haproxy:3.2@sha256:59df2c5336782f5ae47161487794896a396ecbe7f2a9a60ec099cda7a07f1a76
COPY --from=build /usr/local/bin/haproxy-edge-operator /usr/local/bin/haproxy-edge-operator
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/haproxy-edge-operator"]
