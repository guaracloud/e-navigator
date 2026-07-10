FROM rust:1.96-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker --version 0.10.3 --locked

# Keep the host build on the compiler shipped by the builder image instead of
# letting rust-toolchain.toml update the moving `stable` channel during builds.
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}

WORKDIR /workspace
COPY . .

RUN cargo build --locked --release -p e-navigator-cli

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/e-navigator /usr/local/bin/e-navigator

ENTRYPOINT ["/usr/local/bin/e-navigator"]
