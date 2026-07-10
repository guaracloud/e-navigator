FROM rust:1.96-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS builder

ARG BPF_RUST_TOOLCHAIN=nightly-2026-07-01

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install "${BPF_RUST_TOOLCHAIN}" --component rust-src \
    && cargo install bpf-linker --version 0.10.3 --locked

# Keep the host build on the compiler shipped by the builder image instead of
# letting rust-toolchain.toml update the moving `stable` channel during builds.
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}
ENV E_NAVIGATOR_BPF_TOOLCHAIN=${BPF_RUST_TOOLCHAIN}

WORKDIR /workspace
COPY . .

RUN cargo build --locked --release -p e-navigator-cli

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/e-navigator /usr/local/bin/e-navigator

ENTRYPOINT ["/usr/local/bin/e-navigator"]
