FROM rust:1.99-bookworm@sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0 AS builder

ARG BPF_RUST_TOOLCHAIN=nightly-2026-07-01

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install "${BPF_RUST_TOOLCHAIN}" --component rust-src \
    && cargo install bpf-linker --version 0.10.3 --locked

# Keep the host build explicitly aligned with the checked-in compiler pin.
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
