FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends redis-server python3 ca-certificates curl procps linux-perf \
    && rm -rf /var/lib/apt/lists/*
