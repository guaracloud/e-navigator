#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
node_image="${E_NAVIGATOR_NODE_IMAGE:-node:20-slim}"

docker run --rm \
  --volume "$repo_root/tests/fixtures/node_network_transport_workload.mjs:/node_network_transport_workload.mjs:ro" \
  --entrypoint /bin/sh \
  "$node_image" \
  -c '
    set -eu
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends strace >/dev/null
    strace -ff -qq \
      -e trace=read,write,readv,writev,sendto,sendmsg,recvfrom,recvmsg,sendfile,splice,io_uring_setup,io_uring_enter,io_uring_register \
      -o /tmp/network-io.trace \
      node /node_network_transport_workload.mjs
    if ! grep -hEq "(writev|sendmsg)\(" /tmp/network-io.trace*; then
      printf "Node transport did not exercise a vectored socket write\n" >&2
      exit 1
    fi
    if grep -hEq "io_uring_(setup|enter|register)\(" /tmp/network-io.trace*; then
      printf "Node transport unexpectedly used io_uring\n" >&2
      exit 1
    fi
    printf "Node 20 net/TLS transport qualification passed: vectored syscall observed, no io_uring syscall observed\n"
  '
