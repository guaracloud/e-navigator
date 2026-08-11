#!/usr/bin/env python3
"""Exercise byte-returning vectored and zero-copy TCP syscalls."""

from __future__ import annotations

import os
import socket
import tempfile
import time


WRITEV_PAYLOAD = b"w" * 101
SENDFILE_PAYLOAD = b"f" * 131
SPLICE_SEND_PAYLOAD = b"s" * 151
READV_PAYLOAD = b"r" * 173
SPLICE_RECEIVE_PAYLOAD = b"i" * 179


def receive_exact(connection: socket.socket, expected: bytes) -> None:
    received = bytearray()
    while len(received) < len(expected):
        chunk = connection.recv(len(expected) - len(received))
        if not chunk:
            raise RuntimeError("connection closed before expected payload")
        received.extend(chunk)
    if received != expected:
        raise RuntimeError("received payload differs from transmitted payload")


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(listener.getsockname())
            server, _ = listener.accept()
            with server:
                written = os.writev(
                    client.fileno(),
                    [WRITEV_PAYLOAD[:37], WRITEV_PAYLOAD[37:]],
                )
                if written != len(WRITEV_PAYLOAD):
                    raise RuntimeError("writev returned a short write")
                receive_exact(server, WRITEV_PAYLOAD)

                with tempfile.TemporaryFile() as source:
                    source.write(SENDFILE_PAYLOAD)
                    source.flush()
                    source.seek(0)
                    sent = os.sendfile(
                        client.fileno(), source.fileno(), 0, len(SENDFILE_PAYLOAD)
                    )
                    if sent != len(SENDFILE_PAYLOAD):
                        raise RuntimeError("sendfile returned a short write")
                receive_exact(server, SENDFILE_PAYLOAD)

                pipe_read, pipe_write = os.pipe()
                try:
                    if os.write(pipe_write, SPLICE_SEND_PAYLOAD) != len(
                        SPLICE_SEND_PAYLOAD
                    ):
                        raise RuntimeError("pipe write returned a short write")
                    sent = os.splice(
                        pipe_read, client.fileno(), len(SPLICE_SEND_PAYLOAD)
                    )
                    if sent != len(SPLICE_SEND_PAYLOAD):
                        raise RuntimeError("outbound splice returned a short write")
                finally:
                    os.close(pipe_read)
                    os.close(pipe_write)
                receive_exact(server, SPLICE_SEND_PAYLOAD)

                server.sendall(READV_PAYLOAD)
                first = bytearray(73)
                second = bytearray(100)
                received = os.readv(client.fileno(), [first, second])
                if received != len(READV_PAYLOAD) or bytes(first + second) != READV_PAYLOAD:
                    raise RuntimeError("readv did not return the expected payload")

                server.sendall(SPLICE_RECEIVE_PAYLOAD)
                pipe_read, pipe_write = os.pipe()
                try:
                    received = os.splice(
                        client.fileno(), pipe_write, len(SPLICE_RECEIVE_PAYLOAD)
                    )
                    if received != len(SPLICE_RECEIVE_PAYLOAD):
                        raise RuntimeError("inbound splice returned a short read")
                    if os.read(pipe_read, received) != SPLICE_RECEIVE_PAYLOAD:
                        raise RuntimeError("inbound splice payload differs")
                finally:
                    os.close(pipe_read)
                    os.close(pipe_write)

                # Keep the socket open long enough to require at least one
                # active-flow snapshot before the final close event.
                time.sleep(1.0)

    print(
        "network-io-workload-ok "
        f"sent={len(WRITEV_PAYLOAD) + len(SENDFILE_PAYLOAD) + len(SPLICE_SEND_PAYLOAD)} "
        f"received={len(READV_PAYLOAD) + len(SPLICE_RECEIVE_PAYLOAD)}"
    )


if __name__ == "__main__":
    main()
