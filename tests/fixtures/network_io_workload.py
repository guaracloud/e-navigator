#!/usr/bin/env python3
"""Exercise byte-returning vectored and zero-copy TCP syscalls."""

from __future__ import annotations

import os
import socket
import tempfile
import time
import ctypes


WRITEV_PAYLOAD = b"w" * 101
SENDFILE_PAYLOAD = b"f" * 131
SPLICE_SEND_PAYLOAD = b"s" * 151
READV_PAYLOAD = b"r" * 173
SPLICE_RECEIVE_PAYLOAD = b"i" * 179
MMSG_BATCH_SIZE = int(os.environ.get("E_NAVIGATOR_MMSG_BATCH_SIZE", "32"))
if not 1 <= MMSG_BATCH_SIZE <= 1_024:
    raise ValueError("E_NAVIGATOR_MMSG_BATCH_SIZE must be between 1 and 1024")

SENDMMSG_PAYLOADS = tuple(
    bytes((65 + index % 32,)) * (17 + index % 32)
    for index in range(MMSG_BATCH_SIZE)
)
RECVMMSG_PAYLOADS = tuple(
    bytes((97 + index % 32,)) * (23 + index % 32)
    for index in range(MMSG_BATCH_SIZE)
)


class Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


class Msghdr(ctypes.Structure):
    _fields_ = [
        ("msg_name", ctypes.c_void_p),
        ("msg_namelen", ctypes.c_uint),
        ("msg_iov", ctypes.POINTER(Iovec)),
        ("msg_iovlen", ctypes.c_size_t),
        ("msg_control", ctypes.c_void_p),
        ("msg_controllen", ctypes.c_size_t),
        ("msg_flags", ctypes.c_int),
    ]


class Mmsghdr(ctypes.Structure):
    _fields_ = [("msg_hdr", Msghdr), ("msg_len", ctypes.c_uint)]


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.sendmmsg.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(Mmsghdr),
    ctypes.c_uint,
    ctypes.c_uint,
]
LIBC.sendmmsg.restype = ctypes.c_int
LIBC.recvmmsg.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(Mmsghdr),
    ctypes.c_uint,
    ctypes.c_uint,
    ctypes.c_void_p,
]
LIBC.recvmmsg.restype = ctypes.c_int


def receive_exact(connection: socket.socket, expected: bytes) -> None:
    received = bytearray()
    while len(received) < len(expected):
        chunk = connection.recv(len(expected) - len(received))
        if not chunk:
            raise RuntimeError("connection closed before expected payload")
        received.extend(chunk)
    if received != expected:
        raise RuntimeError("received payload differs from transmitted payload")


def send_message_batch(connection: socket.socket, payloads: tuple[bytes, ...]) -> None:
    buffers = [ctypes.create_string_buffer(payload) for payload in payloads]
    iovecs = [
        Iovec(ctypes.cast(buffer, ctypes.c_void_p), len(payload))
        for buffer, payload in zip(buffers, payloads, strict=True)
    ]
    messages = (Mmsghdr * len(payloads))()
    for index, iovec in enumerate(iovecs):
        messages[index].msg_hdr.msg_iov = ctypes.pointer(iovec)
        messages[index].msg_hdr.msg_iovlen = 1

    completed = LIBC.sendmmsg(connection.fileno(), messages, len(messages), 0)
    if completed != len(messages):
        error = ctypes.get_errno()
        raise OSError(error, f"sendmmsg completed {completed} messages")
    if tuple(message.msg_len for message in messages) != tuple(map(len, payloads)):
        raise RuntimeError("sendmmsg reported unexpected per-message lengths")


def receive_message_batch(
    connection: socket.socket, expected_payloads: tuple[bytes, ...]
) -> None:
    buffers = [ctypes.create_string_buffer(payload) for payload in expected_payloads]
    iovecs = [
        Iovec(ctypes.cast(buffer, ctypes.c_void_p), len(payload))
        for buffer, payload in zip(buffers, expected_payloads, strict=True)
    ]
    messages = (Mmsghdr * len(expected_payloads))()
    for index, iovec in enumerate(iovecs):
        messages[index].msg_hdr.msg_iov = ctypes.pointer(iovec)
        messages[index].msg_hdr.msg_iovlen = 1

    completed = LIBC.recvmmsg(
        connection.fileno(), messages, len(messages), 0, None
    )
    if completed != len(messages):
        error = ctypes.get_errno()
        raise OSError(error, f"recvmmsg completed {completed} messages")
    for message, buffer, expected in zip(
        messages, buffers, expected_payloads, strict=True
    ):
        received = message.msg_len
        if received != len(expected) or buffer.raw[:received] != expected:
            raise RuntimeError("recvmmsg did not return the expected payload batch")


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

                send_message_batch(client, SENDMMSG_PAYLOADS)
                receive_exact(server, b"".join(SENDMMSG_PAYLOADS))

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

                server.sendall(b"".join(RECVMMSG_PAYLOADS))
                receive_message_batch(client, RECVMMSG_PAYLOADS)

                # Keep the socket open long enough to require at least one
                # active-flow snapshot before the final close event.
                time.sleep(1.0)

    print(
        "network-io-workload-ok "
        f"sent={len(WRITEV_PAYLOAD) + len(SENDFILE_PAYLOAD) + len(SPLICE_SEND_PAYLOAD) + sum(map(len, SENDMMSG_PAYLOADS))} "
        f"received={len(READV_PAYLOAD) + len(SPLICE_RECEIVE_PAYLOAD) + sum(map(len, RECVMMSG_PAYLOADS))}"
    )


if __name__ == "__main__":
    main()
