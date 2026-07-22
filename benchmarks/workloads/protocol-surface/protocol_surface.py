#!/usr/bin/env python3
"""Bounded WebSocket, gRPC-Web, and real HTTP/3 homelab workload."""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import os
import socket
import ssl
import struct
import tempfile
import threading
import time
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


TCP_PORT = 18080
HTTP3_PORT = 18443
MAX_HTTP_BYTES = 64 * 1024
SOCKET_TIMEOUT_SECONDS = 3


def read_http_message(connection: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before HTTP headers")
        data.extend(chunk)
        if len(data) > MAX_HTTP_BYTES:
            raise RuntimeError("HTTP headers exceeded workload bound")
    header_end = data.index(b"\r\n\r\n") + 4
    content_length = 0
    for line in bytes(data[:header_end]).split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
    total = header_end + content_length
    if total > MAX_HTTP_BYTES:
        raise RuntimeError("HTTP body exceeded workload bound")
    while len(data) < total:
        chunk = connection.recv(min(4096, total - len(data)))
        if not chunk:
            raise RuntimeError("connection closed before HTTP body")
        data.extend(chunk)
    return bytes(data[:total])


class TcpProtocolServer:
    def __init__(self) -> None:
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.listener: socket.socket | None = None
        self.thread = threading.Thread(target=self._run, name="protocol-server")
        self.failures: list[str] = []

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(timeout=5):
            raise RuntimeError("TCP protocol server did not become ready")

    def close(self) -> None:
        self.stop.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("TCP protocol server did not stop")

    def _run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                self.listener = listener
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", TCP_PORT))
                listener.listen(64)
                listener.settimeout(0.2)
                self.ready.set()
                while not self.stop.is_set():
                    try:
                        connection, _ = listener.accept()
                    except TimeoutError:
                        continue
                    except OSError:
                        if self.stop.is_set():
                            break
                        raise
                    with connection:
                        connection.settimeout(SOCKET_TIMEOUT_SECONDS)
                        self._handle(connection)
        except Exception as error:  # proof workload reports rather than hides failure
            self.failures.append(f"{type(error).__name__}: {error}")
            self.ready.set()

    def _handle(self, connection: socket.socket) -> None:
        request = read_http_message(connection)
        if request.startswith(b"GET /websocket-proof HTTP/1.1\r\n"):
            response = (
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
            )
            server_frame = b"\x81\x11server-secret-red"
            connection.sendall(response + server_frame)
            client_frame = connection.recv(1024)
            if len(client_frame) < 6 or client_frame[0] & 0x0F != 0x9:
                raise RuntimeError("missing masked client ping frame")
            return
        if request.startswith(b"POST /proof.Echo/Call HTTP/1.1\r\n"):
            trailer = b"grpc-status: 0\r\n"
            response_body = (
                b"\x00\x00\x00\x00\x02ok"
                + b"\x80"
                + struct.pack(">I", len(trailer))
                + trailer
            )
            encoded = base64.b64encode(response_body)
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/grpc-web-text+proto\r\n"
                + f"Content-Length: {len(encoded)}\r\n\r\n".encode()
                + encoded
            )
            connection.sendall(response)
            return
        raise RuntimeError("unknown proof request")


def websocket_round() -> None:
    request = (
        b"GET /websocket-proof HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: keep-alive, Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    with socket.create_connection(
        ("127.0.0.1", TCP_PORT), timeout=SOCKET_TIMEOUT_SECONDS
    ) as connection:
        connection.sendall(request)
        response = connection.recv(4096)
        if b"101 Switching Protocols" not in response or b"server-secret-red" not in response:
            raise RuntimeError("invalid WebSocket proof response")
        connection.sendall(b"\x89\x80\x01\x02\x03\x04")


def grpc_web_round() -> None:
    body = b"\x00\x00\x00\x00\x12client-secret-blue"
    request = (
        b"POST /proof.Echo/Call HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/grpc-web+proto\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body
    )
    with socket.create_connection(
        ("127.0.0.1", TCP_PORT), timeout=SOCKET_TIMEOUT_SECONDS
    ) as connection:
        connection.sendall(request)
        response = read_http_message(connection)
        if b"application/grpc-web-text+proto" not in response:
            raise RuntimeError("invalid gRPC-Web proof response")
        encoded = response.split(b"\r\n\r\n", 1)[1]
        decoded = base64.b64decode(encoded, validate=True)
        if b"grpc-status: 0\r\n" not in decoded:
            raise RuntimeError("gRPC-Web response omitted status trailer")


class H3ServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.http: H3Connection | None = None

    def quic_event_received(self, event) -> None:
        if isinstance(event, ProtocolNegotiated):
            self.http = H3Connection(self._quic)
        if self.http is None:
            return
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived) and http_event.stream_ended:
                self.http.send_headers(
                    stream_id=http_event.stream_id,
                    headers=[
                        (b":status", b"200"),
                        (b"content-type", b"text/plain"),
                    ],
                )
                self.http.send_data(
                    stream_id=http_event.stream_id,
                    data=b"http3-proof-ok",
                    end_stream=True,
                )
                self.transmit()


class H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.alpn: str | None = None
        self.responses: dict[int, tuple[asyncio.Future, int | None, bytearray]] = {}

    async def get(self) -> tuple[int, bytes, str | None]:
        stream_id = self._quic.get_next_available_stream_id()
        future = self._loop.create_future()
        self.responses[stream_id] = (future, None, bytearray())
        self.http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", f"localhost:{HTTP3_PORT}".encode()),
                (b":path", b"/http3-proof"),
            ],
            end_stream=True,
        )
        self.transmit()
        status, body = await asyncio.wait_for(future, timeout=5)
        return status, body, self.alpn

    def quic_event_received(self, event) -> None:
        if isinstance(event, ProtocolNegotiated):
            self.alpn = event.alpn_protocol
        for http_event in self.http.handle_event(event):
            stream_id = getattr(http_event, "stream_id", None)
            if stream_id not in self.responses:
                continue
            future, status, body = self.responses[stream_id]
            if isinstance(http_event, HeadersReceived):
                for name, value in http_event.headers:
                    if name == b":status":
                        status = int(value)
            elif isinstance(http_event, DataReceived):
                body.extend(http_event.data)
            self.responses[stream_id] = (future, status, body)
            if getattr(http_event, "stream_ended", False) and not future.done():
                future.set_result((status, bytes(body)))
                del self.responses[stream_id]


def write_test_certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path


async def http3_proof() -> tuple[int, str]:
    with tempfile.TemporaryDirectory(prefix="e-navigator-http3-") as temp:
        certificate_path, key_path = write_test_certificate(Path(temp))
        server_configuration = QuicConfiguration(
            is_client=False, alpn_protocols=H3_ALPN
        )
        server_configuration.load_cert_chain(certificate_path, key_path)
        server = await serve(
            "127.0.0.1",
            HTTP3_PORT,
            configuration=server_configuration,
            create_protocol=H3ServerProtocol,
        )
        client_configuration = QuicConfiguration(
            is_client=True, alpn_protocols=H3_ALPN
        )
        client_configuration.verify_mode = ssl.CERT_NONE
        successes = 0
        negotiated = ""
        try:
            async with connect(
                "127.0.0.1",
                HTTP3_PORT,
                configuration=client_configuration,
                create_protocol=H3ClientProtocol,
            ) as client:
                for _ in range(3):
                    status, body, alpn = await client.get()
                    if status != 200 or body != b"http3-proof-ok" or alpn not in H3_ALPN:
                        raise RuntimeError(
                            f"invalid HTTP/3 response status={status} body={body!r} alpn={alpn}"
                        )
                    successes += 1
                    negotiated = alpn
        finally:
            server.close()
            await asyncio.sleep(0.2)
        return successes, negotiated


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * fraction))
    return ordered[index]


def main() -> None:
    duration_seconds = int(os.environ.get("DURATION_SECONDS", "30"))
    round_pause_milliseconds = int(os.environ.get("ROUND_PAUSE_MILLISECONDS", "100"))
    discovery_wait_seconds = 10
    if duration_seconds < 1 or duration_seconds > 300:
        raise ValueError("DURATION_SECONDS must be between 1 and 300")
    if round_pause_milliseconds < 20 or round_pause_milliseconds > 1_000:
        raise ValueError("ROUND_PAUSE_MILLISECONDS must be between 20 and 1000")

    server = TcpProtocolServer()
    server.start()
    h3_successes, h3_alpn = asyncio.run(http3_proof())
    time.sleep(discovery_wait_seconds)

    websocket_successes = 0
    grpc_web_successes = 0
    failures = 0
    latencies_ms: list[float] = []
    started = time.monotonic()
    deadline = started + duration_seconds
    while time.monotonic() < deadline:
        iteration_started = time.monotonic()
        try:
            websocket_round()
            websocket_successes += 1
            grpc_web_round()
            grpc_web_successes += 1
        except Exception:
            failures += 1
        latencies_ms.append((time.monotonic() - iteration_started) * 1000)
        time.sleep(round_pause_milliseconds / 1_000)

    elapsed = time.monotonic() - started
    server.close()
    if server.failures:
        failures += len(server.failures)
    operations = websocket_successes + grpc_web_successes
    print(
        json.dumps(
            {
                "schema": "e-navigator.protocol-surface-workload.v1",
                "duration_seconds": duration_seconds,
                "discovery_wait_seconds": discovery_wait_seconds,
                "round_pause_milliseconds": round_pause_milliseconds,
                "elapsed_seconds": round(elapsed, 6),
                "websocket_successes": websocket_successes,
                "grpc_web_successes": grpc_web_successes,
                "http3_successes": h3_successes,
                "http3_alpn": h3_alpn,
                "failures": failures,
                "operations_per_second": round(operations / elapsed, 6),
                "iteration_latency_ms": {
                    "p50": round(percentile(latencies_ms, 0.50), 6),
                    "p95": round(percentile(latencies_ms, 0.95), 6),
                    "p99": round(percentile(latencies_ms, 0.99), 6),
                },
                "server_failures": server.failures,
            },
            sort_keys=True,
        )
    )
    if failures or not websocket_successes or not grpc_web_successes or h3_successes != 3:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
