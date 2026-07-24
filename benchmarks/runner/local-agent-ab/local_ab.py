"""Local whole-agent A/B workload for the optimization campaign.

Stdlib-only trim of benchmarks/workloads/head-to-head/head_to_head.py:
- redis-proxy: line protocol -> raw RESP INCR against local redis:6379,
  one backend connection per inbound connection, established after the
  collector has attached (mirrors the corrected homelab contract).
- http: the same minimal HTTP/1.1 echo server on 8080.
- load: fixed-rate pacing identical to head_to_head.py (sequence-slot
  scheduling), warmup phase unrecorded, measured phase recorded.
- otlp-sink: opaque gzip-aware collector on 4318 (counts only).

Env: LOCAL_AB_RATES like "redis=800,http=100"; LOCAL_AB_WARMUP_SECONDS;
LOCAL_AB_DURATION_SECONDS; LOCAL_AB_CONCURRENCY like "redis=8,http=8".
"""

import asyncio
import ctypes
import ctypes.util
import json
import os
import sys
import time
import threading
import zlib
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def set_process_name(name: str) -> None:
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        buffer = ctypes.create_string_buffer(name.encode()[:15])
        libc.prctl(15, buffer, 0, 0, 0)  # PR_SET_NAME
    except (OSError, AttributeError):
        pass

SERVICE_HOSTS = {
    "redis": ("127.0.0.1", 16379),
    "http": ("127.0.0.1", 8080),
}
MAX_OTLP_BODY_BYTES = 64 * 1024 * 1024
MAX_OTLP_DECOMPRESSED_BYTES = 256 * 1024 * 1024
OTLP_PATHS = ("/v1/traces", "/v1/metrics", "/v1development/profiles")


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


# ---------------------------------------------------------------- redis proxy

async def open_redis():
    for attempt in range(240):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", 6379)
            writer.write(b"*1\r\n$4\r\nPING\r\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=3)
            if line.startswith(b"+PONG"):
                return reader, writer
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError, asyncio.TimeoutError):
            pass
        await asyncio.sleep(min(0.1 + attempt * 0.02, 1.0))
    raise RuntimeError("redis did not become ready")


async def redis_proxy_connection(reader, writer):
    backend = None
    try:
        backend = await open_redis()
        backend_reader, backend_writer = backend
        while line := await reader.readline():
            sequence = int(line.strip())
            key = f"head-to-head:{sequence % 128}"
            backend_writer.write(
                f"*2\r\n$4\r\nINCR\r\n${len(key)}\r\n{key}\r\n".encode()
            )
            await backend_writer.drain()
            response = await backend_reader.readline()
            if not response.startswith(b":"):
                raise RuntimeError(f"unexpected RESP reply: {response!r}")
            writer.write(response[1:])
            await writer.drain()
    except (ConnectionError, ValueError, RuntimeError, OSError):
        pass
    finally:
        if backend is not None:
            backend[1].close()
            try:
                await backend[1].wait_closed()
            except (ConnectionError, OSError):
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def run_redis_proxy():
    probe = await open_redis()
    probe[1].close()
    await probe[1].wait_closed()
    server = await asyncio.start_server(
        redis_proxy_connection, "0.0.0.0", 16379, backlog=4096
    )
    print("LOCAL_AB_READY role=redis-proxy port=16379", flush=True)
    async with server:
        await server.serve_forever()


# ----------------------------------------------------------------- http echo

async def read_http_request(reader):
    request_line = await reader.readline()
    if not request_line:
        return None
    headers = {}
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b""):
            break
        name, separator, value = line.partition(b":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    length = int(headers.get(b"content-length", b"0"))
    body = await reader.readexactly(length) if length else b""
    return request_line.decode("latin-1"), body


async def http_server_connection(reader, writer):
    try:
        while True:
            request = await read_http_request(reader)
            if request is None:
                break
            _, body = request
            response_body = f"ok:{len(body)}".encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                + f"Content-Length: {len(response_body)}\r\n".encode()
                + b"Connection: keep-alive\r\n\r\n"
                + response_body
            )
            await writer.drain()
    except (ConnectionError, ValueError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def run_http_server():
    server = await asyncio.start_server(
        http_server_connection, "0.0.0.0", 8080, backlog=4096
    )
    print("LOCAL_AB_READY role=http port=8080", flush=True)
    async with server:
        await server.serve_forever()


# ---------------------------------------------------------------------- load

class ConnectionOperation:
    """Owns one lazily opened client connection to a service host."""

    def __init__(self, family):
        self.host, self.port = SERVICE_HOSTS[family]
        self.reader = None
        self.writer = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    async def ensure_connected(self):
        if self.writer is None or self.reader is None:
            await self.connect()

    async def close(self):
        if self.writer is not None:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        self.reader = None
        self.writer = None


class HttpOperation(ConnectionOperation):
    def __init__(self):
        super().__init__("http")

    async def invoke(self, sequence):
        await self.ensure_connected()
        body = f"head-to-head-{sequence:016d}".encode()
        self.writer.write(
            b"POST /work HTTP/1.1\r\nHost: local-ab-http\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Content-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
            + body
        )
        await self.writer.drain()
        status = await self.reader.readline()
        if not status.startswith(b"HTTP/1.1 200"):
            raise RuntimeError(f"HTTP status: {status!r}")
        content_length = None
        while line := await self.reader.readline():
            if line == b"\r\n":
                break
            name, separator, value = line.partition(b":")
            if separator and name.lower() == b"content-length":
                content_length = int(value.strip())
        if content_length is None:
            raise RuntimeError("HTTP response omitted content-length")
        await self.reader.readexactly(content_length)


class LineOperation(ConnectionOperation):
    async def invoke(self, sequence):
        await self.ensure_connected()
        self.writer.write(f"{sequence}\n".encode())
        await self.writer.drain()
        response = await asyncio.wait_for(self.reader.readline(), timeout=5)
        if not response.strip():
            raise RuntimeError("empty line-protocol response")


def operation_for(family):
    if family == "http":
        return HttpOperation()
    return LineOperation(family)


async def load_worker(family, worker_id, concurrency, offered_rps, started_ns,
                      deadline_ns, record):
    operation = operation_for(family)
    latencies = []
    successes = 0
    errors = 0
    scheduled = 0
    iteration = 0
    try:
        while True:
            sequence = worker_id + iteration * concurrency
            due_ns = started_ns + (sequence * 1_000_000_000) // offered_rps
            if due_ns >= deadline_ns:
                break
            remaining_ns = due_ns - time.perf_counter_ns()
            if remaining_ns > 0:
                await asyncio.sleep(remaining_ns / 1_000_000_000)
            scheduled += 1
            operation_started = time.perf_counter_ns()
            try:
                await operation.invoke(sequence)
                successes += 1
                if record:
                    latencies.append(
                        (time.perf_counter_ns() - operation_started) // 1_000
                    )
            except (ConnectionError, OSError, RuntimeError, asyncio.TimeoutError):
                errors += 1
                await operation.close()
                operation = operation_for(family)
                await asyncio.sleep(0.01)
            iteration += 1
    finally:
        await operation.close()
    return {
        "latencies_us": latencies,
        "successes": successes,
        "errors": errors,
        "scheduled": scheduled,
    }


def parse_pairs(raw, default):
    if not raw:
        return dict(default)
    result = {}
    for part in raw.split(","):
        name, _, value = part.partition("=")
        result[name.strip()] = int(value)
    return result


async def load_phase(rates, concurrency_by_family, seconds, record):
    started_ns = time.perf_counter_ns()
    deadline_ns = started_ns + seconds * 1_000_000_000
    tasks = {}
    for family, rate in rates.items():
        concurrency = concurrency_by_family.get(family, 8)
        tasks[family] = asyncio.gather(
            *(
                load_worker(family, worker, concurrency, rate, started_ns,
                            deadline_ns, record)
                for worker in range(concurrency)
            )
        )
    results = {}
    for family, task in tasks.items():
        outcomes = await task
        latencies = [value for outcome in outcomes for value in outcome["latencies_us"]]
        results[family] = {
            "successes": sum(outcome["successes"] for outcome in outcomes),
            "errors": sum(outcome["errors"] for outcome in outcomes),
            "scheduled": sum(outcome["scheduled"] for outcome in outcomes),
            "latency_p50_us": percentile(latencies, 0.50),
            "latency_p95_us": percentile(latencies, 0.95),
            "latency_p99_us": percentile(latencies, 0.99),
        }
    return results


async def run_load():
    rates = parse_pairs(os.environ.get("LOCAL_AB_RATES"), {"redis": 800})
    concurrency = parse_pairs(os.environ.get("LOCAL_AB_CONCURRENCY"), {"redis": 8, "http": 8})
    warmup = int(os.environ.get("LOCAL_AB_WARMUP_SECONDS", "10"))
    duration = int(os.environ.get("LOCAL_AB_DURATION_SECONDS", "60"))
    await load_phase(rates, concurrency, warmup, record=False)
    print("LOCAL_AB_MEASURE_START", flush=True)
    started_unix_nanos = time.time_ns()
    results = await load_phase(rates, concurrency, duration, record=True)
    print("LOCAL_AB_MEASURE_END", flush=True)
    print(
        "LOCAL_AB_RESULT "
        + json.dumps(
            {
                "schema": "e-navigator.local-ab-load.v1",
                "rates": rates,
                "warmup_seconds": warmup,
                "duration_seconds": duration,
                "started_unix_nanos": started_unix_nanos,
                "families": results,
            },
            sort_keys=True,
        ),
        flush=True,
    )


# ----------------------------------------------------------------- otlp sink

class OtlpSinkHandler(BaseHTTPRequestHandler):
    lock = threading.Lock()
    requests = Counter()
    bytes_received = Counter()
    encodings = Counter()

    def log_message(self, _format, *_args):
        return

    @classmethod
    def snapshot(cls):
        with cls.lock:
            return {
                "schema": "e-navigator.local-ab-otlp-sink.v1",
                "requests": dict(sorted(cls.requests.items())),
                "bytes_received": dict(sorted(cls.bytes_received.items())),
                "content_encodings": dict(sorted(cls.encodings.items())),
            }

    def send_json(self, status, value):
        payload = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"status": "ready"})
        elif self.path == "/stats":
            self.send_json(200, self.snapshot())
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in OTLP_PATHS:
            self.send_json(404, {"error": "unsupported OTLP path"})
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length < 0 or content_length > MAX_OTLP_BODY_BYTES:
            self.send_json(413, {"error": "body exceeds the fixture limit"})
            return
        payload = self.rfile.read(content_length)
        encoding = self.headers.get("Content-Encoding", "identity")
        if encoding == "gzip":
            try:
                decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                decoded = decompressor.decompress(payload, MAX_OTLP_DECOMPRESSED_BYTES + 1)
                remaining = MAX_OTLP_DECOMPRESSED_BYTES + 1 - len(decoded)
                if remaining > 0:
                    decoded += decompressor.flush(remaining)
                if (
                    len(decoded) > MAX_OTLP_DECOMPRESSED_BYTES
                    or decompressor.unconsumed_tail
                    or not decompressor.eof
                ):
                    raise ValueError("gzip payload exceeds the decompressed limit")
            except (ValueError, zlib.error):
                self.send_json(400, {"error": "invalid gzip"})
                return
        elif encoding != "identity":
            self.send_json(415, {"error": "unsupported content encoding"})
            return
        with self.lock:
            self.requests[self.path] += 1
            self.bytes_received[self.path] += len(payload)
            self.encodings[encoding] += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", "0")
        self.end_headers()


def run_otlp_sink():
    server = ThreadingHTTPServer(("0.0.0.0", 4318), OtlpSinkHandler)
    print("LOCAL_AB_READY role=otlp-sink port=4318", flush=True)
    server.serve_forever()


def main():
    role = sys.argv[1]
    set_process_name(
        {
            "otlp-sink": "enav-otlp-sink",
            "load": "enav-load",
            "redis-proxy": "enav-redis",
            "http": "enav-http",
        }[role]
    )
    if role == "otlp-sink":
        run_otlp_sink()
        return
    coroutine = {
        "redis-proxy": run_redis_proxy,
        "http": run_http_server,
        "load": run_load,
    }[role]
    asyncio.run(coroutine())


if __name__ == "__main__":
    main()
