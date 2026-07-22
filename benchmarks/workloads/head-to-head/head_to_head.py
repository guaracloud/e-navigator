#!/usr/bin/env python3
"""Pinned five-family homelab workload and opaque OTLP acceptance sink."""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import json
import math
import os
import socket
import sys
import threading
import time
import zlib
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Awaitable, Callable, Protocol

import grpc
import psycopg
import redis.asyncio as redis_async
from redis.exceptions import RedisError


SCHEMA = "e-navigator.head-to-head-workload.v1"
SERVER_NODE = "homelab-02"
SERVICE_HOSTS = {
    "http": ("head-to-head-http", 18080),
    "grpc": ("head-to-head-grpc", 50051),
    "redis": ("head-to-head-redis-proxy", 16379),
    "postgres": ("head-to-head-postgres-proxy", 15432),
    "python_cpu": ("head-to-head-python-cpu", 19090),
}
DEFAULT_RATES = {
    "http": 100,
    "grpc": 80,
    "redis": 160,
    "postgres": 50,
    "python_cpu": 8,
}
DEFAULT_CONCURRENCY = {
    "http": 8,
    "grpc": 8,
    "redis": 8,
    "postgres": 5,
    "python_cpu": 2,
}
MAX_HTTP_BODY_BYTES = 1024 * 1024
MAX_OTLP_BODY_BYTES = 16 * 1024 * 1024
MAX_OTLP_DECOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_OFFERED_RPS = 1_000
MAX_CONCURRENCY = 128
MAX_LATENCY_SAMPLES = 300_000
OTLP_PATHS = frozenset(("/v1/metrics", "/v1/traces", "/v1/profiles"))


def set_process_name(name: str) -> None:
    """Set Linux comm so runtime evidence can identify each fixture."""

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        encoded = name.encode("ascii")[:15]
        result = libc.prctl(15, ctypes.c_char_p(encoded), 0, 0, 0)
        if result != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME) failed")
    except (AttributeError, OSError) as error:
        print(f"HEAD2HEAD_WARNING process_name={name} error={error}", flush=True)


def percentile(values: list[int], fraction: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


async def read_http_request(reader: asyncio.StreamReader) -> tuple[str, bytes] | None:
    try:
        header = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        return None
    lines = header.split(b"\r\n")
    if not lines or len(lines[0].split(b" ")) != 3:
        return None
    method, path, _version = lines[0].split(b" ", 2)
    content_length = 0
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.lower() == b"content-length":
            content_length = int(value.strip())
    if content_length < 0 or content_length > MAX_HTTP_BODY_BYTES:
        raise ValueError("HTTP request body exceeds the fixture limit")
    body = await reader.readexactly(content_length) if content_length else b""
    return f"{method.decode()} {path.decode()}", body


async def http_server_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    sequence = 0
    try:
        while request := await read_http_request(reader):
            _request_line, body = request
            sequence += 1
            value = len(body) + sequence
            for index in range(150):
                value = (value * 1_664_525 + index + 1_013_904_223) & 0xFFFFFFFF
            delay = 0.001 if sequence % 20 else 0.006
            await asyncio.sleep(delay)
            payload = json.dumps({"ok": True, "value": value}, separators=(",", ":")).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode()
                + b"Connection: keep-alive\r\n\r\n"
                + payload
            )
            await writer.drain()
    except (ConnectionError, ValueError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def run_http_server() -> None:
    set_process_name("enav-http")
    server = await asyncio.start_server(
        http_server_connection, "0.0.0.0", 18080, backlog=4096, limit=64 * 1024
    )
    print("HEAD2HEAD_READY role=http port=18080", flush=True)
    async with server:
        await server.serve_forever()


async def grpc_echo(request: bytes, _context: grpc.aio.ServicerContext) -> bytes:
    value = len(request)
    for index in range(100):
        value = (value * 1_103_515_245 + index + 12_345) & 0xFFFFFFFF
    await asyncio.sleep(0.001)
    return value.to_bytes(4, "big")


async def run_grpc_server() -> None:
    set_process_name("enav-grpc")
    server = grpc.aio.server(
        options=(
            ("grpc.max_concurrent_streams", 1024),
            ("grpc.so_reuseport", 0),
        )
    )
    handler = grpc.method_handlers_generic_handler(
        "bench.Echo",
        {
            "Call": grpc.unary_unary_rpc_method_handler(
                grpc_echo,
                request_deserializer=lambda payload: payload,
                response_serializer=lambda payload: payload,
            )
        },
    )
    server.add_generic_rpc_handlers((handler,))
    server.add_insecure_port("[::]:50051")
    await server.start()
    print("HEAD2HEAD_READY role=grpc port=50051", flush=True)
    await server.wait_for_termination()


async def wait_for_redis() -> redis_async.Redis:
    client = redis_async.Redis(
        host="head-to-head-redis",
        port=6379,
        decode_responses=False,
        socket_timeout=3,
        socket_connect_timeout=3,
    )
    for attempt in range(120):
        try:
            if await client.ping():
                return client
        except (OSError, RedisError):
            pass
        await asyncio.sleep(min(0.1 + attempt * 0.02, 1.0))
    await client.aclose()
    raise RuntimeError("Redis did not become ready")


async def redis_proxy_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    client: redis_async.Redis | None = None
    try:
        # Establish observed backend connections after each collector arm has
        # started. A process-wide connection created during workload bootstrap
        # predates eBPF attachment and makes Redis completeness depend on stale
        # socket state rather than the fixed offered workload.
        client = await wait_for_redis()
        while line := await reader.readline():
            sequence = int(line.strip())
            value = await client.incr(f"head-to-head:{sequence % 128}")
            writer.write(f"{value}\n".encode())
            await writer.drain()
    except (ConnectionError, ValueError, RedisError):
        pass
    finally:
        if client is not None:
            await client.aclose()
        writer.close()
        await writer.wait_closed()


async def run_redis_proxy() -> None:
    set_process_name("enav-redis")
    probe = await wait_for_redis()
    await probe.aclose()
    server = await asyncio.start_server(
        redis_proxy_connection,
        "0.0.0.0",
        16379,
        backlog=4096,
    )
    print("HEAD2HEAD_READY role=redis-proxy port=16379", flush=True)
    try:
        async with server:
            await server.serve_forever()
    finally:
        server.close()
        await server.wait_closed()


async def connect_postgres() -> psycopg.AsyncConnection[Any]:
    for attempt in range(120):
        try:
            return await psycopg.AsyncConnection.connect(
                "host=head-to-head-postgres port=5432 dbname=bench user=bench",
                autocommit=True,
                connect_timeout=3,
            )
        except psycopg.Error:
            await asyncio.sleep(min(0.1 + attempt * 0.02, 1.0))
    raise RuntimeError("PostgreSQL did not become ready")


async def postgres_proxy_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    connection: psycopg.AsyncConnection[Any] | None = None
    try:
        connection = await connect_postgres()
        async with connection.cursor() as cursor:
            while line := await reader.readline():
                sequence = int(line.strip())
                await cursor.execute("SELECT %s::bigint + 1", (sequence,))
                row = await cursor.fetchone()
                if row is None:
                    raise RuntimeError("PostgreSQL returned no row")
                writer.write(f"{row[0]}\n".encode())
                await writer.drain()
    except (ConnectionError, ValueError, psycopg.Error):
        pass
    finally:
        if connection is not None:
            await connection.close()
        writer.close()
        await writer.wait_closed()


async def run_postgres_proxy() -> None:
    set_process_name("enav-postgres")
    probe = await connect_postgres()
    await probe.close()
    server = await asyncio.start_server(
        postgres_proxy_connection, "0.0.0.0", 15432, backlog=4096
    )
    print("HEAD2HEAD_READY role=postgres-proxy port=15432", flush=True)
    async with server:
        await server.serve_forever()


def cpu_batch(seed: int) -> int:
    value = seed | 1
    for index in range(85_000):
        value = ((value << 7) ^ (value >> 3) ^ index ^ 0x9E3779B9) & 0xFFFFFFFF
    return value


async def cpu_server_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        while line := await reader.readline():
            sequence = int(line.strip())
            result = cpu_batch(sequence)
            writer.write(f"{result}\n".encode())
            await writer.drain()
    except (ConnectionError, ValueError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def run_cpu_server() -> None:
    set_process_name("enav-cpu")
    server = await asyncio.start_server(
        cpu_server_connection, "0.0.0.0", 19090, backlog=4096
    )
    print("HEAD2HEAD_READY role=python-cpu port=19090", flush=True)
    async with server:
        await server.serve_forever()


class Operation(Protocol):
    async def invoke(self, sequence: int) -> None: ...

    async def close(self) -> None: ...


class HttpOperation:
    def __init__(self) -> None:
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(*SERVICE_HOSTS["http"])

    async def invoke(self, sequence: int) -> None:
        if self.writer is None or self.reader is None:
            await self.connect()
        assert self.writer is not None and self.reader is not None
        body = f"head-to-head-{sequence:016d}".encode()
        self.writer.write(
            b"POST /work HTTP/1.1\r\nHost: head-to-head-http\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Content-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
            + body
        )
        await self.writer.drain()
        status = await self.reader.readline()
        if not status.startswith(b"HTTP/1.1 200"):
            raise RuntimeError(f"HTTP status: {status!r}")
        content_length: int | None = None
        while line := await self.reader.readline():
            if line == b"\r\n":
                break
            name, separator, value = line.partition(b":")
            if separator and name.lower() == b"content-length":
                content_length = int(value.strip())
        if content_length is None:
            raise RuntimeError("HTTP response omitted content-length")
        await self.reader.readexactly(content_length)

    async def close(self) -> None:
        if self.writer is not None:
            self.writer.close()
            await self.writer.wait_closed()
        self.reader = None
        self.writer = None


class GrpcOperation:
    def __init__(self) -> None:
        self.channel = grpc.aio.insecure_channel(
            "head-to-head-grpc:50051",
            options=(("grpc.enable_retries", 0),),
        )
        self.call = self.channel.unary_unary(
            "/bench.Echo/Call",
            request_serializer=lambda payload: payload,
            response_deserializer=lambda payload: payload,
        )

    async def invoke(self, sequence: int) -> None:
        response = await self.call(sequence.to_bytes(8, "big") + b"grpc-head-to-head", timeout=5)
        if len(response) != 4:
            raise RuntimeError(f"invalid gRPC response: {response!r}")

    async def close(self) -> None:
        await self.channel.close()


class LineOperation:
    def __init__(self, family: str) -> None:
        self.host, self.port = SERVICE_HOSTS[family]
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    async def invoke(self, sequence: int) -> None:
        if self.writer is None or self.reader is None:
            await self.connect()
        assert self.writer is not None and self.reader is not None
        self.writer.write(f"{sequence}\n".encode())
        await self.writer.drain()
        response = await asyncio.wait_for(self.reader.readline(), timeout=5)
        if not response.strip():
            raise RuntimeError("empty line-protocol response")

    async def close(self) -> None:
        if self.writer is not None:
            self.writer.close()
            await self.writer.wait_closed()
        self.reader = None
        self.writer = None


def operation_for(family: str) -> Operation:
    if family == "http":
        return HttpOperation()
    if family == "grpc":
        return GrpcOperation()
    return LineOperation(family)


async def load_worker(
    family: str,
    worker_id: int,
    concurrency: int,
    offered_rps: int,
    started_ns: int,
    deadline_ns: int,
    record: bool,
) -> dict[str, Any]:
    operation = operation_for(family)
    latencies: list[int] = []
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
                    latencies.append((time.perf_counter_ns() - operation_started) // 1_000)
            except (ConnectionError, OSError, RuntimeError, asyncio.TimeoutError, grpc.RpcError):
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


async def load_phase(seconds: int, record: bool) -> dict[str, Any]:
    rates, concurrency_by_family = load_contract(seconds, record)
    started_unix_nanos = time.time_ns()
    started_ns = time.perf_counter_ns()
    deadline_ns = started_ns + seconds * 1_000_000_000
    tasks: dict[str, Awaitable[list[dict[str, Any]]]] = {}
    for family, rate in rates.items():
        concurrency = concurrency_by_family[family]
        tasks[family] = asyncio.gather(
            *(
                load_worker(
                    family,
                    worker,
                    concurrency,
                    rate,
                    started_ns,
                    deadline_ns,
                    record,
                )
                for worker in range(concurrency)
            )
        )
    results = dict(zip(tasks, await asyncio.gather(*tasks.values()), strict=True))
    finished_ns = time.perf_counter_ns()
    elapsed_seconds = (finished_ns - started_ns) / 1_000_000_000
    families: dict[str, Any] = {}
    for family, worker_results in results.items():
        latencies = [value for result in worker_results for value in result["latencies_us"]]
        successes = sum(result["successes"] for result in worker_results)
        errors = sum(result["errors"] for result in worker_results)
        scheduled = sum(result["scheduled"] for result in worker_results)
        families[family] = {
            "offered_rps": rates[family],
            "concurrency": concurrency_by_family[family],
            "scheduled": scheduled,
            "successes": successes,
            "errors": errors,
            "throughput_rps": successes / elapsed_seconds,
            "latency_us": {
                "p50": percentile(latencies, 0.50),
                "p95": percentile(latencies, 0.95),
                "p99": percentile(latencies, 0.99),
                "max": percentile(latencies, 1.00),
            },
        }
    return {
        "started_unix_nanos": started_unix_nanos,
        "finished_unix_nanos": time.time_ns(),
        "elapsed_seconds": elapsed_seconds,
        "families": families,
    }


def load_contract(seconds: int, record: bool) -> tuple[dict[str, int], dict[str, int]]:
    rates = {}
    concurrency = {}
    for family in DEFAULT_RATES:
        rate = int(os.environ.get(f"HEAD2HEAD_{family.upper()}_RPS", DEFAULT_RATES[family]))
        workers = int(
            os.environ.get(
                f"HEAD2HEAD_{family.upper()}_CONCURRENCY", DEFAULT_CONCURRENCY[family]
            )
        )
        if not 1 <= rate <= MAX_OFFERED_RPS:
            raise ValueError(f"{family} offered rate must be 1..{MAX_OFFERED_RPS}")
        if not 1 <= workers <= MAX_CONCURRENCY:
            raise ValueError(f"{family} concurrency must be 1..{MAX_CONCURRENCY}")
        if record and rate * seconds > MAX_LATENCY_SAMPLES:
            raise ValueError(
                f"{family} latency sample bound exceeds {MAX_LATENCY_SAMPLES}"
            )
        rates[family] = rate
        concurrency[family] = workers
    return rates, concurrency


async def run_load() -> None:
    set_process_name("enav-load")
    warmup_seconds = int(os.environ.get("HEAD2HEAD_WARMUP_SECONDS", "15"))
    duration_seconds = int(os.environ.get("HEAD2HEAD_DURATION_SECONDS", "45"))
    if not 5 <= warmup_seconds <= 120 or not 20 <= duration_seconds <= 300:
        raise ValueError("warmup must be 5..120 seconds and duration must be 20..300 seconds")
    condition = os.environ.get("HEAD2HEAD_CONDITION", "unknown")
    repetition = int(os.environ.get("HEAD2HEAD_REPETITION", "0"))
    warmup = await load_phase(warmup_seconds, False)
    measured = await load_phase(duration_seconds, True)
    result = {
        "schema": SCHEMA,
        "condition": condition,
        "repetition": repetition,
        "load_node": os.environ.get("NODE_NAME", socket.gethostname()),
        "server_node": SERVER_NODE,
        "python_version": sys.version.split()[0],
        "warmup_seconds": warmup_seconds,
        "duration_seconds": duration_seconds,
        "warmup": warmup,
        "measured": measured,
    }
    print("HEAD2HEAD_RESULT " + json.dumps(result, sort_keys=True), flush=True)
    failures = sum(
        family["errors"]
        for phase in (warmup, measured)
        for family in phase["families"].values()
    )
    missing = sum(
        family["scheduled"] - family["successes"]
        for phase in (warmup, measured)
        for family in phase["families"].values()
    )
    if failures or missing:
        raise SystemExit(1)


class OtlpSinkHandler(BaseHTTPRequestHandler):
    lock = threading.Lock()
    requests: Counter[str] = Counter()
    bytes_received: Counter[str] = Counter()
    encodings: Counter[str] = Counter()

    def log_message(self, _format: str, *_args: object) -> None:
        return

    @classmethod
    def snapshot(cls) -> dict[str, Any]:
        with cls.lock:
            return {
                "schema": "e-navigator.head-to-head-otlp-sink.v1",
                "requests": dict(sorted(cls.requests.items())),
                "bytes_received": dict(sorted(cls.bytes_received.items())),
                "content_encodings": dict(sorted(cls.encodings.items())),
            }

    @classmethod
    def reset(cls) -> None:
        with cls.lock:
            cls.requests.clear()
            cls.bytes_received.clear()
            cls.encodings.clear()

    def send_json(self, status: int, value: dict[str, Any]) -> None:
        payload = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_json(200, {"status": "ready"})
        elif self.path == "/stats":
            self.send_json(200, self.snapshot())
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path == "/reset":
            self.reset()
            self.send_json(200, self.snapshot())
            return
        if self.path not in OTLP_PATHS:
            self.send_json(404, {"error": "unsupported OTLP path"})
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length < 0 or content_length > MAX_OTLP_BODY_BYTES:
            self.send_json(413, {"error": "OTLP request exceeds the fixture limit"})
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


def run_otlp_sink() -> None:
    set_process_name("enav-otlp-sink")
    server = ThreadingHTTPServer(("0.0.0.0", 4318), OtlpSinkHandler)
    print("HEAD2HEAD_READY role=otlp-sink port=4318", flush=True)
    server.serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "role",
        choices=("http", "grpc", "redis-proxy", "postgres-proxy", "python-cpu", "load", "otlp-sink"),
    )
    return parser.parse_args()


def main() -> None:
    role = parse_args().role
    if role == "otlp-sink":
        run_otlp_sink()
        return
    coroutine: Callable[[], Awaitable[None]] = {
        "http": run_http_server,
        "grpc": run_grpc_server,
        "redis-proxy": run_redis_proxy,
        "postgres-proxy": run_postgres_proxy,
        "python-cpu": run_cpu_server,
        "load": run_load,
    }[role]
    asyncio.run(coroutine())


if __name__ == "__main__":
    main()
