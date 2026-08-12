import socket
import threading


PROXY_PORT = 18080
DOWNSTREAM_PORT = 18081
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
UPSTREAM_SPAN_ID = "00f067aa0ba902b7"
TRACESTATE = "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE"


def listening_socket(port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    return server


def receive_request(connection: socket.socket) -> bytes:
    request = bytearray()
    header_end = None
    content_length = 0
    while header_end is None or len(request) < header_end + content_length:
        chunk = connection.recv(4096)
        if not chunk:
            break
        request.extend(chunk)
        if header_end is None:
            marker = request.find(b"\r\n\r\n")
            if marker >= 0:
                header_end = marker + 4
                for line in request[:marker].split(b"\r\n")[1:]:
                    name, separator, value = line.partition(b":")
                    if separator and name.lower() == b"content-length":
                        content_length = int(value.strip())
    return bytes(request)


downstream_ready = threading.Event()
proxy_ready = threading.Event()
downstream_result: list[bytes] = []
thread_errors: list[BaseException] = []


def downstream_server() -> None:
    try:
        with listening_socket(DOWNSTREAM_PORT) as server:
            downstream_ready.set()
            connection, _ = server.accept()
            with connection:
                downstream_result.append(receive_request(connection))
                connection.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    except BaseException as error:
        thread_errors.append(error)


def upstream_client() -> None:
    try:
        proxy_ready.wait(timeout=5)
        with socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=5) as client:
            request = (
                "GET /proxy HTTP/1.1\r\n"
                "Host: proxy\r\n"
                f"traceparent: 00-{TRACE_ID}-{UPSTREAM_SPAN_ID}-01\r\n"
                f"tracestate: {TRACESTATE}\r\n"
                "\r\n"
            ).encode()
            client.sendall(request)
            client.recv(4096)
    except BaseException as error:
        thread_errors.append(error)


downstream_thread = threading.Thread(target=downstream_server)
downstream_thread.start()
if not downstream_ready.wait(timeout=5):
    raise RuntimeError("downstream listener did not start")

with listening_socket(PROXY_PORT) as proxy:
    client_thread = threading.Thread(target=upstream_client)
    client_thread.start()
    proxy_ready.set()
    connection, _ = proxy.accept()
    with connection:
        receive_request(connection)
        with socket.create_connection(("127.0.0.1", DOWNSTREAM_PORT), timeout=5) as downstream:
            parts = [
                b"POST /sink HTTP/1.1\r\nHost: downstream\r\n",
                b"Content-Length: 4\r\n\r\n",
                b"data",
            ]
            expected = sum(map(len, parts))
            sent = downstream.sendmsg(parts)
            if sent != expected:
                raise RuntimeError(f"short sendmsg: sent={sent} expected={expected}")
            downstream.recv(4096)
        connection.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")

client_thread.join(timeout=5)
downstream_thread.join(timeout=5)
if client_thread.is_alive() or downstream_thread.is_alive():
    raise RuntimeError("workload thread did not stop")
if thread_errors:
    raise thread_errors[0]
if len(downstream_result) != 1:
    raise RuntimeError("downstream request was not captured")

request = downstream_result[0]
headers, body = request.split(b"\r\n\r\n", 1)
traceparents = [
    line.split(b":", 1)[1].strip().decode()
    for line in headers.split(b"\r\n")[1:]
    if line.lower().startswith(b"traceparent:")
]
tracestates = [
    line.split(b":", 1)[1].strip().decode()
    for line in headers.split(b"\r\n")[1:]
    if line.lower().startswith(b"tracestate:")
]
if len(traceparents) != 1:
    raise RuntimeError(f"expected one traceparent, got {traceparents!r}")
parts = traceparents[0].split("-")
if len(parts) != 4 or parts[0] != "00" or parts[1] != TRACE_ID or parts[3] != "01":
    raise RuntimeError(f"unexpected propagated traceparent: {traceparents[0]}")
if parts[2] == UPSTREAM_SPAN_ID or parts[2] == "0000000000000000":
    raise RuntimeError(f"propagation did not create a child span: {traceparents[0]}")
if tracestates != [TRACESTATE]:
    raise RuntimeError(f"tracestate was not preserved: {tracestates!r}")
if body != b"data":
    raise RuntimeError(f"body changed during propagation: {body!r}")

print("http-propagation-workload-ok write=sendmsg body=4 tracestate=preserved")
