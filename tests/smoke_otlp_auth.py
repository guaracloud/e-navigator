#!/usr/bin/env python3
"""Exercise the real CLI against disposable loopback OTLP receivers.

Run after cargo build --locked -p e-navigator-cli. Requires Python 3 and openssl.
No external services, credentials, third-party Python packages, or privileged
capture are used. This checks HTTP transport contracts, not backend persistence.
"""
import argparse
import base64
import contextlib
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading


class Receiver(http.server.ThreadingHTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def receiver(context=None, respond=None):
    records = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            assert 0 < length < 8 * 1024 * 1024, "expected bounded nonempty protobuf"
            body = self.rfile.read(length)
            records.append((self.path, dict(self.headers.items()), body))
            status, headers = respond(records) if respond else (200, {})
            self.send_response(status)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", "0")
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()

    server = Receiver(("127.0.0.1", 0), Handler)
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f'{"https" if context else "http"}://127.0.0.1:{server.server_port}', records
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def certificate(directory, name, authority=None, client=False):
    cert, key = directory / f"{name}.pem", directory / f"{name}.key"

    def openssl(*arguments):
        subprocess.run(["openssl", *map(str, arguments)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)

    if authority is None:
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                "-out", cert, "-days", "1", "-subj", f"/CN={name}",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    else:
        request = directory / f"{name}.csr"
        extensions = directory / f"{name}.ext"
        extensions.write_text("basicConstraints=critical,CA:FALSE\n"
                              "keyUsage=critical,digitalSignature,keyEncipherment\n"
                              f"extendedKeyUsage={'clientAuth' if client else 'serverAuth'}\n"
                              "subjectAltName=IP:127.0.0.1\n")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                "-out", request, "-subj", f"/CN={name}")
        openssl("x509", "-req", "-in", request, "-CA", authority[0],
                "-CAkey", authority[1], "-CAcreateserial", "-out", cert,
                "-days", "1", "-extfile", extensions)
    return cert, key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/e-navigator")
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    if not binary.is_file():
        parser.error(f"build the CLI first: binary missing at {binary}")
    with tempfile.TemporaryDirectory(prefix="e-navigator-auth-smoke-") as temporary:
        directory = Path(temporary)
        token = directory / "token"
        token.write_text("first-token")
        authority = certificate(directory, "authority")
        cert, key = certificate(directory, "receiver", authority)
        wrong_cert, _ = certificate(directory, "wrong-ca")
        client_cert, client_key = certificate(directory, "client", authority, client=True)

        def run(endpoint, additions="", traces_endpoint=None, env=None, succeeds=True):
            config = directory / "config.toml"
            config.write_text(f'''log_level = "error"
[otlp_http]
enabled = true
metrics_enabled = true
metrics_endpoint = {json.dumps(endpoint + "/v1/metrics")}
logs_enabled = false
traces_enabled = {str(traces_endpoint is not None).lower()}
traces_endpoint = {json.dumps((traces_endpoint or endpoint) + "/v1/traces")}
profiles_enabled = false
batch_size = 64
flush_interval_millis = 10
timeout_millis = 1000
max_retries = 1
retry_initial_backoff_millis = 10
retry_max_backoff_millis = 20
{additions}
[[modules]]
name = "source.synthetic_exec"
enabled = true
[[modules]]
name = "generator.network_metrics"
enabled = true
[[modules]]
name = "generator.trace_correlation"
enabled = true
[[modules]]
name = "sink.otlp_http"
enabled = true
''')
            result = subprocess.run([str(binary), "--source", "synthetic", "--config", str(config)],
                                    capture_output=True, timeout=5, env={**os.environ, **(env or {})})
            if succeeds:
                assert result.returncode == 0, f"CLI failed: {result.stderr.decode(errors='replace')}"
            else:
                assert result.returncode != 0, "invalid connection must fail startup"
                assert "secret-canary" not in result.stderr.decode(errors="replace")

        def header(record, name):
            return next((value for key, value in record[1].items() if key.lower() == name.lower()), None)

        with receiver() as (metrics_url, metrics), receiver() as (traces_url, traces):
            run(metrics_url, f'''[otlp_http.metrics_auth]
type = "bearer"
token = {{ file = {json.dumps(str(token))} }}
[otlp_http.metrics_headers]
"X-Scope-OrgID" = {{ literal = "smoke-tenant" }}
"X-Test-Secret" = {{ env = "E_NAVIGATOR_SMOKE_HEADER" }}
[otlp_http.metrics_tls]
allow_plaintext_auth = true
''', traces_url, {"E_NAVIGATOR_SMOKE_HEADER": "ephemeral-header"})
            assert metrics and traces, "both families must produce nonempty requests"
            assert all(header(r, "Authorization") == "Bearer first-token" for r in metrics)
            assert all(header(r, "X-Scope-OrgID") == "smoke-tenant" for r in metrics)
            assert all(header(r, "X-Test-Secret") == "ephemeral-header" for r in metrics)
            assert all(header(r, "Content-Type") == "application/x-protobuf" for r in metrics + traces)
            assert all(header(r, "Authorization") is None and header(r, "X-Test-Secret") is None for r in traces)
        print("PASS bearer file, literal/environment headers, nonempty metrics/traces, signal isolation")

        with receiver() as (url, records):
            run(url, '''[otlp_http.metrics_auth]
type = "basic"
username = { env = "E_NAVIGATOR_SMOKE_USER" }
password = { env = "E_NAVIGATOR_SMOKE_PASSWORD" }
[otlp_http.metrics_tls]
allow_plaintext_auth = true
''', env={"E_NAVIGATOR_SMOKE_USER": "smoke", "E_NAVIGATOR_SMOKE_PASSWORD": "password"})
            expected = "Basic " + base64.b64encode(b"smoke:password").decode()
            assert records and all(header(r, "Authorization") == expected for r in records)
        print("PASS Basic authentication")

        if hasattr(os, "mkfifo"):
            fifo = directory / "credential-fifo"
            os.mkfifo(fifo)
            run("http://127.0.0.1:9", f'''[otlp_http.metrics_auth]
type = "bearer"
token = {{ file = {json.dumps(str(fifo))} }}
[otlp_http.metrics_tls]
allow_plaintext_auth = true
''', succeeds=False)
            print("PASS FIFO credential source fails startup without blocking")

        def rotate(records):
            if len(records) == 1:
                replacement = directory / "replacement"
                replacement.write_text("second-token")
                replacement.replace(token)
                return 503, {}
            return 200, {}

        with receiver(respond=rotate) as (url, records):
            run(url, f'''[otlp_http.metrics_auth]
type = "bearer"
token = {{ file = {json.dumps(str(token))} }}
[otlp_http.metrics_tls]
allow_plaintext_auth = true
''')
            assert len(records) >= 2
            assert header(records[0], "Authorization") == "Bearer first-token"
            assert all(header(r, "Authorization") == "Bearer second-token" for r in records[1:])
        print("PASS atomic token rotation before retry")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        with receiver(context) as (url, records):
            run(url, f'[otlp_http.metrics_tls]\nca_file = {json.dumps(str(authority[0]))}\n')
            assert records, "custom CA must permit verified HTTPS export"
            records.clear()
            run(url, f'[otlp_http.metrics_tls]\nca_file = {json.dumps(str(wrong_cert))}\n')
            assert not records, "wrong CA must prevent application requests"
        print("PASS custom CA and wrong-CA rejection")

        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(authority[0]))
        with receiver(context) as (url, records):
            run(url, f'''[otlp_http.metrics_tls]
ca_file = {json.dumps(str(authority[0]))}
client_certificate_file = {json.dumps(str(client_cert))}
client_key_file = {json.dumps(str(client_key))}
''')
            assert records, "mTLS identity must permit export"
            records.clear()
            run(url, f'[otlp_http.metrics_tls]\nca_file = {json.dumps(str(authority[0]))}\n')
            assert not records, "missing client certificate must prevent requests"
        print("PASS mTLS identity and missing-identity rejection")

        with receiver() as (destination, forwarded):
            with receiver(respond=lambda _: (307, {"Location": destination + "/stolen"})) as (url, records):
                run(url, f'''[otlp_http.metrics_auth]
type = "bearer"
token = {{ file = {json.dumps(str(token))} }}
[otlp_http.metrics_tls]
allow_plaintext_auth = true
''')
                assert records and not forwarded, "exporter must not follow redirect"
        print("PASS redirect refusal")
    print("PASS local CLI OTLP transport smoke; no backend persistence qualification")


if __name__ == "__main__":
    main()
