import shutil
import ssl
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

import httpx2
import pytest
from cerbia.core.apis import APIError
from cerbia.core.apis._http import HTTPClient


@pytest.mark.parametrize("trusted", [False, True])
def test_tls_verification_when_local_ca_is_trusted_only_via_environment(
    trusted: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a fresh local CA that cannot already be in the system trust store.
    if shutil.which("openssl") is None:
        pytest.skip("openssl is required to generate the local TLS certificate")
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
        check=True,
        capture_output=True,
        timeout=10,
    )
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    if trusted:
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: str) -> None:
            return

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = HTTPClient(base_url=f"https://127.0.0.1:{server.server_port}", endpoint_path="/evaluate", timeout=2)
        try:
            # When / Then: the real HTTP client rejects unknown CAs but honors SSL_CERT_FILE.
            if trusted:
                assert client.request('{"text":"local only"}') == b'{"text":"local only"}'
            else:
                with pytest.raises(APIError) as error:
                    client.request("{}")
                assert isinstance(error.value.__context__, httpx2.ConnectError)
                assert error.value.__suppress_context__
        finally:
            server.shutdown()
            thread.join(timeout=5)
