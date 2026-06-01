"""Black-box smoke tests for everything under ``examples/``.

Each example is run exactly the way its docstring documents — as a subprocess
using the current interpreter:

* Self-contained scripts must exit 0.
* Server/client pairs start the server as a subprocess, wait for its port,
  run the client, and assert it exits 0.

Server-based tests are skipped when their optional deps (``fastapi`` /
``uvicorn`` / ``flask``) are not installed, so ``uv sync --group dev`` alone
still passes; install them with ``uv sync --group examples``.
"""
from __future__ import annotations

import contextlib
import importlib.util
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
EXAMPLES = REPO / "examples"

_HAS_SERVER = all(importlib.util.find_spec(m) for m in ("fastapi", "uvicorn"))
_HAS_FLASK = importlib.util.find_spec("flask") is not None
_HAS_ZEEP = importlib.util.find_spec("zeep") is not None

requires_server = pytest.mark.skipif(
    not _HAS_SERVER, reason="fastapi/uvicorn not installed (uv sync --group examples)"
)


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------
def _run(script: Path, *args: str, timeout: float = 90.0) -> subprocess.CompletedProcess[str]:
    """Run an example script and capture its output."""
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _wait_port(port: int, timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


@contextlib.contextmanager
def _serve(script: str, port: int):
    """Start an example server, wait until it binds ``port``, then clean up.

    Runs in its own process group so we can reap children too (werkzeug's
    reloader and uvicorn both spawn helpers).
    """
    proc = subprocess.Popen(
        [sys.executable, str(EXAMPLES / script)],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=os.name == "posix",
    )
    try:
        if not _wait_port(port):
            with contextlib.suppress(Exception):
                _kill(proc)
            out = ""
            with contextlib.suppress(Exception):
                out = proc.communicate(timeout=5)[0] or ""
            pytest.fail(f"server {script} did not bind :{port}\n{out}")
        yield proc
    finally:
        _kill(proc)


def _kill(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if os.name == "posix":
        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    else:  # pragma: no cover - examples CI runs on POSIX
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover
        if os.name == "posix":
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()


def _ok(result: subprocess.CompletedProcess[str], label: str) -> None:
    assert result.returncode == 0, (
        f"{label} exited {result.returncode}\n"
        f"--- stdout/stderr ---\n{result.stdout}{result.stderr}"
    )


# ---------------------------------------------------------------------------
# 1. Self-contained scripts (no server)
# ---------------------------------------------------------------------------
SELF_CONTAINED = [
    "04_ws_security_signing/sign_and_verify.py",
    "07_mtom_attachments/build_and_parse.py",
    "08_binding_styles/compare_styles.py",
    "14_security_replay_protection/replay_demo.py",
    "15_xml_encryption/encrypt_and_decrypt.py",
    "16_introspection/inspect_envelope.py",
]


@pytest.mark.parametrize("script", SELF_CONTAINED)
def test_self_contained(script: str) -> None:
    _ok(_run(EXAMPLES / script), script)


# ---------------------------------------------------------------------------
# 2. Server / client pairs that own a dedicated port
# ---------------------------------------------------------------------------
# These clients call through SoapClient, which raises on a fault or parse
# error, so a clean exit is a meaningful pass.
PAIRS = [
    ("02_soap12/server.py", 8012, "02_soap12/client.py"),
    ("05_ws_addressing/server.py", 8005, "05_ws_addressing/client.py"),
    ("06_username_token_auth/server.py", 8006, "06_username_token_auth/client.py"),
    ("09_async_client/server.py", 8009, "09_async_client/client_async.py"),
    ("10_complex_types/server.py", 8010, "10_complex_types/client.py"),
]


@requires_server
@pytest.mark.parametrize("server,port,client", PAIRS, ids=[p[2].split("/")[0] for p in PAIRS])
def test_server_client(server: str, port: int, client: str) -> None:
    with _serve(server, port):
        result = _run(EXAMPLES / client)
    _ok(result, client)


# 11 and 12 use raw httpx and only *print* their results (no internal assert),
# so we verify the actual output, not just the exit code.
@requires_server
def test_one_way_and_json() -> None:
    with _serve("11_one_way_and_json/server.py", 8011):
        result = _run(EXAMPLES / "11_one_way_and_json/client.py")
    _ok(result, "11/client.py")
    assert "HTTP status = 202" in result.stdout  # one-way → 202 + empty body
    assert "application/json" in result.stdout  # JSON dual-mode honoured
    assert '"return": "echo: hello"' in result.stdout


@requires_server
def test_schema_validation() -> None:
    with _serve("12_schema_validation/server.py", 8012):
        result = _run(EXAMPLES / "12_schema_validation/client.py")
    _ok(result, "12/client.py")
    assert "<return>81</return>" in result.stdout  # valid request was computed
    assert "soapenv:Client" in result.stdout  # invalid request raised a Client fault


# ---------------------------------------------------------------------------
# 3. Calculator (:8000) — reused by the 01 clients, 13/* and 16 inspect_wsdl
# ---------------------------------------------------------------------------
@requires_server
def test_calculator_and_dependents(tmp_path: Path) -> None:
    clients = [
        "01_calculator/client.py",
        "13_advanced_client/custom_transport.py",
        "13_advanced_client/manual_client.py",
    ]
    if _HAS_ZEEP:
        clients.insert(1, "01_calculator/client_zeep.py")

    with _serve("01_calculator/server_fastapi.py", 8000):
        for client in clients:
            _ok(_run(EXAMPLES / client), client)

        # 13/from_file_client.py consumes a WSDL saved to disk.
        wsdl = tmp_path / "calculator.wsdl"
        with urllib.request.urlopen("http://127.0.0.1:8000/soap?wsdl", timeout=10) as resp:
            wsdl.write_bytes(resp.read())
        assert b"definitions" in wsdl.read_bytes()
        _ok(
            _run(EXAMPLES / "13_advanced_client/from_file_client.py", str(wsdl)),
            "13/from_file_client.py",
        )

        # 16/inspect_wsdl.py walks a live WSDL URL.
        inspect = _run(
            EXAMPLES / "16_introspection/inspect_wsdl.py",
            "http://127.0.0.1:8000/soap?wsdl",
        )
        _ok(inspect, "16/inspect_wsdl.py")
        assert "Calculator" in inspect.stdout  # the contract was actually parsed


# ---------------------------------------------------------------------------
# 4. Flask variant (:5000) — boot and serve a WSDL
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not _HAS_FLASK, reason="flask not installed (uv sync --group examples)")
def test_flask_serves_wsdl() -> None:
    with _serve("01_calculator/server_flask.py", 5000), urllib.request.urlopen(
        "http://127.0.0.1:5000/soap?wsdl", timeout=10
    ) as resp:
        assert resp.status == 200
        assert "definitions" in resp.read().decode()


# ---------------------------------------------------------------------------
# 5. WSDL access control (:8003) — 403 without auth, 200 with bearer token
# ---------------------------------------------------------------------------
@requires_server
def test_wsdl_access_control() -> None:
    url = "http://127.0.0.1:8003/soap?wsdl"
    with _serve("03_wsdl_access_control/server.py", 8003):
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            urllib.request.urlopen(url, timeout=10)
        assert excinfo.value.code == 403

        req = urllib.request.Request(url, headers={"Authorization": "Bearer s3cret"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == 200
            assert "definitions" in resp.read().decode()
