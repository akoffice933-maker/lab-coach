"""MCP stdio: Content-Length (Cursor/Claude) + NDJSON fallback."""
import io
import json
import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from lab_coach.mcp import read_mcp_message, write_mcp_message


def _lsp_frame(obj: dict) -> bytes:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


def test_read_write_lsp_roundtrip():
    msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"protocolVersion": "2024-11-05"}}
    buf = io.BytesIO()
    write_mcp_message(buf, msg, "lsp")
    raw = buf.getvalue()
    assert raw.startswith(b"Content-Length:")
    got, mode = read_mcp_message(io.BytesIO(raw))
    assert mode == "lsp"
    assert got["method"] == "initialize"
    assert got["id"] == 1


def test_read_ndjson_fallback():
    line = b'{"jsonrpc":"2.0","id":7,"method":"ping"}\n'
    got, mode = read_mcp_message(io.BytesIO(line))
    assert mode == "ndjson"
    assert got["method"] == "ping"


def test_content_length_line_is_not_skipped_as_bad_json():
    # Регрессия: старый serve_stdio делал json.loads(line) и молча ел заголовок.
    header = b"Content-Length: 2\r\n"
    got = None
    try:
        json.loads(header)
        parsed_as_json = True
    except ValueError:
        parsed_as_json = False
    assert not parsed_as_json
    body = _lsp_frame({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    got, mode = read_mcp_message(io.BytesIO(body))
    assert mode == "lsp" and got["method"] == "ping"


def test_mcp_lsp_initialize_subprocess():
    env = dict(os.environ)
    env["ADMIN_IDS"] = "1"
    env["MCP_TRANSPORT"] = "stdio"
    env["LAB_COACH_STATE"] = os.path.join(os.path.dirname(__file__), "_no_runtime_state.json")
    proc = subprocess.Popen(
        [sys.executable, "-m", "lab_coach.mcp"],
        cwd=ROOT, env=env,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "pytest", "version": "0"}},
    }
    try:
        proc.stdin.write(_lsp_frame(init))
        proc.stdin.flush()
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = proc.stdout.read(1)
            if not chunk:
                break
            header += chunk
            if len(header) > 4000:
                break
        assert b"Content-Length:" in header, header + proc.stderr.read()[:1000]
        n = int(header.split(b"Content-Length:")[1].split(b"\r\n")[0].strip())
        body = proc.stdout.read(n)
        msg = json.loads(body)
        assert msg["id"] == 1
        assert "result" in msg
        assert msg["result"]["serverInfo"]["name"] == "lab-coach"
        assert "tools" in msg["result"]["capabilities"]
        # tools/list
        listed = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        proc.stdin.write(_lsp_frame(listed))
        proc.stdin.flush()
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = proc.stdout.read(1)
            if not chunk:
                break
            header += chunk
            if len(header) > 4000:
                break
        n = int(header.split(b"Content-Length:")[1].split(b"\r\n")[0].strip())
        msg2 = json.loads(proc.stdout.read(n))
        names = {t["name"] for t in msg2["result"]["tools"]}
        assert "scan_lab_target" in names
        assert "next_action" in names
        assert "ingest_output" in names
        assert "run_exploit" not in names
    finally:
        proc.stdin.close()
        proc.kill()
        proc.wait(timeout=5)
