#!/usr/bin/env python3
"""Integration smoke test for the unified Web application.

Starts a local mock Kali HTTP API and verifies:
- Flask serves the React build from /
- basic and aggregate health endpoints
- same-origin user-question proxy
- Socket.IO connection and user-question response proxy

No security tool or external target is contacted.
"""

from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOCK_PORT = 18888
os.environ["HEXSTRIKE_SERVER_URL"] = f"http://127.0.0.1:{MOCK_PORT}"
sys.path.insert(0, str(ROOT / "UI" / "backend"))
sys.path.insert(0, str(ROOT))


class MockKali(BaseHTTPRequestHandler):
    def _json(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(b'{"status":"healthy","version":"test","total_tools_available":6,"all_essential_tools_available":true}')
        else:
            self._json(b'{"error":"not found"}', 404)

    def do_POST(self):
        if self.path == "/api/tools/ask-user/respond":
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self._json(b'{"success":true}')
        else:
            self._json(b'{"error":"not found"}', 404)

    def log_message(self, *_args):
        pass


def main() -> int:
    mock = ThreadingHTTPServer(("127.0.0.1", MOCK_PORT), MockKali)
    threading.Thread(target=mock.serve_forever, daemon=True).start()

    try:
        import app as unified

        client = unified.app.test_client()
        response = client.get("/")
        assert response.status_code == 200
        assert b'<div id="root"></div>' in response.data

        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json["status"] == "healthy"

        response = client.get("/api/health/full")
        assert response.status_code == 200, response.json
        assert response.json["frontend"]["status"] == "ready"
        assert response.json["mcp"]["status"] == "ready"
        assert response.json["kali"]["status"] == "healthy"

        payload = {"ask_id": "ask_test", "response": {"text": "continue", "choice": "continue"}}
        response = client.post("/api/user-question/respond", json=payload)
        assert response.status_code == 200
        assert response.json["success"] is True

        socket_client = unified.socketio.test_client(unified.app)
        assert socket_client.is_connected()
        assert any(item["name"] == "connected" for item in socket_client.get_received())
        ack = socket_client.emit("user_question_response", payload, callback=True)
        assert ack and ack.get("success") is True
        resume = socket_client.emit("runtime_resume", {"after_seq": 0}, callback=True)
        assert resume and resume.get("success") is True
        ack_result = socket_client.emit("runtime_ack", {"last_seq": 0}, callback=True)
        assert ack_result and ack_result.get("success") is True
        socket_client.disconnect()
    finally:
        mock.shutdown()

    print("UNIFIED_WEB_INTEGRATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
