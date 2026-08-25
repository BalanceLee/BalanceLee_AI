#!/usr/bin/env python3
"""HexStrike AI unified Web application.

Production mode serves the built React application and Socket.IO from one
process/port. The browser never talks to the Kali tool server directly.
"""

from __future__ import annotations

import atexit
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict

import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parents[1]
FRONTEND_DIST = PROJECT_ROOT / "UI" / "frontend" / "dist"

# Make project modules and the backend-local wrapper importable regardless of cwd.
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from orchestrator_wrapper_v2 import OrchestratorWrapper

app = Flask(__name__, static_folder=None)
app.config["SECRET_KEY"] = os.environ.get("HEXSTRIKE_SECRET_KEY", "hexstrike-dev-secret-change-me")

# CORS remains configurable for Vite development mode. Production is same-origin.
allowed_origin = os.environ.get("HEXSTRIKE_WEB_ORIGIN", "*")
CORS(app, resources={r"/api/*": {"origins": allowed_origin}})
socketio = SocketIO(app, cors_allowed_origins=allowed_origin, async_mode="threading")

active_sessions: Dict[str, OrchestratorWrapper] = {}
session_threads: Dict[str, threading.Thread] = {}
_sessions_lock = threading.RLock()


def get_kali_server_url() -> str:
    return os.environ.get("HEXSTRIKE_SERVER_URL", "http://127.0.0.1:8888").rstrip("/")


def _check_kali(timeout: float = 5.0) -> Dict[str, Any]:
    url = get_kali_server_url()
    try:
        response = requests.get(f"{url}/health", timeout=timeout)
        response.raise_for_status()
        data = response.json()
        return {
            "status": "healthy",
            "url": url,
            "version": data.get("version"),
            "tools_available": data.get("total_tools_available"),
            "essential_tools": data.get("all_essential_tools_available"),
        }
    except Exception as exc:
        return {"status": "unavailable", "url": url, "error": str(exc)}


def _check_runtime() -> Dict[str, Any]:
    mcp_script = PROJECT_ROOT / "hexstrike_mcp.py"
    llm_key = bool(os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY"))
    return {
        "frontend": {
            "status": "ready" if (FRONTEND_DIST / "index.html").exists() else "not_built",
            "path": str(FRONTEND_DIST),
        },
        "mcp": {
            "status": "ready" if mcp_script.exists() else "missing",
            "script": str(mcp_script),
            "mode": "on_demand_stdio",
        },
        "llm": {
            "status": "configured" if llm_key else "not_configured",
            "model": os.environ.get("LLM_MODEL", "gpt-4.1-mini"),
            "base_url": os.environ.get("LLM_API_BASE_URL", "https://api.openai.com/v1/chat/completions"),
        },
    }


def _cleanup_sessions() -> None:
    with _sessions_lock:
        for wrapper in list(active_sessions.values()):
            wrapper.stop()
        active_sessions.clear()
        session_threads.clear()


atexit.register(_cleanup_sessions)


# ---------------------------------------------------------------------------
# API and health endpoints
# ---------------------------------------------------------------------------

@app.route("/api")
def api_index():
    return jsonify({"status": "HexStrike AI Web service running", "version": "2.0.0"})


@app.route("/api/health")
def health():
    with _sessions_lock:
        active = len(active_sessions)
        running = sum(1 for thread in session_threads.values() if thread.is_alive())
    return jsonify({"status": "healthy", "active_sessions": active, "running_tasks": running})


@app.route("/api/health/full")
def full_health():
    runtime = _check_runtime()
    runtime["web"] = {"status": "healthy", "active_sessions": len(active_sessions)}
    runtime["kali"] = _check_kali()
    all_ready = (
        runtime["frontend"]["status"] == "ready"
        and runtime["mcp"]["status"] == "ready"
        and runtime["kali"]["status"] == "healthy"
    )
    runtime["status"] = "healthy" if all_ready else "degraded"
    return jsonify(runtime), (200 if all_ready else 503)


@app.route("/api/user-question/respond", methods=["POST"])
def proxy_user_question_response():
    """Same-origin HTTP fallback for replying to a Kali ask_user request."""
    payload = request.get_json(silent=True) or {}
    return _forward_user_question(payload)


def _forward_user_question(payload: Dict[str, Any]):
    ask_id = payload.get("ask_id")
    response_payload = payload.get("response")
    if not ask_id or not response_payload:
        result = {"success": False, "error": "ask_id and response are required"}
        return jsonify(result), 400
    try:
        response = requests.post(
            f"{get_kali_server_url()}/api/tools/ask-user/respond",
            json={"ask_id": ask_id, "response": response_payload},
            timeout=10,
        )
        data = response.json()
        return jsonify(data), response.status_code
    except Exception as exc:
        return jsonify({"success": False, "error": f"Kali response proxy failed: {exc}"}), 502


# ---------------------------------------------------------------------------
# Socket.IO session handling
# ---------------------------------------------------------------------------

@socketio.on("connect")
def handle_connect():
    session_id = request.sid
    print(f"[WebSocket] 客户端连接: {session_id}")
    emit("connected", {"session_id": session_id})


@socketio.on("disconnect")
def handle_disconnect():
    session_id = request.sid
    print(f"[WebSocket] 客户端断开: {session_id}")
    with _sessions_lock:
        wrapper = active_sessions.pop(session_id, None)
        session_threads.pop(session_id, None)
    if wrapper:
        wrapper.stop()


@socketio.on("start_pentest")
def handle_start_pentest(data):
    session_id = request.sid
    target = (data or {}).get("target", "")
    message = (data or {}).get("message", "")
    print(f"[WebSocket] 收到测试请求: {target}")

    with _sessions_lock:
        existing_thread = session_threads.get(session_id)
        if existing_thread and existing_thread.is_alive():
            emit("error", {"message": "当前会话仍有任务运行，请等待完成或先停止任务"})
            return

        if session_id not in active_sessions:
            print(f"[会话] 创建新的会话: {session_id}")
            active_sessions[session_id] = OrchestratorWrapper(socketio, session_id)
        else:
            print(f"[会话] 复用会话: {session_id} (历史: {len(active_sessions[session_id].messages)}条)")
        wrapper = active_sessions[session_id]
        wrapper.should_stop_flag = False

        def run_in_background():
            try:
                wrapper.run_pentest(target, message)
            except Exception as exc:
                print(f"[错误] 渗透测试异常: {exc}")
                import traceback
                traceback.print_exc()
                socketio.emit("error", {"message": f"测试异常: {exc}"}, room=session_id)
            finally:
                with _sessions_lock:
                    current = session_threads.get(session_id)
                    if current is threading.current_thread():
                        session_threads.pop(session_id, None)

        thread = threading.Thread(target=run_in_background, daemon=True, name=f"hexstrike-{session_id[:8]}")
        session_threads[session_id] = thread
        thread.start()

    emit("test_started", {"session_id": session_id})


@socketio.on("user_choice")
def handle_user_choice(data):
    session_id = request.sid
    choice = (data or {}).get("choice", "continue")
    with _sessions_lock:
        wrapper = active_sessions.get(session_id)
    if wrapper:
        wrapper.handle_user_choice(choice)


@socketio.on("user_question_response")
def handle_user_question_response(data):
    """Proxy browser response through this Web service to Kali; browser never calls Kali directly."""
    payload = data or {}
    ask_id = payload.get("ask_id")
    response_payload = payload.get("response")
    if not ask_id or not response_payload:
        return {"success": False, "error": "ask_id and response are required"}
    try:
        response = requests.post(
            f"{get_kali_server_url()}/api/tools/ask-user/respond",
            json={"ask_id": ask_id, "response": response_payload},
            timeout=10,
        )
        try:
            result = response.json()
        except ValueError:
            result = {"success": False, "error": response.text[:500]}
        if response.status_code >= 400:
            result.setdefault("success", False)
        return result
    except Exception as exc:
        return {"success": False, "error": f"Kali response proxy failed: {exc}"}


@socketio.on("runtime_resume")
def handle_runtime_resume(data):
    session_id = request.sid
    after_seq = int((data or {}).get("after_seq", 0))
    with _sessions_lock:
        wrapper = active_sessions.get(session_id)
    if not wrapper:
        return {"success": True, "events": [], "last_seq": 0}
    events = wrapper.event_bus.replay(session_id, after_seq=after_seq, limit=500)
    return {"success": True, "events": events, "last_seq": wrapper.event_store.last_seq(session_id)}


@socketio.on("runtime_ack")
def handle_runtime_ack(data):
    # ACK is intentionally lightweight in v1.0. Durable compaction will use it later.
    return {"success": True, "last_seq": int((data or {}).get("last_seq", 0))}


@socketio.on("stop_pentest")
def handle_stop_pentest():
    session_id = request.sid
    with _sessions_lock:
        wrapper = active_sessions.pop(session_id, None)
        session_threads.pop(session_id, None)
    if wrapper:
        wrapper.stop()
    emit("test_stopped", {"message": "测试已停止"})


@socketio.on("clear_chat_history")
def handle_clear_chat_history():
    session_id = request.sid
    with _sessions_lock:
        wrapper = active_sessions.get(session_id)
    if wrapper:
        wrapper.clear_chat_history()
        emit("terminal_output", {"output": f"[{time.strftime('%H:%M:%S')}] 对话历史已清空\n", "stream": "stdout"})
        emit("chat_history_cleared", {"message": "对话历史已清空"})


@socketio.on("get_config")
def handle_get_config():
    session_id = request.sid
    with _sessions_lock:
        wrapper = active_sessions.get(session_id)
    if wrapper:
        config = wrapper.config
    else:
        config = {"enable_graphrag": True, "enable_phase_aware": True, "max_rounds": 50, "timeout": 300}
    emit("config_status", config)


# ---------------------------------------------------------------------------
# React static hosting / SPA fallback. API and Socket.IO routes take priority.
# ---------------------------------------------------------------------------

@app.route("/")
def frontend_index():
    index_path = FRONTEND_DIST / "index.html"
    if not index_path.exists():
        return jsonify({
            "status": "frontend_not_built",
            "message": "Run: python run.py --build-ui",
            "dist": str(FRONTEND_DIST),
        }), 503
    return send_from_directory(FRONTEND_DIST, "index.html")


@app.route("/<path:path>")
def frontend_assets(path: str):
    candidate = (FRONTEND_DIST / path).resolve()
    try:
        candidate.relative_to(FRONTEND_DIST.resolve())
    except ValueError:
        return jsonify({"error": "invalid path"}), 400
    if candidate.is_file():
        return send_from_directory(FRONTEND_DIST, path)
    if (FRONTEND_DIST / "index.html").exists():
        return send_from_directory(FRONTEND_DIST, "index.html")
    return jsonify({"status": "frontend_not_built"}), 503


def create_app():
    """Application factory used by tests and external runners."""
    return app, socketio


if __name__ == "__main__":
    host = os.environ.get("HEXSTRIKE_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("HEXSTRIKE_WEB_PORT", "5000"))
    print("=" * 70)
    print("HexStrike AI Unified Web App")
    print(f"Web:  http://{host}:{port}")
    print(f"Kali: {get_kali_server_url()}")
    print("=" * 70)
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
