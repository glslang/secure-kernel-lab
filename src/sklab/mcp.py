from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
from typing import Any

from .errors import ExecutionFailure, RecoveryRequired


class McpClient:
    def __init__(
        self,
        executable: Path,
        *,
        cwd: Path,
        policy: Path,
        transcript: Path,
        extra_tools: str = "all",
    ) -> None:
        environment = os.environ.copy()
        environment.update(
            {
                "WINDBG_MCP_SK_LIVE_POLICY": str(policy),
                "WINDBG_MCP_TRANSCRIPT": str(transcript),
                "WINDBG_MCP_TRANSCRIPT_MAX_FIELD": "0",
            }
        )
        self.process = subprocess.Popen(
            [str(executable), "--tools", extra_tools],
            cwd=cwd,
            env=environment,
            text=True,
            encoding="utf-8",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
        )
        self._messages: queue.Queue[dict[str, Any]] = queue.Queue()
        self._pending: list[dict[str, Any]] = []
        self._errors: list[str] = []
        self._next_id = 1
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    @property
    def stderr(self) -> str:
        return "".join(self._errors)

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            try:
                self._messages.put(json.loads(line))
            except (TypeError, ValueError) as error:
                self._messages.put({"reader_error": f"{error}: {line!r}"})

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self._errors.append(line)

    def _send(self, value: dict[str, Any]) -> None:
        if self.process.stdin is None:
            raise ExecutionFailure("MCP server input is closed")
        self.process.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for index, message in enumerate(self._pending):
                if message.get("id") == request_id:
                    return self._pending.pop(index)
            if self.process.poll() is not None and self._messages.empty():
                raise ExecutionFailure(
                    f"MCP server exited {self.process.returncode}: {self.stderr[-4000:]}"
                )
            try:
                message = self._messages.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if message.get("id") == request_id:
                return message
            self._pending.append(message)
        raise ExecutionFailure(f"MCP {method} exceeded {timeout:.1f}s")

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def initialize(self) -> dict[str, Any]:
        response = self.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "secure-kernel-lab", "version": "1"},
            },
            15,
        )
        if response.get("error") is not None:
            raise ExecutionFailure(f"MCP initialize failed: {response['error']}")
        self.notify("notifications/initialized", {})
        return response["result"]

    def tool_result(self, name: str, arguments: dict[str, Any], timeout: float = 60) -> dict[str, Any]:
        response = self.request(
            "tools/call", {"name": name, "arguments": arguments}, timeout
        )
        if response.get("error") is not None:
            raise ExecutionFailure(f"{name} JSON-RPC failure: {response['error']}")
        result = response.get("result", {})
        if result.get("isError"):
            structured = result.get("structuredContent", {})
            error = structured.get("error", {}) if isinstance(structured, dict) else {}
            message = error.get("message") or json.dumps(result, sort_keys=True)
            if error.get("category") == "recovery_required" or "recovery_required" in message:
                raise RecoveryRequired(f"{name}: {message}")
            raise ExecutionFailure(f"{name}: {message}")
        return result

    def tool(self, name: str, arguments: dict[str, Any], timeout: float = 60) -> dict[str, Any]:
        result = self.tool_result(name, arguments, timeout)
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            raise ExecutionFailure(f"{name} returned no structured result: {result}")
        if structured.get("status") == "error":
            error = structured.get("error", {})
            message = error.get("message") or json.dumps(structured, sort_keys=True)
            if error.get("category") == "recovery_required" or "recovery_required" in message:
                raise RecoveryRequired(f"{name}: {message}")
            raise ExecutionFailure(f"{name}: {message}")
        return structured

    def tool_text(self, name: str, arguments: dict[str, Any], timeout: float = 60) -> str:
        result = self.tool_result(name, arguments, timeout)
        content = result.get("content", [])
        text = "\n".join(
            str(row.get("text", ""))
            for row in content
            if isinstance(row, dict) and row.get("type") == "text"
        )
        if not text:
            raise ExecutionFailure(f"{name} returned no text result: {result}")
        return text

    def session(self, session_id: str) -> dict[str, Any] | None:
        status = self.tool("session_status", {"session_id": session_id}, 30)
        return next(
            (row for row in status.get("sessions", []) if row.get("session_id") == session_id),
            None,
        )

    def end_session(self, session_id: str, timeout: float = 90) -> dict[str, Any]:
        return self.tool("end_session", {"session_id": session_id}, timeout)

    def close(self, *, terminate: bool = False, timeout: float = 120) -> None:
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
            self.process.stdin = None
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if not terminate:
                return
            self.process.kill()
            self.process.wait(timeout=10)

    def __enter__(self) -> "McpClient":
        return self

    def __exit__(self, _kind: object, _error: object, _traceback: object) -> None:
        self.close()

