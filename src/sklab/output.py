from __future__ import annotations

import ctypes
import json
import os
import sys
import threading
from typing import Any, TextIO

from .util import redact


STYLES = {
    "bold": "1",
    "dim": "2",
    "italic": "3",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
}

PREFIX_STYLES = {"[+]": "green", "[-]": "red", "[!]": "yellow", "[*]": "blue"}


def _ansi(stream: TextIO) -> bool:
    """Whether escape sequences will render here rather than print as noise."""
    if "NO_COLOR" in os.environ:
        return False
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING: on in Windows Terminal, off by default in conhost.
        return bool(mode.value & 0x0004) or bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        return False


class Output:
    def __init__(self, mode: str = "text", *, color: bool = True, stream: TextIO | None = None):
        self.mode = mode
        self.stream = stream or sys.stdout
        self.color = color and mode == "text" and _ansi(self.stream)
        self._lock = threading.Lock()

    def paint(self, text: str, *styles: str) -> str:
        codes = [STYLES[style] for style in styles if style in STYLES]
        if not self.color or not codes:
            return text
        return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"

    def event(self, event: str, message: str = "", **fields: Any) -> None:
        record = redact({"event": event, "message": message, **fields})
        with self._lock:
            if self.mode == "jsonl":
                print(json.dumps(record, sort_keys=True), file=self.stream, flush=True)
                return
            prefix = {
                "ok": "[+]",
                "error": "[-]",
                "warning": "[!]",
                "phase": "[*]",
                "info": "[*]",
            }.get(event, "[*]")
            suffix = ""
            if fields:
                suffix = " " + " ".join(
                    f"{name}={redact(value, name)!s}" for name, value in fields.items()
                )
            line = f"{message}{suffix}".rstrip()
            print(f"{self.paint(prefix, PREFIX_STYLES[prefix])} {line}".rstrip(), file=self.stream, flush=True)

    def table(self, rows: list[dict[str, Any]], columns: tuple[str, ...]) -> None:
        if self.mode == "jsonl":
            for row in rows:
                self.event("row", **row)
            return
        with self._lock:
            widths = {name: len(name) for name in columns}
            for row in rows:
                for name in columns:
                    widths[name] = max(widths[name], len(str(row.get(name, ""))))
            print("  ".join(name.ljust(widths[name]) for name in columns), file=self.stream)
            print("  ".join("-" * widths[name] for name in columns), file=self.stream)
            for row in rows:
                print(
                    "  ".join(str(row.get(name, "")).ljust(widths[name]) for name in columns),
                    file=self.stream,
                )

