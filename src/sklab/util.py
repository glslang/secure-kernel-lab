from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Iterator


SECRET_NAMES = re.compile(r"(?:key|token|password|secret|credential)", re.IGNORECASE)
KD_KEY = re.compile(r"(?i)(key=)[^,\s]+")


def module_loaded(name: str) -> bool:
    """Whether a DLL is already mapped in this process, without loading it.

    The runs ask it of ``hvlib.dll``: nothing in sklab loads hvlib, and a run records that it did not.
    """
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    return bool(kernel32.GetModuleHandleW(name))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def pe_identity(header: bytes) -> dict[str, int] | None:
    """Machine, TimeDateStamp and SizeOfImage from the first page of a PE image, or None if not one."""
    if len(header) < 0x40 or header[:2] != b"MZ":
        return None
    offset = int.from_bytes(header[0x3C:0x40], "little")
    # Signature (4) + COFF header (20), then SizeOfImage at the same optional-header offset, 56,
    # in PE32 and PE32+ alike.
    if offset + 24 + 60 > len(header) or header[offset : offset + 4] != b"PE\0\0":
        return None
    return {
        "machine": int.from_bytes(header[offset + 4 : offset + 6], "little"),
        "timestamp": int.from_bytes(header[offset + 8 : offset + 12], "little"),
        "size_of_image": int.from_bytes(header[offset + 24 + 56 : offset + 24 + 60], "little"),
    }


def redact(value: Any, name: str = "") -> Any:
    if SECRET_NAMES.search(name):
        return "<redacted>"
    if isinstance(value, str):
        return KD_KEY.sub(r"\1<redacted>", value)
    if isinstance(value, dict):
        return {str(key): redact(item, str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(redact(value), indent=2, sort_keys=True) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def command_line(parts: list[str]) -> str:
    return subprocess.list2cmdline(parts)


def powershell_command(parts: list[str]) -> str:
    """Render an argv as a PowerShell invocation, including paths containing spaces."""
    if not parts:
        raise ValueError("a PowerShell command requires an executable")
    quoted = ["'" + part.replace("'", "''") + "'" for part in parts]
    return "& " + " ".join(quoted)


def parse_scalar(text: str) -> Any:
    lowered = text.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"none", "null"}:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return text


@contextmanager
def temporary_environment(values: dict[str, str | None]) -> Iterator[None]:
    before = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in before.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

