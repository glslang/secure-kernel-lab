"""Service lifecycle for the operator-built h3probe driver.

The driver source and every device operation live in windbg-mcp. Sklab only starts, stops and
audits the service selected by its local configuration.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
from dataclasses import dataclass
import os
from pathlib import Path
import time

try:
    import winreg
except ImportError:  # pragma: no cover - the lab is Windows-only; keep imports testable elsewhere
    winreg = None  # type: ignore[assignment]


_STATES = {
    1: "stopped",
    2: "start_pending",
    3: "stop_pending",
    4: "running",
    5: "continue_pending",
    6: "pause_pending",
    7: "paused",
}

_SC_MANAGER_CONNECT = 0x0001
_SERVICE_QUERY_STATUS = 0x0004
_SERVICE_START = 0x0010
_SERVICE_STOP = 0x0020
_SERVICE_CONTROL_STOP = 0x00000001
_ERROR_SERVICE_ALREADY_RUNNING = 1056
_ERROR_SERVICE_DOES_NOT_EXIST = 1060
_ERROR_SERVICE_NOT_ACTIVE = 1062


class _ServiceStatus(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wt.DWORD),
        ("dwCurrentState", wt.DWORD),
        ("dwControlsAccepted", wt.DWORD),
        ("dwWin32ExitCode", wt.DWORD),
        ("dwServiceSpecificExitCode", wt.DWORD),
        ("dwCheckPoint", wt.DWORD),
        ("dwWaitHint", wt.DWORD),
    ]


@dataclass(frozen=True)
class DriverStatus:
    service: str
    state: str
    image: Path | None = None
    error: str | None = None

    @property
    def installed(self) -> bool:
        return self.state != "missing"

    @property
    def running(self) -> bool:
        return self.state == "running"


class DriverError(RuntimeError):
    pass


def _advapi() -> ctypes.WinDLL:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenSCManagerW.restype = ctypes.c_void_p
    advapi.OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
    advapi.OpenServiceW.restype = ctypes.c_void_p
    advapi.OpenServiceW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, wt.DWORD]
    advapi.QueryServiceStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ServiceStatus)]
    advapi.StartServiceW.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.c_void_p]
    advapi.ControlService.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(_ServiceStatus)]
    advapi.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    return advapi


def _image_path(service: str) -> Path | None:
    """The service's ImagePath, in the form a file system call can open."""
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{service}"
        ) as key:
            raw, _ = winreg.QueryValueEx(key, "ImagePath")
    except OSError:
        return None
    text = os.path.expandvars(str(raw))
    root = os.environ.get("SystemRoot", r"C:\Windows")
    if text.startswith("\\??\\"):
        text = text[4:]
    elif text.lower().startswith("\\systemroot\\"):
        text = root + text[len("\\SystemRoot"):]
    elif not Path(text).is_absolute():
        text = str(Path(root) / text)
    return Path(text)


def _open(advapi: ctypes.WinDLL, service: str, access: int) -> tuple[int, int]:
    manager = advapi.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not manager:
        raise DriverError(f"cannot open the service control manager: Win32 {ctypes.get_last_error()}")
    handle = advapi.OpenServiceW(manager, service, access)
    if not handle:
        error = ctypes.get_last_error()
        advapi.CloseServiceHandle(manager)
        if error == _ERROR_SERVICE_DOES_NOT_EXIST:
            raise FileNotFoundError(service)
        raise DriverError(f"cannot open service {service}: Win32 {error}")
    return manager, handle


def _state(advapi: ctypes.WinDLL, handle: int) -> str:
    status = _ServiceStatus()
    if not advapi.QueryServiceStatus(handle, ctypes.byref(status)):
        raise DriverError(f"QueryServiceStatus: Win32 {ctypes.get_last_error()}")
    return _STATES.get(status.dwCurrentState, f"state_{status.dwCurrentState}")


def status(service: str) -> DriverStatus:
    try:
        advapi = _advapi()
        manager, handle = _open(advapi, service, _SERVICE_QUERY_STATUS)
    except FileNotFoundError:
        return DriverStatus(service, "missing")
    except (AttributeError, OSError, DriverError) as error:
        return DriverStatus(service, "unknown", _image_path(service), str(error))
    try:
        return DriverStatus(service, _state(advapi, handle), _image_path(service))
    except DriverError as error:
        return DriverStatus(service, "unknown", _image_path(service), str(error))
    finally:
        advapi.CloseServiceHandle(handle)
        advapi.CloseServiceHandle(manager)


def _transition(service: str, *, start: bool, timeout: float) -> DriverStatus:
    advapi = _advapi()
    try:
        manager, handle = _open(advapi, service, _SERVICE_QUERY_STATUS | (_SERVICE_START if start else _SERVICE_STOP))
    except FileNotFoundError as error:
        raise DriverError(f"service {service} is not installed") from error
    want = "running" if start else "stopped"
    try:
        if start:
            if not advapi.StartServiceW(handle, 0, None):
                error = ctypes.get_last_error()
                if error != _ERROR_SERVICE_ALREADY_RUNNING:
                    raise DriverError(f"StartService {service}: Win32 {error}")
        else:
            scratch = _ServiceStatus()
            if not advapi.ControlService(handle, _SERVICE_CONTROL_STOP, ctypes.byref(scratch)):
                error = ctypes.get_last_error()
                if error != _ERROR_SERVICE_NOT_ACTIVE:
                    raise DriverError(f"ControlService(STOP) {service}: Win32 {error}")
        deadline = time.monotonic() + timeout
        state = _state(advapi, handle)
        while state != want and time.monotonic() < deadline:
            time.sleep(0.2)
            state = _state(advapi, handle)
        # Reported as it stands rather than raised: a stop held pending by an open handle is a
        # state the operator needs to see, not an exception to unwind past.
        return DriverStatus(service, state, _image_path(service))
    finally:
        advapi.CloseServiceHandle(handle)
        advapi.CloseServiceHandle(manager)


def start(service: str, timeout: float = 15) -> DriverStatus:
    return _transition(service, start=True, timeout=timeout)


def stop(service: str, timeout: float = 15) -> DriverStatus:
    return _transition(service, start=False, timeout=timeout)
