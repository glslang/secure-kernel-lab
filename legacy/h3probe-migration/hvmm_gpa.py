"""Direct hvmm reads through a VID handle duplicated from vmwp.

No hvlib code is imported here. The caller supplies the vmwp PID and the
per-boot VID file handle captured at the profiled dispatcher entry. CR3 and
IDTR come from HvCallGetVpRegisters through h3probe; the Secure Kernel image
base is recovered by following live IDT handlers through that CR3.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import pathlib
import struct
from typing import Any

from guest_physical import (  # noqa: F401 -- the neutral half, re-exported for comparison callers
    GuestVirtual,
    disk_pe_identity,
    find_secure_kernel_base,
    idt_handlers,
    vtl1_identity,
)


PROCESS_DUP_HANDLE = 0x0040
DUPLICATE_SAME_ACCESS = 0x00000002
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
IOCTL_HVMM_READ_PHYSICAL = 0x2220C0
PAGE_SIZE = 0x1000
MASK_4K = 0x000F_FFFF_FFFF_F000
MASK_2M = 0x000F_FFFF_FFE0_0000
MASK_1G = 0x000F_FFFF_C000_0000
HV_X64_REGISTER_IDTR = 0x00070000


def _handle_value(handle: wintypes.HANDLE | None) -> int:
    if handle is None:
        return 0
    return ctypes.cast(handle, ctypes.c_void_p).value or 0


def _winerror(action: str) -> OSError:
    error = ctypes.get_last_error()
    return OSError(error, f"{action}: {ctypes.FormatError(error).strip()}")


class HvmmSource:
    """An uncached hvmm physical source bound to one duplicated vmwp VID handle.

    This object backs a live protocol transport, so two reads of one GPA must be
    allowed to observe two different page-table generations.  Snapshot-style
    caching belongs in a higher-level operation such as :class:`GuestVirtual`,
    never at this raw source boundary.
    """

    max_read = PAGE_SIZE

    def __init__(self, vmwp_pid: int, partition_handle: int) -> None:
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k32.OpenProcess.restype = wintypes.HANDLE
        self.k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.k32.GetCurrentProcess.restype = wintypes.HANDLE
        self.k32.GetCurrentProcess.argtypes = []
        self.k32.DuplicateHandle.restype = wintypes.BOOL
        self.k32.DuplicateHandle.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        self.k32.CreateFileW.restype = wintypes.HANDLE
        self.k32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self.k32.DeviceIoControl.restype = wintypes.BOOL
        self.k32.DeviceIoControl.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        self.k32.CloseHandle.restype = wintypes.BOOL
        self.k32.CloseHandle.argtypes = [wintypes.HANDLE]

        self.process: wintypes.HANDLE | None = None
        self.partition: wintypes.HANDLE | None = None
        self.device: wintypes.HANDLE | None = None
        try:
            self.process = self.k32.OpenProcess(PROCESS_DUP_HANDLE, False, vmwp_pid)
            if not self.process:
                raise _winerror(f"OpenProcess(PROCESS_DUP_HANDLE, pid={vmwp_pid})")
            duplicate = wintypes.HANDLE()
            if not self.k32.DuplicateHandle(
                self.process,
                wintypes.HANDLE(partition_handle),
                self.k32.GetCurrentProcess(),
                ctypes.byref(duplicate),
                0,
                False,
                DUPLICATE_SAME_ACCESS,
            ):
                raise _winerror(
                    f"DuplicateHandle(pid={vmwp_pid}, handle=0x{partition_handle:x})"
                )
            self.partition = duplicate
            self.device = self.k32.CreateFileW(
                r"\\.\hvmm",
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if _handle_value(self.device) == ctypes.c_void_p(-1).value:
                self.device = None
                raise _winerror(r"CreateFileW(\\.\hvmm)")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        for name in ("device", "partition", "process"):
            handle = getattr(self, name, None)
            if handle and _handle_value(handle):
                self.k32.CloseHandle(handle)
            setattr(self, name, None)

    def _page(self, page: int) -> tuple[bytes | None, str | None]:
        page &= ~(PAGE_SIZE - 1)
        if self.device is None or self.partition is None:
            return None, "ERROR hvmm source is closed"
        request_bytes = struct.pack(
            "<6Q", _handle_value(self.partition), 0, 0, 0, 0, page
        )
        request = (ctypes.c_ubyte * len(request_bytes)).from_buffer_copy(request_bytes)
        output = (ctypes.c_ubyte * PAGE_SIZE)()
        returned = wintypes.DWORD()
        ok = self.k32.DeviceIoControl(
            self.device,
            IOCTL_HVMM_READ_PHYSICAL,
            request,
            len(request_bytes),
            output,
            PAGE_SIZE,
            ctypes.byref(returned),
            None,
        )
        if not ok:
            error = ctypes.get_last_error()
            return None, f"ERROR hvmm DeviceIoControl failed: Win32 {error}"
        if returned.value == 0:
            return None, "NOTPRESENT"
        if returned.value != PAGE_SIZE:
            return None, f"ERROR hvmm returned {returned.value} bytes, expected {PAGE_SIZE}"
        return bytes(output), None

    def read(self, gpa: int, size: int) -> tuple[bytes | None, str | None]:
        if gpa < 0 or size < 0:
            return None, "ERROR negative GPA or size"
        result = bytearray()
        while size:
            page, failure = self._page(gpa)
            if page is None:
                return None, failure
            offset = gpa & (PAGE_SIZE - 1)
            take = min(size, PAGE_SIZE - offset)
            result += page[offset : offset + take]
            gpa += take
            size -= take
        return bytes(result), None
