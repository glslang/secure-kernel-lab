"""Guest-physical reads and writes straight through LiveCloudKd's `hvmm` driver.

hvlib reads a page with one `DeviceIoControl` to hvmm, but first decides whether to ask at all, from
a bound it fixes when it opens the partition (`modules/core.py:_hvlib_view`). With VP 0 in VTL1 at
that moment the bound is 4 GiB, and K3's last 128 MiB of RAM lies above it. hvmm itself reads there,
so this sends hvmm the request hvlib sends, and nothing decides in between.

The request is read from the installed driver, not from LiveCloudKd's public source, because the two
differ: the public `hvmm.h` gives function 0x830 a 32-byte `GPA_INFO`, while the installed build
(`hvmm.sys`, SHA-256 `be704692...ee461c29`, the re-signed `.orig`) serves the 80-byte request traced
from hvlib on 2026-10-17 at code 0x2220C0, in its routine at RVA 0x1F00:

- `+0x00` a handle to the VM's partition object, valid in the **calling process**: the driver passes
  it to `ObReferenceObjectByHandle` in the caller's context. hvlib opens it when it opens the
  partition and reports it as `InfoPartitionHandle`. This module opens none of its own.
- `+0x28` the guest-physical address, which the driver shifts right by 12: a read starts at the page.
- The length is the output buffer's. `+0x30` carries it too, as hvlib sends it, and is not read.
- `+0x08` (hvlib sends the partition ID) and `+0x10` are copied but used nowhere on the read path.

The driver accepts only a full Windows VM (its partition type `0x2000014`). It answers success with no
bytes when it cannot use the handle or the partition type, or when a copy inside one memory block
fails, so a page counts only when the driver hands back all of it.

Writes use the installed driver's function 0x835 (`0x2220D4`). Its buffered request is the same
80-byte header followed by the bytes to write: `+0x28` is the exact GPA and `+0x30` is the byte
count. One request must be non-empty and remain within one 4 KiB page. `Writer` splits a larger
write at page boundaries and treats the driver's one-byte response as the completion sentinel.

**A GPA with no RAM behind it is not one of those failures: it reads as a page of zeros.** The routine
at RVA `0x186C` zeroes nothing itself, but when the page is in no memory block it runs the copy,
discards the copy's result and returns success (`0x192D`), over a buffer the handler had zeroed.
Measured on K3 2026-10-17: the device gap (`0xF8000000`, `0xFC000000`), the pages just past RAM
(`0x108000000`, `0x108001000`) and `0x200000000` all came back as 4096 zero bytes, while
`HvCallReadGpa` answered `Unmapped` for the three past RAM. So an all-zero page from this reader is
either a page of zeros or no page at all. Given the guest's own RAM runs, `Reader` refuses zeros
outside them, which is right for the device gap and the end of RAM but not for every page there;
given the hypervisor's word as well (`sklab.backing`), it serves the zeros the hypervisor calls memory.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
from typing import Any


DEVICE = r"\\.\hvmm"
READ_MEMORY = 0x2220C0  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
WRITE_MEMORY = 0x2220D4  # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x835, METHOD_BUFFERED, FILE_ANY_ACCESS)
REQUEST_SIZE = 0x50
PAGE = 0x1000
_GENERIC_READ_WRITE, _OPEN_EXISTING = 0xC0000000, 3
PROCESS_DUP_HANDLE = 0x0040
DUPLICATE_SAME_ACCESS = 0x00000002


def _handle_value(handle: wt.HANDLE | None) -> int:
    if handle is None:
        return 0
    return ctypes.cast(handle, ctypes.c_void_p).value or 0


def _winerror(action: str) -> OSError:
    error = ctypes.get_last_error()
    return OSError(error, f"{action}: {ctypes.FormatError(error).strip()}")


def module_loaded(name: str) -> bool:
    """Whether a DLL is already mapped in this process, without loading it."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    return bool(kernel32.GetModuleHandleW(name))


class DuplicatedHandle:
    """A vmwp VID handle duplicated into the current process for hvmm."""

    def __init__(self, vmwp_pid: int, source_handle: int) -> None:
        if vmwp_pid <= 0 or source_handle <= 0:
            raise ValueError("vmwp PID and partition handle must both be nonzero")
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k32.OpenProcess.restype = wt.HANDLE
        self.k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        self.k32.GetCurrentProcess.restype = wt.HANDLE
        self.k32.GetCurrentProcess.argtypes = []
        self.k32.DuplicateHandle.restype = wt.BOOL
        self.k32.DuplicateHandle.argtypes = [
            wt.HANDLE,
            wt.HANDLE,
            wt.HANDLE,
            ctypes.POINTER(wt.HANDLE),
            wt.DWORD,
            wt.BOOL,
            wt.DWORD,
        ]
        self.k32.CloseHandle.restype = wt.BOOL
        self.k32.CloseHandle.argtypes = [wt.HANDLE]
        self.process: wt.HANDLE | None = None
        self.handle: wt.HANDLE | None = None
        try:
            self.process = self.k32.OpenProcess(PROCESS_DUP_HANDLE, False, vmwp_pid)
            if not self.process:
                raise _winerror(f"OpenProcess(PROCESS_DUP_HANDLE, pid={vmwp_pid})")
            duplicate = wt.HANDLE()
            if not self.k32.DuplicateHandle(
                self.process,
                wt.HANDLE(source_handle),
                self.k32.GetCurrentProcess(),
                ctypes.byref(duplicate),
                0,
                False,
                DUPLICATE_SAME_ACCESS,
            ):
                raise _winerror(
                    f"DuplicateHandle(pid={vmwp_pid}, handle=0x{source_handle:x})"
                )
            self.handle = duplicate
        except BaseException:
            self.close()
            raise

    @property
    def value(self) -> int:
        return _handle_value(self.handle)

    def close(self) -> None:
        for name in ("handle", "process"):
            handle = getattr(self, name, None)
            if handle and _handle_value(handle):
                self.k32.CloseHandle(handle)
            setattr(self, name, None)


def request(partition_handle: int, partition_id: int, gpa: int) -> bytes:
    """One page's input, laid out as hvlib sends it."""
    block = bytearray(REQUEST_SIZE)
    struct.pack_into("<Q", block, 0x00, partition_handle)
    struct.pack_into("<Q", block, 0x08, partition_id)
    struct.pack_into("<Q", block, 0x28, gpa & ~(PAGE - 1))
    struct.pack_into("<Q", block, 0x30, PAGE)
    return bytes(block)


def write_request(partition_handle: int, partition_id: int, gpa: int, data: bytes) -> bytes:
    """One in-page write request, laid out as the installed hvmm driver consumes it."""
    if not partition_handle:
        raise ValueError("hvmm writes through a partition handle, and none was given")
    if gpa < 0:
        raise ValueError("hvmm write GPA cannot be negative")
    if not data:
        raise ValueError("hvmm write cannot be empty")
    if len(data) > PAGE or (gpa & (PAGE - 1)) + len(data) > PAGE:
        raise ValueError("one hvmm write request must remain within one 4 KiB page")
    block = bytearray(REQUEST_SIZE)
    struct.pack_into("<Q", block, 0x00, partition_handle)
    struct.pack_into("<Q", block, 0x08, partition_id)
    struct.pack_into("<Q", block, 0x28, gpa)
    struct.pack_into("<Q", block, 0x30, len(data))
    return bytes(block) + data


class Device:
    """`\\\\.\\hvmm`, opened by this process."""

    def __init__(self) -> None:
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k32.CreateFileW.restype = ctypes.c_void_p
        self.k32.DeviceIoControl.argtypes = [
            ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD,
            ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p,
        ]
        self.k32.DeviceIoControl.restype = wt.BOOL
        self.k32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.handle = self.k32.CreateFileW(DEVICE, _GENERIC_READ_WRITE, 0, None, _OPEN_EXISTING, 0, None)
        if not self.handle or self.handle == ctypes.c_void_p(-1).value:
            raise OSError(f"cannot open {DEVICE}: Win32 {ctypes.get_last_error()}")

    def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
        """What the driver wrote, cut to the length it reported. Raises OSError when the call fails."""
        out = ctypes.create_string_buffer(b"\xAA" * out_size, out_size)
        returned = wt.DWORD()
        ok = self.k32.DeviceIoControl(
            ctypes.c_void_p(self.handle), code, payload, len(payload), out, out_size, ctypes.byref(returned), None
        )
        if not ok:
            raise OSError(f"DeviceIoControl 0x{code:X}: Win32 {ctypes.get_last_error()}")
        return out.raw[: returned.value]

    def write(self, partition_handle: int, partition_id: int, gpa: int, data: bytes) -> None:
        """Submit one in-page write and require the installed driver's completion byte."""
        answer = self.ioctl(
            WRITE_MEMORY,
            write_request(partition_handle, partition_id, gpa, data),
            1,
        )
        if len(answer) != 1:
            raise OSError(f"hvmm write returned {len(answer)} of 1 completion bytes")

    def close(self) -> None:
        if self.handle:
            self.k32.CloseHandle(ctypes.c_void_p(self.handle))
            self.handle = None


ZERO_PAGE = bytes(PAGE)


class Reader:
    """Guest-physical reads through hvmm, in the `(data, failure)` shape the page walkers take.

    A failure is one of two things, and `failed_calls` tells them apart: the driver answered without
    the page, or the call to the driver failed. Only the second counts there.

    With `ram` set to the guest's own RAM runs (`sklab.guest_ram`), a page of zeros at a GPA outside
    them is a failure too, its GPA among the first few kept in `refused`. That is right for the device
    gap and past the end of RAM, and wrong for a zero page of memory NT does not own, which K3 has
    below the gap. With `backing` as well (`sklab.backing`), the hypervisor is asked about each such
    page, and one it says is memory is returned as the zeros it is, counted in `outside_zero_backed`.
    Its answer for every page asked about, among the first few, is kept in `answers`. A page outside
    the runs that comes back with data is returned, counted in `outside_with_data` and its GPA among
    the first few kept in `contradictions`.
    """

    def __init__(
        self, device: Any, partition_handle: int, partition_id: int, ram: Any = None, backing: Any = None
    ) -> None:
        if not partition_handle:
            raise ValueError("hvmm reads through a partition handle, and none was given")
        self.device = device
        self.partition_handle = partition_handle
        self.partition_id = partition_id
        self.ram = ram
        self.backing = backing
        self.calls = 0
        self.failed_calls = 0
        self.outside_zero = 0
        self.refused: list[int] = []  # the first few GPAs `outside_zero` counts
        self.outside_zero_backed = 0
        self.answers: dict[int, str] = {}
        self.outside_with_data = 0
        self.contradictions: list[int] = []

    def page(self, gpa: int) -> tuple[bytes | None, str | None]:
        self.calls += 1
        try:
            data = self.device.ioctl(READ_MEMORY, request(self.partition_handle, self.partition_id, gpa), PAGE)
        except OSError as error:
            self.failed_calls += 1
            return None, f"hvmm: {error}"
        if len(data) != PAGE:
            return None, f"hvmm returned {len(data)} of {PAGE} bytes"
        if self.ram is not None and (gpa & ~(PAGE - 1)) not in self.ram:
            if data == ZERO_PAGE:
                page = gpa & ~(PAGE - 1)
                backed, answer = self.backing.ask(page) if self.backing is not None else (None, "not asked")
                if self.backing is not None and len(self.answers) < 16:
                    self.answers[page] = answer
                if backed:
                    self.outside_zero_backed += 1
                    return data, None
                self.outside_zero += 1
                if len(self.refused) < 16:
                    self.refused.append(page)
                return None, f"no RAM here by the guest's own map; hvmm answered with zeros, the hypervisor: {answer}"
            self.outside_with_data += 1
            if len(self.contradictions) < 16:
                self.contradictions.append(gpa & ~(PAGE - 1))
        return data, None

    def read(self, gpa: int, size: int) -> tuple[bytes | None, str | None]:
        out = bytearray()
        while len(out) < size:
            start = gpa & (PAGE - 1)
            data, failure = self.page(gpa)
            if failure is not None or data is None:
                return None, failure
            take = min(PAGE - start, size - len(out))
            out += data[start : start + take]
            gpa += take
        return bytes(out), None


class Writer:
    """Guest-physical writes through hvmm, split into the driver's in-page requests."""

    def __init__(self, device: Any, partition_handle: int, partition_id: int) -> None:
        if not partition_handle:
            raise ValueError("hvmm writes through a partition handle, and none was given")
        self.device = device
        self.partition_handle = partition_handle
        self.partition_id = partition_id
        self.calls = 0
        self.failed_calls = 0

    def write(self, gpa: int, data: bytes) -> tuple[int, str | None]:
        if gpa < 0:
            return 0, "hvmm write GPA cannot be negative"
        if not data:
            return 0, None
        written = 0
        while written < len(data):
            address = gpa + written
            take = min(PAGE - (address & (PAGE - 1)), len(data) - written)
            self.calls += 1
            try:
                if hasattr(self.device, "write"):
                    self.device.write(
                        self.partition_handle,
                        self.partition_id,
                        address,
                        data[written : written + take],
                    )
                else:
                    answer = self.device.ioctl(
                        WRITE_MEMORY,
                        write_request(
                            self.partition_handle,
                            self.partition_id,
                            address,
                            data[written : written + take],
                        ),
                        1,
                    )
                    if len(answer) != 1:
                        raise OSError(
                            f"hvmm write returned {len(answer)} of 1 completion bytes"
                        )
            except OSError as error:
                self.failed_calls += 1
                return written, f"hvmm: {error}"
            written += take
        return written, None
