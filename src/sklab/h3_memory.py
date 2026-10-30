"""Guest-physical reads and writes through h3probe's exact-build VID memory operation.

This is sklab's guest-physical provider; it replaced LiveCloudKd's ``hvmm.sys`` in the h3probe-only
migration (``docs/h3probe-only-plan.md``). h3probe attaches to the named ``vmwp``, proves the
partition handle there is its
own, checks the caller's partition ID against the handle's, and then sends the page request
``vid.dll!VidReadMemoryBlockPageRange`` sends, through vmwp's own handle. The derivation and the
Phase 1 measurement it rests on are in ``drivers/h3probe/h3probe.c`` and the plan.

Three things it does that the retired hvmm reader could not:

- **Absence is typed.** VID is asked which range holds the page before anything is read, so a page
  of zeros that is RAM comes back as data and a page with no RAM behind it comes back as
  ``not-present`` (no range) or ``refused`` (a range that is not memory-block RAM, such as the local
  APIC). hvmm answered both with zeros.
- **Identity is checked by the driver**, and a mismatch is ``identity``, never a GPA result: the VID
  build, the process, the handle, the handle's owner, and the partition ID.
- **No handle is duplicated.** The handle value is used inside vmwp, where VID's own gate accepts it.

A request is one byte range inside one guest page; larger reads are split here. A write is applied
by the driver as read, patch, write and full-page read-back, so a write answer of ``ok`` means the
page as read back holds exactly the bytes asked for. VID moves whole pages, so a guest store to the
same page between the driver's read and write would be lost: writers hold the guest paused.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
from dataclasses import dataclass
import struct
from typing import Any


DEVICE = r"\\.\H3Probe"
IOCTL_H3_MEMREAD = (0x22 << 16) | (0x812 << 2)
IOCTL_H3_MEMWRITE = (0x22 << 16) | (0x813 << 2)
VERSION = 1
PAGE = 0x1000

# H3_MEM_REQUEST: Version, OwnerPid, PartitionHandle, PartitionId, Gpa, Length, Reserved.
REQUEST = struct.Struct("<IIQQQII")
# H3_MEM_ANSWER: Version, Result, Stage, Status, Length, Reserved, Gpn.
ANSWER = struct.Struct("<6IQ")
READ_OUTPUT_SIZE = ANSWER.size + PAGE

RESULTS = {0: "ok", 1: "not-present", 2: "refused", 3: "error", 4: "identity"}
STAGES = {
    0: "none",
    1: "request",
    2: "build",
    3: "process",
    4: "handle",
    5: "owner",
    6: "partition",
    7: "scratch",
    8: "translate",
    9: "block",
    10: "read",
    11: "write",
    12: "verify",
    13: "recheck",
}


@dataclass(frozen=True)
class Answer:
    result: str
    stage: str
    status: int
    length: int
    gpn: int

    @property
    def ok(self) -> bool:
        return self.result == "ok"

    def failure(self) -> str:
        return (
            f"h3 memory: {self.result} at {self.stage} "
            f"(status 0x{self.status:08x}) for page 0x{self.gpn << 12:x}"
        )


def request(owner_pid: int, partition_handle: int, partition_id: int, gpa: int, length: int) -> bytes:
    """One request, refused here before the driver if it could not be valid there."""
    if owner_pid <= 0 or owner_pid > 0xFFFFFFFF:
        raise ValueError("the vmwp PID must be a nonzero 32-bit value")
    if partition_handle <= 0 or partition_handle > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("the partition handle must be a nonzero 64-bit value")
    if partition_id < 0 or partition_id > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("the partition ID must fit in an unsigned 64-bit value")
    if gpa < 0 or gpa > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("the GPA must fit in an unsigned 64-bit value")
    if length < 1 or length > PAGE - (gpa & (PAGE - 1)):
        raise ValueError("one request must be non-empty and remain within one 4 KiB page")
    return REQUEST.pack(VERSION, owner_pid, partition_handle, partition_id, gpa, length, 0)


def parse_answer(raw: bytes, asked: int) -> Answer:
    """The driver's answer, refused unless it is complete, known and self-consistent."""
    if len(raw) < ANSWER.size:
        raise OSError(f"h3probe memory answer is {len(raw)} of {ANSWER.size} bytes")
    version, result, stage, status, length, _reserved, gpn = ANSWER.unpack_from(raw, 0)
    if version != VERSION:
        raise OSError(f"h3probe memory answered ABI version {version}; this client speaks {VERSION}")
    if result not in RESULTS or stage not in STAGES:
        raise OSError(f"h3probe memory answered unknown result {result} at stage {stage}")
    answer = Answer(RESULTS[result], STAGES[stage], status, length, gpn)
    if answer.ok and (length != asked or stage != 0 or status != 0):
        raise OSError(f"h3probe memory answered ok with {length} of {asked} bytes at stage {stage}")
    if not answer.ok and length != 0:
        raise OSError(f"h3probe memory answered {answer.result} with {length} bytes")
    return answer


def capability(device: Any) -> tuple[bool, str]:
    """Whether the loaded driver serves this ABI, asked without naming any target.

    An empty request needs no identity and must come back ``error`` at ``request``, stamped with this
    client's version. A driver without the operation fails the call instead, so an opening device
    alone is not taken to mean the memory operation is there.
    """
    try:
        raw = device.ioctl(IOCTL_H3_MEMREAD, REQUEST.pack(VERSION, 0, 0, 0, 0, 0, 0), READ_OUTPUT_SIZE)
        answer = parse_answer(raw, 0)
    except (OSError, RuntimeError) as error:
        return False, f"memory operation ABI {VERSION} is not served: {error}"
    if (answer.result, answer.stage) != ("error", "request"):
        return False, f"an empty request answered {answer.result} at {answer.stage}, not error at request"
    return True, f"memory operation ABI {VERSION}"


class Device:
    """``\\\\.\\H3Probe``, opened by this process."""

    def __init__(self) -> None:
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k32.CreateFileW.restype = ctypes.c_void_p
        self.k32.DeviceIoControl.argtypes = [
            ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD,
            ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p,
        ]
        self.k32.DeviceIoControl.restype = wt.BOOL
        self.k32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.handle = self.k32.CreateFileW(DEVICE, 0xC0000000, 0, None, 3, 0, None)
        if not self.handle or self.handle == ctypes.c_void_p(-1).value:
            raise OSError(f"cannot open {DEVICE}: Win32 {ctypes.get_last_error()}")

    def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
        if self.handle is None:
            raise OSError(f"{DEVICE} is closed")
        out = ctypes.create_string_buffer(b"\xAA" * out_size, out_size)
        returned = wt.DWORD()
        ok = self.k32.DeviceIoControl(
            ctypes.c_void_p(self.handle), code, payload, len(payload), out, out_size,
            ctypes.byref(returned), None,
        )
        if not ok:
            raise OSError(f"DeviceIoControl 0x{code:X}: Win32 {ctypes.get_last_error()}")
        return out.raw[: returned.value]

    def close(self) -> None:
        if self.handle:
            self.k32.CloseHandle(ctypes.c_void_p(self.handle))
            self.handle = None


def read(
    device: Any, owner_pid: int, partition_handle: int, partition_id: int, gpa: int, length: int
) -> tuple[Answer, bytes]:
    raw = device.ioctl(
        IOCTL_H3_MEMREAD,
        request(owner_pid, partition_handle, partition_id, gpa, length),
        READ_OUTPUT_SIZE,
    )
    if len(raw) != READ_OUTPUT_SIZE:
        raise OSError(f"h3probe memory read returned {len(raw)} of {READ_OUTPUT_SIZE} bytes")
    answer = parse_answer(raw, length)
    data = raw[ANSWER.size : ANSWER.size + answer.length]
    return answer, data


def write(
    device: Any, owner_pid: int, partition_handle: int, partition_id: int, gpa: int, data: bytes
) -> Answer:
    raw = device.ioctl(
        IOCTL_H3_MEMWRITE,
        request(owner_pid, partition_handle, partition_id, gpa, len(data)) + bytes(data),
        ANSWER.size,
    )
    if len(raw) != ANSWER.size:
        raise OSError(f"h3probe memory write returned {len(raw)} of {ANSWER.size} bytes")
    return parse_answer(raw, len(data))


class Reader:
    """Guest-physical reads in the ``(data, failure)`` shape the page walkers take.

    ``failed_calls`` counts calls to the driver that failed; ``results`` counts every typed answer,
    so a run can say how many pages were absent as distinct from how many reads broke.
    """

    def __init__(self, device: Any, owner_pid: int, partition_handle: int, partition_id: int) -> None:
        if owner_pid <= 0 or partition_handle <= 0:
            raise ValueError("h3 memory reads through vmwp's PID and partition handle, and one was not given")
        self.device = device
        self.owner_pid = owner_pid
        self.partition_handle = partition_handle
        self.partition_id = partition_id
        self.calls = 0
        self.failed_calls = 0
        self.results: dict[str, int] = {}
        self.last: Answer | None = None

    def chunk(self, gpa: int, size: int) -> tuple[bytes | None, Answer | None, str | None]:
        """One in-page read: the bytes, the typed answer, or why there is no answer."""
        self.calls += 1
        try:
            answer, data = read(self.device, self.owner_pid, self.partition_handle, self.partition_id, gpa, size)
        except (OSError, RuntimeError) as error:
            self.failed_calls += 1
            return None, None, f"h3 memory: {error}"
        self.last = answer
        self.results[answer.result] = self.results.get(answer.result, 0) + 1
        if not answer.ok:
            return None, answer, answer.failure()
        return data, answer, None

    def read(self, gpa: int, size: int) -> tuple[bytes | None, str | None]:
        if gpa < 0 or size < 0:
            return None, "h3 memory: negative GPA or size"
        out = bytearray()
        while len(out) < size:
            take = min(PAGE - (gpa & (PAGE - 1)), size - len(out))
            data, _answer, failure = self.chunk(gpa, take)
            if data is None:
                return None, failure
            out += data
            gpa += take
        return bytes(out), None


class Writer:
    """Guest-physical writes split into the driver's in-page requests, each read back by the driver."""

    def __init__(self, device: Any, owner_pid: int, partition_handle: int, partition_id: int) -> None:
        if owner_pid <= 0 or partition_handle <= 0:
            raise ValueError("h3 memory writes through vmwp's PID and partition handle, and one was not given")
        self.device = device
        self.owner_pid = owner_pid
        self.partition_handle = partition_handle
        self.partition_id = partition_id
        self.calls = 0
        self.failed_calls = 0
        self.last: Answer | None = None

    def write(self, gpa: int, data: bytes) -> tuple[int, str | None]:
        if gpa < 0:
            return 0, "h3 memory write GPA cannot be negative"
        written = 0
        while written < len(data):
            address = gpa + written
            take = min(PAGE - (address & (PAGE - 1)), len(data) - written)
            self.calls += 1
            try:
                answer = write(
                    self.device, self.owner_pid, self.partition_handle, self.partition_id,
                    address, data[written : written + take],
                )
            except (OSError, RuntimeError) as error:
                self.failed_calls += 1
                return written, f"h3 memory: {error}"
            self.last = answer
            if not answer.ok:
                return written, answer.failure()
            written += take
        return written, None
