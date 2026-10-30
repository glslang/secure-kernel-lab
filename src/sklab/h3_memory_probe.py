"""Read-only probes used to discover h3probe's future direct-memory boundary.

These controls are measurements, not the product memory ABI. Both send their
request through the vmwp partition handle from inside the attached owner, which
is the identity VID's own IOCTL gate checks.

What the two VID controls take was read out of Vid.sys 10.0.26100.9711 (SHA-256
``633171F0...D6AD369``) and that build's vid.dll and vmwp.exe, and the comment
above ``IOCTL_H3_VIDTRANSLATE`` in ``drivers/h3probe/h3probe.c`` carries the
derivation. The decisive fact is that the translate control takes a guest
*page number*: version 1 of these probes sent the byte address unshifted, which
resolved GPA 0 and 0x1000 only because their low 12 bits are zero, and reported
every page above 4 GiB as absent. Version 2 sends ``gpa >> 12``.

The read probe answers with a typed result, so a page of zeros that is RAM can
never be confused with no page at all:

- ``ok``: one complete page, read through the block the GPA belongs to;
- ``not-present``: no GPA range holds the page;
- ``refused``: a range holds it, but not as memory-block RAM;
- ``error``: a call, the handle lookup, or the after-read recheck failed;
- ``identity``: the VID build, the vmwp, its handle, or the owner did not match.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Any


IOCTL_H3_VIDTRANSLATE = (0x22 << 16) | (0x810 << 2)
IOCTL_H3_VIDREADPROBE = (0x22 << 16) | (0x811 << 2)
VERSION = 2
PAGE = 0x1000

INPUT = struct.Struct("<IIQQ")
# H3_VIDIDENT: stamp, size, build, lookup, attached, owner_read, owner_matched,
# handle_status, owner_field, attached_process.
IDENT = struct.Struct("<8I2Q")
# Version, UserBufferStatus, ident, Gpn, TranslateStatus, Reserved,
# IoInformation, Field[4].
TRANSLATE_OUTPUT = struct.Struct("<2I48sQ2IQ4Q")
# Version, Result, ident, Gpn, UserBufferStatus, TranslateStatus,
# TranslateInformation, TranslateField[4], ScanStatus, TableCount,
# TableMatches, ReadStatus, MemoryBlockHandle, MemoryBlockPages,
# ReadInformation, Completion, RecheckStatus, DataLength, RecheckField[4], Data.
READ_OUTPUT = struct.Struct("<2I48sQ2IQ4Q4I4Q2I4Q4096s")

RESULTS = {0: "ok", 1: "not-present", 2: "refused", 3: "error", 4: "identity"}


def _hex32(value: int) -> str:
    return f"0x{value:08x}"


@dataclass(frozen=True)
class Identity:
    vid_timestamp: int
    vid_size: int
    build_status: int
    lookup_status: int
    attached: bool
    owner_read: bool
    owner_matched: bool
    handle_status: int
    owner_field: int
    attached_process: int

    @classmethod
    def unpack(cls, raw: bytes) -> "Identity":
        values = IDENT.unpack(raw)
        return cls(
            vid_timestamp=values[0],
            vid_size=values[1],
            build_status=values[2],
            lookup_status=values[3],
            attached=bool(values[4]),
            owner_read=bool(values[5]),
            owner_matched=bool(values[6]),
            handle_status=values[7],
            owner_field=values[8],
            attached_process=values[9],
        )

    @property
    def matched(self) -> bool:
        return (
            self.build_status == 0
            and self.lookup_status == 0
            and self.attached
            and self.handle_status == 0
            and self.owner_read
            and self.owner_matched
        )

    def record(self) -> dict[str, object]:
        return {
            "vid_build": {
                "timestamp": _hex32(self.vid_timestamp),
                "size": f"0x{self.vid_size:x}",
                "status": _hex32(self.build_status),
            },
            "lookup_status": _hex32(self.lookup_status),
            "attached": self.attached,
            "handle_status": _hex32(self.handle_status),
            "owner_read": self.owner_read,
            "owner_matched": self.owner_matched,
            "matched": self.matched,
        }


def _request(owner_pid: int, partition_handle: int, gpa: int) -> bytes:
    if owner_pid <= 0 or partition_handle <= 0:
        raise ValueError("vmwp PID and partition handle must both be nonzero")
    if gpa < 0 or gpa > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("GPA must fit in an unsigned 64-bit value")
    return INPUT.pack(owner_pid, 0, partition_handle, gpa)


def _version(value: int, what: str) -> None:
    if value != VERSION:
        raise OSError(
            f"h3probe {what} answered version {value}; this client reads version {VERSION}"
        )


@dataclass(frozen=True)
class Translation:
    identity: Identity
    gpn: int
    user_buffer_status: int
    translate_status: int
    information: int
    fields: tuple[int, int, int, int]

    @property
    def succeeded(self) -> bool:
        return (
            self.identity.matched
            and self.user_buffer_status == 0
            and self.translate_status == 0
            and self.information == 32
        )

    @property
    def kind(self) -> str:
        """What VID holds at this page: memory-block RAM, another range, or nothing."""
        if not self.succeeded:
            return "unknown"
        if self.fields[1]:
            return "memory-block"
        return "other-range" if self.fields[0] else "none"

    def record(self) -> dict[str, object]:
        return {
            "identity": self.identity.record(),
            "gpn": f"0x{self.gpn:x}",
            "user_buffer_status": _hex32(self.user_buffer_status),
            "translate_status": _hex32(self.translate_status),
            "information": self.information,
            "fields": [f"0x{value:x}" for value in self.fields],
            "kind": self.kind,
            "succeeded": self.succeeded,
        }


def translate(
    device: Any,
    owner_pid: int,
    partition_handle: int,
    gpa: int,
) -> Translation:
    """Ask the exact-build VID partition handle what holds one guest page."""
    raw = device.ioctl(
        IOCTL_H3_VIDTRANSLATE,
        _request(owner_pid, partition_handle, gpa),
        TRANSLATE_OUTPUT.size,
    )
    if len(raw) != TRANSLATE_OUTPUT.size:
        raise OSError(
            f"h3probe VID translate returned {len(raw)} of {TRANSLATE_OUTPUT.size} bytes"
        )
    values = TRANSLATE_OUTPUT.unpack(raw)
    _version(values[0], "VID translate")
    return Translation(
        identity=Identity.unpack(values[2]),
        gpn=values[3],
        user_buffer_status=values[1],
        translate_status=values[4],
        information=values[6],
        fields=(values[7], values[8], values[9], values[10]),
    )


@dataclass(frozen=True)
class ReadProbe:
    result: str
    identity: Identity
    gpn: int
    user_buffer_status: int
    translate_status: int
    translate_information: int
    translate_fields: tuple[int, int, int, int]
    scan_status: int
    table_count: int
    table_matches: int
    read_status: int
    memory_block_handle: int
    memory_block_pages: int
    read_information: int
    completion: int
    recheck_status: int
    recheck_fields: tuple[int, int, int, int]
    data: bytes

    @property
    def succeeded(self) -> bool:
        return self.result == "ok" and len(self.data) == PAGE

    def record(self) -> dict[str, object]:
        return {
            "result": self.result,
            "identity": self.identity.record(),
            "gpn": f"0x{self.gpn:x}",
            "user_buffer_status": _hex32(self.user_buffer_status),
            "translate": {
                "status": _hex32(self.translate_status),
                "information": self.translate_information,
                "fields": [f"0x{value:x}" for value in self.translate_fields],
            },
            "memory_block": {
                "scan_status": _hex32(self.scan_status),
                "table_count": self.table_count,
                "table_matches": self.table_matches,
                "handle": self.memory_block_handle,
                "pages": self.memory_block_pages,
            },
            "read": {
                "status": _hex32(self.read_status),
                "information": self.read_information,
                "completion": f"0x{self.completion:x}",
            },
            "recheck": {
                "status": _hex32(self.recheck_status),
                "fields": [f"0x{value:x}" for value in self.recheck_fields],
            },
            "all_zero": self.data == bytes(len(self.data)) if self.data else None,
            "sha256": hashlib.sha256(self.data).hexdigest() if self.data else None,
            "succeeded": self.succeeded,
        }


def read_probe(
    device: Any,
    owner_pid: int,
    partition_handle: int,
    gpa: int,
) -> ReadProbe:
    """Read one aligned guest page through vmwp's own memory block, typed."""
    if gpa & (PAGE - 1):
        raise ValueError("read-probe GPA must be page aligned")
    raw = device.ioctl(
        IOCTL_H3_VIDREADPROBE,
        _request(owner_pid, partition_handle, gpa),
        READ_OUTPUT.size,
    )
    if len(raw) != READ_OUTPUT.size:
        raise OSError(
            f"h3probe VID read probe returned {len(raw)} of {READ_OUTPUT.size} bytes"
        )
    values = READ_OUTPUT.unpack(raw)
    _version(values[0], "VID read probe")
    result = RESULTS.get(values[1])
    if result is None:
        raise OSError(f"h3probe VID read probe answered unknown result {values[1]}")
    data_length = values[20]
    if data_length not in (0, PAGE) or (result == "ok") != (data_length == PAGE):
        raise OSError(
            f"h3probe VID read probe answered {result} with {data_length} data bytes"
        )
    return ReadProbe(
        result=result,
        identity=Identity.unpack(values[2]),
        gpn=values[3],
        user_buffer_status=values[4],
        translate_status=values[5],
        translate_information=values[6],
        translate_fields=(values[7], values[8], values[9], values[10]),
        scan_status=values[11],
        table_count=values[12],
        table_matches=values[13],
        read_status=values[14],
        memory_block_handle=values[15],
        memory_block_pages=values[16],
        read_information=values[17],
        completion=values[18],
        recheck_status=values[19],
        recheck_fields=(values[21], values[22], values[23], values[24]),
        data=values[25][:data_length],
    )
