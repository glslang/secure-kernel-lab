"""Guest-physical sources and the provider-neutral walks over them.

`H3Source` reads and writes guest-physical pages through h3probe's exact-build VID memory operation
(`sklab.h3_memory`): no handle is duplicated, no other driver is opened, and absence is typed, so a page
with no RAM behind it answers `NOTPRESENT` rather than a page of zeros. The caller supplies the
vmwp PID, the per-boot VID handle valid inside it, and the partition ID; h3probe checks all three.

`HypercallSource` reads through `HvCallReadGpa`, which refuses VTL1; it is the negative control.

`GuestVirtual`, `vtl1_identity` and `find_secure_kernel_base` take any source with the
`read(gpa, size) -> (data, failure)` shape. CR3 and IDTR come from HvCallGetVpRegisters through
h3probe; the Secure Kernel image base is recovered by following live IDT handlers through that CR3.
"""

from __future__ import annotations

import pathlib
import struct
from typing import Any

from h3_vtl1_debug_control import Probe, REGISTERS
from sklab import h3_memory


PAGE_SIZE = 0x1000
MASK_4K = 0x000F_FFFF_FFFF_F000
MASK_2M = 0x000F_FFFF_FFE0_0000
MASK_1G = 0x000F_FFFF_C000_0000
HV_X64_REGISTER_IDTR = 0x00070000


class H3Source:
    """An uncached h3probe physical source bound to one vmwp, VID handle and partition.

    It backs a live protocol transport, so two reads of one GPA may observe two generations of the
    guest; caching belongs to a higher-level walk such as :class:`GuestVirtual`. Failures are given
    in the transport's own words: ``NOTPRESENT``, ``REFUSED <stage>`` and ``ERROR <detail>``.
    """

    max_read = PAGE_SIZE
    max_write = PAGE_SIZE

    def __init__(self, vmwp_pid: int, partition_handle: int, partition_id: int) -> None:
        self.device: Any = h3_memory.Device()
        self.reader = h3_memory.Reader(self.device, vmwp_pid, partition_handle, partition_id)
        self.writer = h3_memory.Writer(self.device, vmwp_pid, partition_handle, partition_id)

    def close(self) -> None:
        if self.device is not None:
            self.device.close()
            self.device = None

    @staticmethod
    def _words(answer: h3_memory.Answer | None, failure: str | None) -> str:
        if answer is None:
            return f"ERROR {failure or 'h3 memory gave no answer'}"
        if answer.result == "not-present":
            return "NOTPRESENT"
        if answer.result == "refused":
            return f"REFUSED {answer.stage}"
        return f"ERROR {answer.failure()}"

    def read(self, gpa: int, size: int) -> tuple[bytes | None, str | None]:
        if self.device is None:
            return None, "ERROR h3 source is closed"
        if gpa < 0 or size < 0:
            return None, "ERROR negative GPA or size"
        result = bytearray()
        while size:
            take = min(size, PAGE_SIZE - (gpa & (PAGE_SIZE - 1)))
            data, answer, failure = self.reader.chunk(gpa, take)
            if data is None:
                return None, self._words(answer, failure)
            result += data
            gpa += take
            size -= take
        return bytes(result), None

    def write(self, gpa: int, data: bytes) -> str | None:
        if self.device is None:
            return "ERROR h3 source is closed"
        if not data or len(data) > self.max_write:
            return f"ERROR write size must be in 1..{self.max_write}"
        if gpa < 0 or (gpa & (PAGE_SIZE - 1)) + len(data) > PAGE_SIZE:
            return "ERROR write must remain within one physical page"
        written, failure = self.writer.write(gpa, data)
        if written != len(data):
            return self._words(self.writer.last, failure)
        return None


HV_ACCESS = {0: "Accepted", 1: "Unmapped", 2: "ReadIntercept", 3: "WriteIntercept", 4: "Rom"}
IOCTL_H3_READGPA = (0x22 << 16) | (0x801 << 2)


class HypercallSource:
    """``HvCallReadGpa`` through h3probe: the transport that refuses.

    H4 measured the hypercall answering HV_STATUS_SUCCESS with a buffer of zeros and a per-access
    ``ReadIntercept`` for VTL1 pages, so the access result, not the status, decides: anything but
    ``Accepted`` is ``REFUSED`` with its name. It moves at most sixteen bytes, which is why
    ``max_read`` is 16 and why the decode is seen chunking at the source's own width.
    """

    max_read = 16

    def __init__(self, partition_id: int) -> None:
        self.probe: Any = Probe()
        self.partition_id = partition_id

    def close(self) -> None:
        if self.probe is not None:
            self.probe.close()
            self.probe = None

    def read(self, gpa: int, size: int) -> tuple[bytes | None, str | None]:
        if self.probe is None:
            return None, "ERROR hypercall source is closed"
        if gpa < 0 or size < 0 or size > self.max_read:
            return None, f"ERROR a hypercall read is 0..{self.max_read} bytes at a non-negative GPA"
        try:
            raw = self.probe.ioctl(IOCTL_H3_READGPA, struct.pack("<QQII", self.partition_id, gpa, size, 0), 32)
        except RuntimeError as error:
            return None, f"ERROR {error}"
        if len(raw) < 16 + size:
            return None, f"ERROR h3probe returned {len(raw)} bytes"
        status, _, access = struct.unpack_from("<IIQ", raw, 0)
        if status:
            return None, f"ERROR HV_STATUS 0x{status:04X}"
        if access:
            return None, f"REFUSED {HV_ACCESS.get(access, '?')}({access})"
        return raw[16 : 16 + size], None


class GuestVirtual:
    def __init__(self, source: Any, cr3: int) -> None:
        if not cr3 or cr3 & (PAGE_SIZE - 1):
            raise ValueError(f"VTL1 CR3 is not a nonzero aligned address: 0x{cr3:x}")
        self.source = source
        self.cr3 = cr3 & MASK_4K
        # One virtual walk is a snapshot-like operation and repeatedly consults
        # the same paging pages.  Keep that optimization local so a later raw
        # transport READ is never answered from this walk's old generation.
        self.pages: dict[int, bytes] = {}

    def _page(self, gpa: int) -> bytes:
        page = gpa & ~(PAGE_SIZE - 1)
        cached = self.pages.get(page)
        if cached is not None:
            return cached
        raw, failure = self.source.read(page, PAGE_SIZE)
        if raw is None:
            raise KeyError(f"GPA 0x{page:x}: {failure}")
        self.pages[page] = raw
        return raw

    def qword(self, gpa: int) -> int:
        page = self._page(gpa)
        return struct.unpack_from("<Q", page, gpa & (PAGE_SIZE - 1))[0]

    def translate(self, va: int) -> int:
        table = self.cr3
        for level, shift in ((4, 39), (3, 30), (2, 21), (1, 12)):
            entry = self.qword(table + ((va >> shift) & 0x1FF) * 8)
            if not entry & 1:
                raise KeyError(f"VA 0x{va:x}: level {level} entry is not present")
            if level == 3 and entry & (1 << 7):
                return (entry & MASK_1G) | (va & ((1 << 30) - 1))
            if level == 2 and entry & (1 << 7):
                return (entry & MASK_2M) | (va & ((1 << 21) - 1))
            table = entry & MASK_4K
        return table | (va & (PAGE_SIZE - 1))

    def read(self, va: int, size: int) -> bytes:
        result = bytearray()
        while size:
            gpa = self.translate(va)
            take = min(size, PAGE_SIZE - (va & (PAGE_SIZE - 1)))
            page = self._page(gpa)
            offset = gpa & (PAGE_SIZE - 1)
            result += page[offset : offset + take]
            va += take
            size -= take
        return bytes(result)


def vtl1_identity(partition_id: int, vp: int = 0) -> dict[str, int]:
    """Read the VTL1 CR3, IDTR and RIP from the hypervisor register interface."""
    probe = Probe()
    try:
        children = probe.children()
        if children.get(partition_id) != 3:
            raise RuntimeError(
                f"partition 0x{partition_id:x} is not the selected VTL0+VTL1 child: {children}"
            )
        values: dict[str, tuple[int, int]] = {}
        for name, register in (
            ("cr3", REGISTERS["cr3"]),
            ("rip", REGISTERS["rip"]),
            ("idtr", HV_X64_REGISTER_IDTR),
        ):
            status, low, high = probe.get(partition_id, 1, register, vp)
            if status != 0:
                raise RuntimeError(f"VTL1 {name} read failed: HV_STATUS 0x{status:04x}")
            values[name] = (low, high)
    finally:
        probe.close()
    idtr_low, idtr_base = values["idtr"]
    result = {
        "cr3": values["cr3"][0],
        "rip": values["rip"][0],
        "idtr_base": idtr_base,
        "idtr_limit": (idtr_low >> 48) & 0xFFFF,
    }
    if result["idtr_base"] == 0 or result["idtr_limit"] < 15:
        raise RuntimeError(f"VTL1 IDTR is invalid: {result}")
    return result


def _pe_identity(data: bytes) -> dict[str, int] | None:
    if len(data) < PAGE_SIZE or data[:2] != b"MZ":
        return None
    (pe,) = struct.unpack_from("<I", data, 0x3C)
    if pe > len(data) - 0x108 or data[pe : pe + 4] != b"PE\0\0":
        return None
    (machine,) = struct.unpack_from("<H", data, pe + 4)
    (timestamp,) = struct.unpack_from("<I", data, pe + 8)
    (magic,) = struct.unpack_from("<H", data, pe + 24)
    (size_of_image,) = struct.unpack_from("<I", data, pe + 24 + 0x38)
    if machine != 0x8664 or magic != 0x20B or not size_of_image:
        return None
    return {
        "machine": machine,
        "timestamp": timestamp,
        "size_of_image": size_of_image,
    }


def disk_pe_identity(path: pathlib.Path) -> dict[str, int]:
    data = path.read_bytes()[:PAGE_SIZE]
    identity = _pe_identity(data)
    if identity is None:
        raise ValueError(f"{path} is not a PE32+ AMD64 image")
    return identity


def idt_handlers(guest: GuestVirtual, idtr_base: int, idtr_limit: int) -> list[int]:
    size = min(idtr_limit + 1, PAGE_SIZE)
    table = guest.read(idtr_base, size)
    handlers: list[int] = []
    for offset in range(0, len(table) - 15, 16):
        (low,) = struct.unpack_from("<H", table, offset)
        (middle,) = struct.unpack_from("<H", table, offset + 6)
        (high,) = struct.unpack_from("<I", table, offset + 8)
        address = low | (middle << 16) | (high << 32)
        if not address:
            continue
        top = address >> 47
        if top not in (0, 0x1FFFF):
            continue
        handlers.append(address)
    if not handlers:
        raise RuntimeError("the live VTL1 IDT contains no canonical handler address")
    return handlers


def find_secure_kernel_base(
    guest: GuestVirtual,
    idtr_base: int,
    idtr_limit: int,
    image: pathlib.Path | None = None,
    window_mib: int = 16,
) -> tuple[int, dict[str, Any]]:
    """Find the PE containing a live VTL1 IDT handler."""
    expected = disk_pe_identity(image) if image is not None else None
    handlers = idt_handlers(guest, idtr_base, idtr_limit)
    checked: set[int] = set()
    for handler in handlers:
        start = handler & ~(PAGE_SIZE - 1)
        stop = start - window_mib * 1024 * 1024
        for candidate in range(start, stop - 1, -PAGE_SIZE):
            if candidate in checked:
                continue
            checked.add(candidate)
            try:
                header = guest.read(candidate, PAGE_SIZE)
            except KeyError:
                continue
            identity = _pe_identity(header)
            if identity is None:
                continue
            if not candidate <= handler < candidate + identity["size_of_image"]:
                continue
            if expected is not None and any(
                identity[field] != expected[field]
                for field in ("machine", "timestamp", "size_of_image")
            ):
                continue
            return candidate, {
                "idtr_base": f"0x{idtr_base:016x}",
                "idtr_limit": idtr_limit,
                "handler": f"0x{handler:016x}",
                "vectors_with_handlers": len(handlers),
                "pages_checked": len(checked),
                "image": {key: f"0x{value:x}" for key, value in identity.items()},
            }
    qualification = f" matching {image}" if image is not None else ""
    raise RuntimeError(
        f"no PE{qualification} contains any VTL1 IDT handler within {window_mib} MiB"
    )
