"""What the hypervisor itself says about a guest-physical page, asked through h3probe's `HvCallReadGpa`.

It is the oracle beside h3probe's memory operation rather than a second copy of it: the memory
operation reads through VID's memory blocks inside vmwp, and this asks the hypervisor directly, so
the two can disagree only if one of them is wrong. Two answers are used.

- **Whether memory is there.** On K3 on 2026-10-17 the hypercall accepted page 0, answered
  `Unmapped` for the pages past the end of RAM, and failed with HV_STATUS 0x0080 for the local APIC
  page at `0xFEE00000`; 0x0080 is not in the SDK's hvgdk.h, so a failed hypercall is read as "not
  memory" by choice, from that one page. It answers `ReadIntercept` for a page VTL1 protects, which
  is what makes the pages the memory operation reads there a test of it.
- **The first bytes of a page it accepts.** It moves sixteen bytes, and for a page it accepts those
  are the page's own, so they must equal the start of what the memory operation read.

Before the h3probe-only migration this also decided, for the retired hvmm reader, whether a page of
zeros outside NT's RAM runs was a zero page or no page; the memory operation now answers that by type.
"""

from __future__ import annotations

import struct
from typing import Any


IOCTL_READ_GPA = (0x22 << 16) | (0x801 << 2)  # h3probe's IOCTL_H3_READGPA
UNMAPPED = 1
# HV_ACCESS results that mean memory is there: read, intercepted for a VTL, or read-only
BACKED = {0: "Accepted", 2: "ReadIntercept", 3: "WriteIntercept", 4: "Rom"}
READ_BYTES = 16


class Hypervisor:
    """`ask(gpa)` answers `(backed, answer)`: True for memory, False for `Unmapped` or a failed
    hypercall, None when h3probe could not be asked or answered something not listed here.
    `read(gpa)` adds the sixteen bytes at `gpa` when the answer is `Accepted`, and None otherwise."""

    def __init__(self, device: Any, partition_id: int) -> None:
        self.device = device
        self.partition_id = partition_id

    def read(self, gpa: int) -> tuple[bool | None, str, bytes | None]:
        request = struct.pack("<QQII", self.partition_id, gpa, READ_BYTES, 0)  # H3_READGPA_IN
        try:
            raw = self.device.ioctl(IOCTL_READ_GPA, request, 32)
        except (OSError, RuntimeError) as error:  # the bench's Probe raises RuntimeError for a failed call
            return None, f"h3probe: {error}", None
        if len(raw) < 16:
            return None, f"h3probe returned {len(raw)} bytes", None
        status, _, access = struct.unpack_from("<IIQ", raw, 0)  # H3_READGPA_OUT
        if status:  # h3probe zeroes its output, so the access result means nothing here
            return False, f"HV_STATUS 0x{status:04X}", None
        code = access & 0xFFFFFFFF
        if code == UNMAPPED:
            return False, "Unmapped", None
        if code in BACKED:
            data = raw[16 : 16 + READ_BYTES] if code == 0 and len(raw) >= 16 + READ_BYTES else None
            return True, BACKED[code], data
        return None, f"access result {code}", None

    def ask(self, gpa: int) -> tuple[bool | None, str]:
        backed, answer, _data = self.read(gpa)
        return backed, answer
