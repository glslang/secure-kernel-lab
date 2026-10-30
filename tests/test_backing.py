from __future__ import annotations

import struct
import unittest

from sklab import backing


class H3Probe:
    """h3probe's IOCTL_H3_READGPA: a 32-byte H3_READGPA_OUT, HvStatus at +0 and AccessResult at +8."""

    def __init__(self, status: int = 0, access: int = 0, fail: Exception | None = None, size: int = 32) -> None:
        self.status, self.access, self.fail, self.size = status, access, fail, size
        self.calls: list[tuple[int, bytes, int]] = []

    def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
        self.calls.append((code, payload, out_size))
        if self.fail is not None:
            raise self.fail
        return (struct.pack("<IIQ", self.status, 0, self.access) + bytes(16))[: self.size]


class HypervisorTests(unittest.TestCase):
    def ask(self, probe: H3Probe, gpa: int = 0x0) -> tuple[bool | None, str]:
        return backing.Hypervisor(probe, 0xB).ask(gpa)

    def test_the_request_is_h3probes_readgpa_for_16_bytes(self) -> None:
        probe = H3Probe()
        self.ask(probe, 0xFEE00000)
        self.assertEqual(
            probe.calls,
            [(0x222004, bytes.fromhex("0b00000000000000" "0000e0fe00000000" "10000000" "00000000"), 32)],
        )

    def test_what_k3_answered(self) -> None:
        # 2026-10-17: page 0 Accepted, the first page past RAM Unmapped, the local APIC HV_STATUS 0x0080
        self.assertEqual(self.ask(H3Probe(access=0)), (True, "Accepted"))
        self.assertEqual(self.ask(H3Probe(access=1)), (False, "Unmapped"))
        self.assertEqual(self.ask(H3Probe(status=0x80)), (False, "HV_STATUS 0x0080"))

    def test_a_failed_hypercall_is_not_read_for_its_access_result(self) -> None:
        # h3probe zeroes its output, so a failure reads as access 0, which alone would mean Accepted
        self.assertEqual(self.ask(H3Probe(status=0x80, access=0)), (False, "HV_STATUS 0x0080"))

    def test_a_page_intercepted_for_a_vtl_is_memory(self) -> None:
        self.assertEqual(self.ask(H3Probe(access=2)), (True, "ReadIntercept"))

    def test_an_answer_not_listed_is_no_answer(self) -> None:
        self.assertEqual(self.ask(H3Probe(access=7)), (None, "access result 7"))

    def test_h3probe_failing_is_no_answer(self) -> None:
        self.assertEqual(self.ask(H3Probe(fail=RuntimeError("DeviceIoControl 0x222004: Win32 6"))),
                         (None, "h3probe: DeviceIoControl 0x222004: Win32 6"))
        self.assertEqual(self.ask(H3Probe(size=8)), (None, "h3probe returned 8 bytes"))


    def test_only_an_accepted_page_gives_up_its_bytes(self) -> None:
        class Data(H3Probe):
            def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
                return struct.pack("<IIQ", self.status, 0, self.access) + b"0123456789abcdef"

        self.assertEqual(backing.Hypervisor(Data(access=0), 0xB).read(0x1000), (True, "Accepted", b"0123456789abcdef"))
        self.assertEqual(backing.Hypervisor(Data(access=2), 0xB).read(0x1000), (True, "ReadIntercept", None))
        self.assertEqual(backing.Hypervisor(Data(access=1), 0xB).read(0x1000), (False, "Unmapped", None))

if __name__ == "__main__":
    unittest.main()
