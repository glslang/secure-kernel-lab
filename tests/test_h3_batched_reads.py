from __future__ import annotations

import struct
import unittest

from sklab import bench_bridge


control = bench_bridge._module("h3_vtl1_debug_control")


class FakeProbe(control.Probe):
    """`IOCTL_H3_CALL` as h3probe.c serves it: an 80-byte `H3_CALL_OUT`, refused below that."""

    def __init__(self) -> None:  # no device: nothing here reaches a driver
        self.handle = None
        self.sizes: list[int] = []

    def ioctl(self, code: int, payload: bytes | None, out_size: int) -> bytes:
        self.sizes.append(out_size)
        if code != control.IOCTL_H3_CALL:
            raise AssertionError(f"unexpected ioctl 0x{code:x}")
        if out_size < 80:
            raise RuntimeError(f"DeviceIoControl 0x{code:X}: Win32 122")
        control_word, _length, _reserved = struct.unpack_from("<QII", payload, 0)
        reps = (control_word >> 32) & 0xFFF
        values = b"".join(struct.pack("<QQ", 0x1000 + index, 0) for index in range(min(reps, 4)))
        # RawResult (status 0, reps completed in 43:32), poison + pad, then Out[64].
        return struct.pack("<Q", reps << 32) + bytes(8) + values.ljust(64, b"\0")


class BatchedReadTests(unittest.TestCase):
    def test_short_batches_still_meet_the_driver_minimum(self) -> None:
        probe = FakeProbe()
        rows = control.get_many(probe, 0x2, 1, control.SNAPSHOT_NAMES, 0, 4)
        self.assertEqual(len(rows), len(control.SNAPSHOT_NAMES))
        self.assertTrue(all(row["status"] == 0 for row in rows.values()))
        single = control.get_many(probe, 0x2, 0, ("vsm_vp_status",), 0, 1)
        self.assertEqual(single["vsm_vp_status"]["low"], "0x0000000000001000")
        self.assertGreaterEqual(min(probe.sizes), 80)

    def test_the_coherent_snapshot_settles_on_what_the_driver_returns(self) -> None:
        snapshot = control.snapshot_coherent(FakeProbe(), 0x2, 0)
        self.assertEqual(snapshot["coherence"]["registers_per_call"], 4)
        self.assertEqual(snapshot["coherence"]["hypercalls"], 4)
        self.assertEqual(set(snapshot["registers"]), {*control.SNAPSHOT_NAMES, "vsm_vp_status"})


if __name__ == "__main__":
    unittest.main()
