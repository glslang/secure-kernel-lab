from __future__ import annotations

import unittest

from sklab import h3


def _child(
    partition: int,
    *,
    vtl0: tuple[int, int],
    vtl1: tuple[int, int],
    vp_status: tuple[int, int],
    partition_status: tuple[int, int],
) -> bytes:
    """One `H3_VP_RESULT`, laid out at the offsets `#pragma pack(1)` gives it in h3probe.c."""
    raw = bytearray(60)
    raw[0:8] = partition.to_bytes(8, "little")  # PartitionId
    raw[8:12] = (0).to_bytes(4, "little")  # VpIndex
    raw[12:16] = vtl0[0].to_bytes(4, "little")  # Vtl0Status
    raw[16:24] = vtl0[1].to_bytes(8, "little")  # Vtl0Cr3
    raw[24:28] = vtl1[0].to_bytes(4, "little")  # Vtl1Status
    raw[28:36] = vtl1[1].to_bytes(8, "little")  # Vtl1Cr3
    raw[36:40] = vp_status[0].to_bytes(4, "little")  # VsmVpStatusStatus
    raw[40:48] = vp_status[1].to_bytes(8, "little")  # VsmVpStatus
    raw[48:52] = partition_status[0].to_bytes(4, "little")  # VsmPartStatusStatus
    raw[52:60] = partition_status[1].to_bytes(8, "little")  # VsmPartitionStatus
    return bytes(raw)


def _results(*children: bytes, enum_status: int = 0) -> bytes:
    header = (1).to_bytes(4, "little") + enum_status.to_bytes(4, "little")
    header += len(children).to_bytes(4, "little") + bytes(4)
    body = b"".join(children)
    return header + body + bytes(8 * 60 - len(body))


# The two guests the gate first ran against (feasibility doc, H3 result, 2026-09-26).
VBS_OFF = _child(
    0x2,
    vtl0=(0, 0x7D5000),
    vtl1=(0x15, 0),
    vp_status=(0, 0x0001 << 8),
    partition_status=(0, 0x0001),
)
VBS_ON = _child(
    0x3,
    vtl0=(0, 0x1A75000),
    vtl1=(0, 0x1201000),
    vp_status=(0, (0x0003 << 8) | 1),
    partition_status=(0, (1 << 16) | 0x0003),
)


class H3Tests(unittest.TestCase):
    def test_layout_matches_the_driver_struct(self) -> None:
        self.assertEqual(h3.CHILD.size, 60)
        self.assertEqual(h3.RESULT_SIZE, 16 + 8 * 60)

    def test_the_recorded_gate_reads_back(self) -> None:
        gate = h3.parse(_results(VBS_OFF, VBS_ON))
        self.assertEqual(gate["enum_status"], "success")
        off, on = gate["children"]
        self.assertEqual(off["partition_id"], "0x2")
        self.assertEqual(off["vtl0"], {"status": "success", "cr3": "0x7d5000"})
        self.assertEqual(off["vtl1"]["status"], "0x0015")
        self.assertEqual(off["vsm_partition_status"]["maximum_vtl"], 0)
        self.assertEqual(off["verdict"], "no-vtl1")
        self.assertEqual(on["vtl1"], {"status": "success", "cr3": "0x1201000"})
        self.assertEqual(on["vsm_vp_status"]["enabled_vtl_set"], 0x3)
        self.assertEqual(on["vsm_vp_status"]["active_vtl"], 1)
        self.assertEqual(on["vsm_partition_status"]["enabled_vtl_set"], 0x3)
        self.assertEqual(on["vsm_partition_status"]["maximum_vtl"], 1)
        self.assertEqual(on["verdict"], "granted")

    def test_a_failed_control_says_nothing_about_vtl1(self) -> None:
        both_refused = _child(
            0x4, vtl0=(0x6, 0), vtl1=(0x6, 0), vp_status=(0x6, 0), partition_status=(0x6, 0)
        )
        self.assertEqual(h3.parse(_results(both_refused))["children"][0]["verdict"], "control-failed")

    def test_vtl1_cr3_equal_to_vtl0_is_not_a_pass(self) -> None:
        aliased = _child(
            0x5,
            vtl0=(0, 0x1000),
            vtl1=(0, 0x1000),
            vp_status=(0, 0x0003 << 8),
            partition_status=(0, 0x0003),
        )
        self.assertEqual(h3.parse(_results(aliased))["children"][0]["verdict"], "same-cr3")

    def test_truncated_and_overfull_results_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            h3.parse(bytes(8))
        overfull = (1).to_bytes(4, "little") + bytes(4) + (9).to_bytes(4, "little") + bytes(4)
        with self.assertRaises(ValueError):
            h3.parse(overfull + bytes(8 * 60))
        short = _results(VBS_OFF, VBS_ON)[: 16 + 60 + 10]
        with self.assertRaises(ValueError):
            h3.parse(short)

    def test_rows_mark_the_target_and_show_refusals_raw(self) -> None:
        rows = h3.rows(h3.parse(_results(VBS_OFF, VBS_ON)), target_partition="0x3")
        self.assertEqual(rows[0]["vtl1 cr3"], "refused 0x0015")
        self.assertEqual(rows[0]["target"], "")
        self.assertEqual(rows[1]["vtl set"], "0x0003")
        self.assertEqual(rows[1]["target"], "<- target")


if __name__ == "__main__":
    unittest.main()
