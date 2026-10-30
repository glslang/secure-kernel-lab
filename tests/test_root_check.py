from __future__ import annotations

from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from sklab.config import load
from sklab.context import RunContext
from sklab.modules import core
from sklab.util import pe_identity


EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.toml"
BASE = 0xFFFFF80460000000
IDT = 0xFFFFF80461000000


def _pe(timestamp: int, size_of_image: int, *, offset: int = 0x108) -> bytes:
    """A first page with an MZ stub and PE headers, at offsets written out rather than packed."""
    page = bytearray(0x1000)
    page[0:2] = b"MZ"
    page[0x3C:0x40] = offset.to_bytes(4, "little")  # e_lfanew
    page[offset : offset + 4] = b"PE\0\0"
    page[offset + 4 : offset + 6] = (0x8664).to_bytes(2, "little")  # Machine
    page[offset + 8 : offset + 12] = timestamp.to_bytes(4, "little")  # TimeDateStamp
    page[offset + 24 : offset + 26] = (0x20B).to_bytes(2, "little")  # PE32+ magic
    page[offset + 24 + 56 : offset + 24 + 60] = size_of_image.to_bytes(4, "little")  # SizeOfImage
    return bytes(page)


PINNED = _pe(0x5A0B1C2D, 0x1A4000)


class PeIdentityTests(unittest.TestCase):
    def test_reads_machine_timestamp_and_size(self) -> None:
        self.assertEqual(
            pe_identity(PINNED),
            {"machine": 0x8664, "timestamp": 0x5A0B1C2D, "size_of_image": 0x1A4000},
        )

    def test_refuses_what_is_not_a_pe(self) -> None:
        self.assertIsNone(pe_identity(bytes(0x1000)))
        self.assertIsNone(pe_identity(b"MZ" + bytes(0x3E)))
        broken = bytearray(PINNED)
        broken[0x108:0x10C] = b"NE\0\0"
        self.assertIsNone(pe_identity(bytes(broken)))


class RootCheckTests(unittest.TestCase):
    """The three verdicts, against a fake reader whose roots map what each test says they map."""

    def run_check(self, roots: dict[int, bytes | None]) -> dict:
        config = load(EXAMPLE)
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "securekernel.exe"
            image.write_bytes(PINNED)
            target = config.target("demo")
            target = type(target)(**{**target.__dict__, "secure_kernel_image": image})
            context = RunContext(config, mock.Mock(), mock.Mock(), target)

            class Guest:
                def __init__(self, source, cr3):
                    self.cr3 = cr3

                def virtual(self, va, size):
                    page = roots[self.cr3]
                    if page is None:
                        raise KeyError(f"VA 0x{va:X}: level 4 not present")
                    if va == IDT:  # vector 0's gate, pointing at BASE + 0x1010
                        return bytes.fromhex("1010" "1000" "00" "8e" "0060" "04f8ffff" "00000000")[:size]
                    if va != BASE:
                        raise KeyError(f"VA 0x{va:X}: level 1 not present")
                    return page[:size]

            idtr = {"status": 0, "low": f"0x{0xFFF << 48:016x}", "high": f"0x{IDT:016x}"}
            snapshots = {
                str(vp): {"registers": {"cr3": {"low": f"0x{cr3:016x}"}, "idtr": idtr}}
                for vp, cr3 in enumerate(roots)
            }
            with mock.patch.object(core.bench_bridge, "_module", return_value=types.SimpleNamespace(Guest=Guest)), \
                 mock.patch.object(core.h3_memory, "Device", mock.Mock()), \
                 mock.patch.object(core.h3_memory, "Reader", wraps=core.h3_memory.Reader) as reader:
                self.reader = reader
                return core._root_check(
                    context,
                    0x2,
                    snapshots,
                    vmwp_pid=4242,
                    partition_handle=0x2E0,
                )

    def test_each_root_gets_its_own_verdict(self) -> None:
        result = self.run_check({0x2601000: PINNED, 0x3000000: _pe(0x11111111, 0x1A4000), 0x4000000: None})
        self.assertEqual(result["vps"]["0"]["verdict"], "maps-pinned-image")
        self.assertEqual(result["vps"]["1"]["verdict"], "maps-other-image")
        self.assertEqual(result["vps"]["2"]["verdict"], "base-unmapped")
        self.assertEqual(result["secure_kernel_base"], hex(BASE))
        # The default reader is h3probe's memory operation, given vmwp's PID, its own handle value
        # and the partition, with nothing duplicated.
        self.assertEqual(result["reader"], "h3")
        self.assertEqual(self.reader.call_args.args[1:], (4242, 0x2E0, 0x2))
        self.assertEqual(result["partition_handle"], "0x2e0")

    def test_the_root_check_is_part_of_a_snapshot_by_default(self) -> None:
        context = RunContext(load(EXAMPLE), mock.Mock(), mock.Mock(), load(EXAMPLE).target("demo"))
        with mock.patch.object(core, "doctor", return_value=[]) as doctor:
            core._registers_checks(context, {"snapshot": True})
            self.assertTrue({"h3_memory", "image"} <= set(doctor.call_args.kwargs["required"]))
            self.assertFalse({"hvlib", "hvmm"} & set(doctor.call_args.kwargs["required"]))
            core._registers_checks(context, {"snapshot": True, "root_check": False})
            self.assertFalse({"h3_memory", "image"} & set(doctor.call_args.kwargs["required"]))


if __name__ == "__main__":
    unittest.main()
