from __future__ import annotations

import unittest

from sklab import guest_ram, sk_processes


NT_BASE = 0xFFFFF80300000000
DESCRIPTOR = 0xFFFFC00012340000
VTL0_IDT = 0xFFFFF80310000000
HANDLER = NT_BASE + 0xBC9100  # KiDivideErrorFaultShadow in the K3 build
# K3's RAM as its own registry map listed it on 2026-10-17, in pages: first page and count
K3_RUNS = [(0x1, 0x9F), (0x100, 0x877), (0xC70, 0xF72D1), (0xF7FC5, 0xF), (0xF7FFF, 0x1), (0x100000, 0x8000)]


def nt_header(guid: bytes, age: int, name: bytes = b"ntkrnlmp.pdb") -> bytes:
    """ntoskrnl's first page: PE32+ headers whose debug directory points at a CodeView record, at
    offsets written out rather than taken from the module under test."""
    page = bytearray(0x1000)
    page[0:2] = b"MZ"
    page[0x3C:0x40] = (0x108).to_bytes(4, "little")  # e_lfanew
    page[0x108:0x10C] = b"PE\0\0"
    page[0x10C:0x10E] = (0x8664).to_bytes(2, "little")
    page[0x120:0x122] = (0x20B).to_bytes(2, "little")  # PE32+ optional header at 0x108 + 24
    page[0x120 + 56 : 0x120 + 60] = (0x1249000).to_bytes(4, "little")  # SizeOfImage
    page[0x1C0:0x1C8] = (0x800).to_bytes(4, "little") + (28).to_bytes(4, "little")  # data directory 6: debug
    page[0x800 + 12 : 0x800 + 16] = (2).to_bytes(4, "little")  # IMAGE_DEBUG_TYPE_CODEVIEW
    page[0x800 + 16 : 0x800 + 20] = (0x40).to_bytes(4, "little")  # SizeOfData
    page[0x800 + 20 : 0x800 + 24] = (0x900).to_bytes(4, "little")  # AddressOfRawData
    page[0x900:0x904] = b"RSDS"
    page[0x904:0x914] = guid
    page[0x914:0x918] = age.to_bytes(4, "little")
    page[0x918 : 0x918 + len(name)] = name
    return bytes(page)


# GUID C29EBFB0-6B78-B3C0-20DC-A66D99713F9E as it sits in memory: three little-endian fields, then 8 bytes
K3_GUID = bytes.fromhex("b0bf9ec2" "786b" "c0b3" "20dca66d99713f9e")


class Space:
    """A VTL0 kernel address space of bytes; anything not put is not mapped."""

    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.unreadable: set[int] = set()  # pages the reader cannot read

    def put(self, va: int, data: bytes) -> None:
        for index, byte in enumerate(data):
            self.bytes[va + index] = byte

    def virtual(self, va: int, size: int) -> bytes:
        if va & ~0xFFF in self.unreadable:
            raise sk_processes.UnreadablePage(f"GPA of VA 0x{va:X}: unreadable", 0)
        try:
            return bytes(self.bytes[va + index] for index in range(size))
        except KeyError:
            raise KeyError(f"VA 0x{va:X}: level 1 not present") from None


def k3(runs: list[tuple[int, int]] | None = None, total: int | None = None, guid: bytes = K3_GUID) -> Space:
    runs = K3_RUNS if runs is None else runs
    space = Space()
    space.put(NT_BASE, nt_header(guid, 1))
    space.put(VTL0_IDT, bytes.fromhex("0091" "1000" "00" "8e" "bc00" "03f8ffff" "00000000"))  # -> HANDLER
    space.put(NT_BASE + 0xFC6BC8, DESCRIPTOR.to_bytes(8, "little"))  # MmPhysicalMemoryBlock
    space.put(DESCRIPTOR, len(runs).to_bytes(4, "little") + bytes(4))
    space.put(DESCRIPTOR + 8, (sum(count for _, count in runs) if total is None else total).to_bytes(8, "little"))
    for index, (first, count) in enumerate(runs):
        space.put(DESCRIPTOR + 0x10 + 0x10 * index, first.to_bytes(8, "little") + count.to_bytes(8, "little"))
    return space


def snapshots(*idtrs: dict) -> dict:
    return {str(vp): {"registers": {"vtl0_idtr": idtr}} for vp, idtr in enumerate(idtrs)}


IDTR = {"status": 0, "low": f"0x{0xFFF << 48:016x}", "high": f"0x{VTL0_IDT:016x}"}


class LocateTests(unittest.TestCase):
    def locate(self, space: Space, *idtrs: dict) -> dict:
        return guest_ram.locate(lambda root: space, 0x7D5000, snapshots(*(idtrs or (IDTR,))))

    def test_the_runs_are_read_from_nt_found_through_the_vtl0_idt(self) -> None:
        found = self.locate(k3())
        self.assertEqual(found["kernel_base"], "0xfffff80300000000")
        self.assertEqual(found["pdb"], "ntkrnlmp.pdb C29EBFB06B78B3C020DCA66D99713F9E1")
        self.assertEqual(
            found["runs"],
            [(0x1000, 0xA0000), (0x100000, 0x977000), (0xC70000, 0xF7F41000), (0xF7FC5000, 0xF7FD4000),
             (0xF7FFF000, 0xF8000000), (0x100000000, 0x108000000)],
        )
        self.assertEqual(found["pages"] * 0x1000 // 0x100000, 4091)  # the registry said 4092.0 MiB, rounded

    def test_a_vp_whose_vtl0_idtr_was_not_read_is_passed_over(self) -> None:
        # a failed read whose value would still lead somewhere, so only its status turns it away
        failed = {"status": 0x5, "low": "0x0", "high": f"0x{VTL0_IDT:016x}"}
        found = self.locate(k3(), failed, IDTR)
        self.assertEqual(found["vp"], "1")

    def test_an_nt_build_with_no_entry_names_its_pdb(self) -> None:
        found = self.locate(k3(guid=bytes(16)))
        self.assertNotIn("runs", found)
        self.assertEqual(found["error"], "no MmPhysicalMemoryBlock entry for ntkrnlmp.pdb " + "0" * 32 + "1")

    def test_runs_that_do_not_add_up_are_not_a_map(self) -> None:
        found = self.locate(k3(total=0xFFBF6))
        self.assertIn("do not add up", found["error"])

    def test_overlapping_runs_are_not_a_map(self) -> None:
        found = self.locate(k3(runs=[(0x1, 0x100), (0x80, 0x10)]))
        self.assertIn("overlapping", found["error"])

    def test_no_runs_is_not_a_map(self) -> None:
        self.assertIn("claims 0 runs", self.locate(k3(runs=[]))["error"])

    def test_a_page_the_reader_cannot_read_is_not_skipped_as_unmapped(self) -> None:
        space = k3()
        space.unreadable.add(HANDLER & ~0xFFF)
        found = self.locate(space)
        self.assertIn("unreadable", found["error"])
        self.assertNotIn("runs", found)


class RamTests(unittest.TestCase):
    def test_a_gpa_is_in_ram_up_to_each_runs_end(self) -> None:
        ram = guest_ram.Ram([(0x1000, 0xA0000), (0x100000000, 0x108000000)])
        self.assertEqual(
            [gpa in ram for gpa in (0x0, 0x1000, 0x9F000, 0xA0000, 0xF8000000, 0x100000000, 0x107FFF000, 0x108000000)],
            [False, True, True, False, False, True, True, False],
        )

    def test_the_runs_cross_a_command_line_and_back(self) -> None:
        runs = [(0x1000, 0xA0000), (0x100000000, 0x108000000)]
        self.assertEqual(guest_ram.text(runs), "0x1000-0xA0000,0x100000000-0x108000000")
        self.assertEqual(guest_ram.parse(guest_ram.text(runs)), runs)


if __name__ == "__main__":
    unittest.main()
