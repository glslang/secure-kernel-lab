from __future__ import annotations

import argparse
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from guest_physical import H3Source


MASK_4K = 0x000FFFFFFFFFF000
MASK_2M = 0x000FFFFFFFE00000
MASK_1G = 0x000FFFFFC0000000


def u16(data: bytes, at: int) -> int:
    return struct.unpack_from("<H", data, at)[0]


def u32(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def disk_identity(path: pathlib.Path, selected_breakpoint_rva: int | None = None):
    data = path.read_bytes()
    pe = u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise SystemExit("disk image is not PE")
    sections = u16(data, pe + 6)
    timestamp = u32(data, pe + 8)
    opt_size = u16(data, pe + 20)
    opt = pe + 24
    if u16(data, opt) != 0x20B:
        raise SystemExit("disk image is not PE32+")
    size_of_image = u32(data, opt + 0x38)
    export_rva, export_size = struct.unpack_from("<II", data, opt + 0x70)
    section_table = opt + opt_size

    def rva_to_offset(rva: int) -> int:
        for index in range(sections):
            sec = section_table + index * 40
            virtual_size = u32(data, sec + 8)
            virtual_address = u32(data, sec + 12)
            raw_size = u32(data, sec + 16)
            raw_at = u32(data, sec + 20)
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return raw_at + rva - virtual_address
        if rva < section_table:
            return rva
        raise ValueError(f"RVA 0x{rva:X} is not file-backed")

    exp = rva_to_offset(export_rva)
    function_count = u32(data, exp + 20)
    name_count = u32(data, exp + 24)
    functions = rva_to_offset(u32(data, exp + 28))
    names = rva_to_offset(u32(data, exp + 32))
    ordinals = rva_to_offset(u32(data, exp + 36))
    breakpoint_rva = selected_breakpoint_rva
    if breakpoint_rva is None:
        wanted = b"DbgBreakPointWithStatus"
        for index in range(name_count):
            name_rva = u32(data, names + index * 4)
            name_at = rva_to_offset(name_rva)
            end = data.index(0, name_at)
            if data[name_at:end] == wanted:
                ordinal = u16(data, ordinals + index * 2)
                if ordinal >= function_count:
                    raise SystemExit("export ordinal is outside function table")
                breakpoint_rva = u32(data, functions + ordinal * 4)
                break
    if breakpoint_rva is None:
        raise SystemExit("DbgBreakPointWithStatus export not found")
    bp_at = rva_to_offset(breakpoint_rva)
    return data, timestamp, size_of_image, breakpoint_rva, data[bp_at:bp_at + 8]


class Guest:
    def __init__(self, source: Direct, cr3: int):
        self.source = source
        self.cr3 = cr3 & MASK_4K
        self.pages: dict[int, bytes] = {}

    def physical_page(self, gpa: int) -> bytes:
        page = gpa & ~0xFFF
        if page not in self.pages:
            data, error = self.source.read(page, 0x1000)
            if error or data is None:
                raise KeyError(f"GPA 0x{page:X}: {error}")
            self.pages[page] = data
        return self.pages[page]

    def qword(self, gpa: int) -> int:
        page = self.physical_page(gpa)
        return struct.unpack_from("<Q", page, gpa & 0xFFF)[0]

    def translate(self, va: int) -> int:
        table = self.cr3
        for level, shift in ((4, 39), (3, 30), (2, 21), (1, 12)):
            entry = self.qword(table + (((va >> shift) & 0x1FF) * 8))
            if not entry & 1:
                raise KeyError(f"VA 0x{va:X}: level {level} not present")
            if level == 3 and entry & (1 << 7):
                return (entry & MASK_1G) | (va & ((1 << 30) - 1))
            if level == 2 and entry & (1 << 7):
                return (entry & MASK_2M) | (va & ((1 << 21) - 1))
            table = entry & MASK_4K
        return table | (va & 0xFFF)

    def virtual(self, va: int, size: int) -> bytes:
        out = bytearray()
        while size:
            take = min(size, 0x1000 - (va & 0xFFF))
            gpa = self.translate(va)
            page = self.physical_page(gpa)
            out += page[gpa & 0xFFF:(gpa & 0xFFF) + take]
            va += take
            size -= take
        return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--partition-id", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--vmwp-pid", type=int, required=True)
    ap.add_argument("--partition-handle", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--cr3", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--rip", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--image", type=pathlib.Path, required=True)
    ap.add_argument("--vtl", type=int, choices=(0, 1), default=0)
    ap.add_argument("--breakpoint-rva", type=lambda x: int(x, 0))
    ap.add_argument("--window-mib", type=int, default=64)
    args = ap.parse_args()

    disk, timestamp, image_size, bp_rva, bp_bytes = disk_identity(
        args.image, args.breakpoint_rva
    )
    source = H3Source(args.vmwp_pid, args.partition_handle, args.partition_id)
    guest = Guest(source, args.cr3)
    start = args.rip & ~0xFFF
    stop = start - args.window_mib * 1024 * 1024
    try:
        for base in range(start, stop - 1, -0x1000):
            try:
                head = guest.virtual(base, 0x1000)
            except KeyError:
                continue
            if head[:2] != b"MZ":
                continue
            try:
                pe = u32(head, 0x3C)
                enough = guest.virtual(base, max(0x1000, pe + 0x200))
                if enough[pe:pe + 4] != b"PE\0\0":
                    continue
                live_timestamp = u32(enough, pe + 8)
                live_size = u32(enough, pe + 24 + 0x38)
            except (KeyError, IndexError, struct.error):
                continue
            print(f"candidate base=0x{base:016X} timestamp=0x{live_timestamp:08X} size=0x{live_size:X}")
            if live_timestamp == timestamp and live_size == image_size:
                live_bp = guest.virtual(base + bp_rva, len(bp_bytes))
                print(f"matched_base=0x{base:016X}")
                print(f"dbg_breakpoint_with_status_rva=0x{bp_rva:X}")
                print(f"dbg_breakpoint_with_status_va=0x{base + bp_rva:016X}")
                print(f"disk_bytes={bp_bytes.hex()}")
                print(f"live_bytes={live_bp.hex()}")
                print(f"physical_pages_cached={len(guest.pages)}")
                return 0 if live_bp == bp_bytes else 2
        print("matching image not found", file=sys.stderr)
        return 1
    finally:
        source.close()


if __name__ == "__main__":
    raise SystemExit(main())
