"""The guest's own record of its RAM, read from NT through a VTL0 root.

Before the h3probe-only migration, hvmm answered a GPA that lies in none of the VM's memory blocks --
the device gap, past the end of RAM -- with a page of zeros and success, so a reader could not tell that from a page of
zeros. NT knows which GPAs are RAM: `MmPhysicalMemoryBlock` points to a `_PHYSICAL_MEMORY_DESCRIPTOR`
listing the runs it was given, and the guest's registry map of physical memory is written from it.
On K3 on 2026-10-17 the runs read here equalled that registry map, six runs, and the Secure Kernel's
image and root lay inside them.

**The runs are the RAM NT owns, not all the memory behind the partition.** On the same boot three of
the four holes below the device gap held data through hvmm: 57 of 761 pages at `0x977000`, 97 of 132
at `0xF7F41000` and 40 of 43 at `0xF7FD4000`, which looks like firmware's. So a page of zeros
outside the runs is either no RAM, as at `0xFEE00000` or past the end, or a zero page of memory NT
does not own, and the runs cannot say which; the hypervisor can (`sklab.backing`), and on a later
boot it called every zero page sampled from all four holes, `0xA0000` included, memory. The runs
decide only which pages to ask about. hvmm's other memory routine, code `0x2220D4`, does
look the GPA up and fail when nothing backs it, but it is a write -- it copies the caller's buffer
into the guest page -- so it is no way to ask.

NT is found the way the Secure Kernel is (`modules/core.py`): vector 0 of a VP's VTL0 IDT points into
ntoskrnl, and the nearest PE header at or below it is the image's base. The build is identified by
the PDB signature in its own debug directory, read from guest memory, and only a build with an entry
in `LAYOUTS` is read. The table holds an RVA per PDB signature rather than a symbol lookup at run
time, as `sk_processes` holds offsets per securekernel.exe build.
"""

from __future__ import annotations

import bisect
from typing import Any, Callable

from .sk_processes import UnreadablePage
from .util import pe_identity


# ntkrnlmp.pdb signature, as a symbol server names it (GUID, then age) -> RVA of MmPhysicalMemoryBlock.
# Read from the PDB with the debugger kit's DbgHelp on 2026-10-17. That PDB was fetched on 2026-09-29
# beside the securekernel.pdb whose signature the pinned K3 Secure Kernel carries.
LAYOUTS = {"C29EBFB06B78B3C020DCA66D99713F9E1": 0xFC6BC8}
# _PHYSICAL_MEMORY_DESCRIPTOR and _PHYSICAL_MEMORY_RUN, from the same PDB
NUMBER_OF_RUNS, NUMBER_OF_PAGES, RUNS, RUN_SIZE = 0x0, 0x8, 0x10, 0x10
MAX_RUNS = 128  # far above any guest's; a count past it is not a descriptor
PAGE = 0x1000
IDT_GATE = 16
DEBUG_DIRECTORY = 6  # IMAGE_DIRECTORY_ENTRY_DEBUG
CODEVIEW = 2  # IMAGE_DEBUG_TYPE_CODEVIEW
# ntoskrnl's vector 0 handlers sit 6.7 MiB (KiDivideErrorFault) and 11.8 MiB (its KVA Shadow copy)
# into the K3 build, so the walk down to the base may pass thousands of pages.
KERNEL_PAGES = 0x2000


def _int(root: Any, va: int, size: int) -> int:
    return int.from_bytes(root.virtual(va, size), "little")


def idt_handler(gate: bytes) -> int:
    """The handler an x64 interrupt gate points at: offset bits 0-15, 16-31 and 32-63."""
    return (
        int.from_bytes(gate[0:2], "little")
        | int.from_bytes(gate[6:8], "little") << 16
        | int.from_bytes(gate[8:12], "little") << 32
    )


def image_base_below(root: Any, address: int, pages: int) -> int | None:
    """The nearest page at or below `address` that starts with PE headers, looking at most `pages`
    pages down. A page the root does not map, such as a discarded section, is skipped; a page the
    reader could not read stops the walk, since it says nothing about what is there."""
    page = address & ~(PAGE - 1)
    for _ in range(pages):
        try:
            if pe_identity(root.virtual(page, PAGE)) is not None:
                return page
        except UnreadablePage:
            raise
        except KeyError:  # not mapped through this root
            pass
        page -= PAGE
    return None


def codeview(root: Any, base: int) -> tuple[str, str] | None:
    """The PDB signature and name an image in guest memory records for itself, or None."""
    header = root.virtual(base, PAGE)
    pe = int.from_bytes(header[0x3C:0x40], "little")
    optional = pe + 24
    if header[pe : pe + 4] != b"PE\0\0" or int.from_bytes(header[optional : optional + 2], "little") != 0x20B:
        return None
    entry = optional + 112 + DEBUG_DIRECTORY * 8  # PE32+ data directories
    directory = int.from_bytes(header[entry : entry + 4], "little")
    size = int.from_bytes(header[entry + 4 : entry + 8], "little")
    for index in range(min(size // 28, 16)):  # IMAGE_DEBUG_DIRECTORY, 28 bytes each
        record = root.virtual(base + directory + 28 * index, 28)
        if int.from_bytes(record[12:16], "little") != CODEVIEW:
            continue
        data = root.virtual(base + int.from_bytes(record[20:24], "little"), min(int.from_bytes(record[16:20], "little"), 0x120))
        if data[0:4] != b"RSDS":
            return None
        guid = data[4:20]
        key = (
            f"{int.from_bytes(guid[0:4], 'little'):08X}{int.from_bytes(guid[4:6], 'little'):04X}"
            f"{int.from_bytes(guid[6:8], 'little'):04X}{guid[8:16].hex().upper()}{int.from_bytes(data[20:24], 'little'):X}"
        )
        return key, data[24:].split(b"\0", 1)[0].decode("ascii", errors="replace")
    return None


def ram_runs(root: Any, base: int, rva: int) -> list[tuple[int, int]]:
    """NT's RAM runs as `(first GPA, end GPA)`, end exclusive. Raises ValueError for a descriptor that
    does not hold together: a run count out of range, runs out of order or overlapping, or a page
    total that is not the sum of the runs."""
    descriptor = _int(root, base + rva, 8)
    count = _int(root, descriptor + NUMBER_OF_RUNS, 4)
    total = _int(root, descriptor + NUMBER_OF_PAGES, 8)
    if not 0 < count <= MAX_RUNS:
        raise ValueError(f"MmPhysicalMemoryBlock at 0x{descriptor:X} claims {count} runs")
    raw = root.virtual(descriptor + RUNS, count * RUN_SIZE)
    runs, end = [], 0
    for index in range(count):
        first = int.from_bytes(raw[index * RUN_SIZE : index * RUN_SIZE + 8], "little")
        pages = int.from_bytes(raw[index * RUN_SIZE + 8 : index * RUN_SIZE + 16], "little")
        if pages == 0 or first < end:
            raise ValueError(f"MmPhysicalMemoryBlock run {index} (page 0x{first:X}, 0x{pages:X} pages) is empty, out of order or overlapping")
        runs.append((first * PAGE, (first + pages) * PAGE))
        end = first + pages
    if sum((last - first) // PAGE for first, last in runs) != total:
        raise ValueError(f"MmPhysicalMemoryBlock's runs do not add up to its total of 0x{total:X} pages")
    return runs


def locate(open_root: Callable[[int], Any], vtl0_root: int, snapshots: dict[str, Any]) -> dict[str, Any]:
    """The guest's RAM runs, from the first VP whose VTL0 IDT leads to an NT build with an entry here.

    Returns `runs` on success, and `error` otherwise, with what was found on the way, so an unknown
    build names the PDB signature an entry would need.
    """
    root = open_root(vtl0_root)
    attempts: dict[str, str] = {}
    for vp, snapshot in snapshots.items():
        idtr = snapshot["registers"].get("vtl0_idtr")
        if idtr is None or idtr["status"] != 0:
            attempts[vp] = f"VTL0 IDTR not read: {idtr}"
            continue
        try:
            handler = idt_handler(root.virtual(int(str(idtr["high"]), 0), IDT_GATE))
            base = image_base_below(root, handler, KERNEL_PAGES)
            signature = codeview(root, base) if base is not None else None
        except KeyError as error:  # a page not mapped, or one the reader could not read
            attempts[vp] = str(error)
            continue
        if base is None:
            attempts[vp] = f"no PE headers within 0x{KERNEL_PAGES:X} pages below VTL0 vector 0's handler 0x{handler:X}"
            continue
        if signature is None:
            return {"kernel_base": hex(base), "error": "the image below VTL0 vector 0's handler records no PDB signature"}
        key, name = signature
        found = {"kernel_base": hex(base), "pdb": f"{name} {key}"}
        rva = LAYOUTS.get(key)
        if rva is None:
            return {**found, "error": f"no MmPhysicalMemoryBlock entry for {name} {key}"}
        try:
            runs = ram_runs(root, base, rva)
        except (KeyError, ValueError) as error:
            return {**found, "error": str(error)}
        return {"vp": vp, **found, "runs": runs, "pages": sum((last - first) // PAGE for first, last in runs)}
    return {"error": f"NT was not found from any VP's VTL0 IDT: {attempts}"}


class Ram:
    """Whether a GPA is in the guest's RAM runs, by bisection over their starts."""

    def __init__(self, runs: list[tuple[int, int]]) -> None:
        self.runs = runs
        self.starts = [first for first, _ in runs]

    def __contains__(self, gpa: int) -> bool:
        index = bisect.bisect_right(self.starts, gpa) - 1
        return index >= 0 and gpa < self.runs[index][1]


def text(runs: list[tuple[int, int]]) -> str:
    """The runs as one command-line argument: `first-end` in hex, end exclusive, comma-separated."""
    return ",".join(f"0x{first:X}-0x{last:X}" for first, last in runs)


def parse(argument: str) -> list[tuple[int, int]]:
    runs = []
    for part in argument.split(","):
        first, last = part.split("-")
        runs.append((int(first, 16), int(last, 16)))
    return runs
