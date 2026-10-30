"""Negative test: the same virtual address resolves to different physical pages in VTL0 and VTL1.

Everything the live-control runs have shown so far is that the Secure Kernel *can* be read. None of
it shows that the normal kernel **cannot**, and without that half "we read protected memory" is an
assertion rather than a result. The claim being tested here is the one that actually matters, and it
is about physical pages rather than virtual ones: VTL1's mapping of an address and VTL0's mapping of
the same address must land on **distinct** GPAs, or VTL0's must not resolve at all. If they landed on
the same page there would be nothing protected about it.

Reads nothing but page tables, arms nothing, and needs no stop: the Secure Kernel is always mapped,
so this works whenever the VM is up. The physical reads go through h3probe's memory operation inside
vmwp (which sees guest physical memory from the host, and is why any of this is possible); the two
roots come from the hypervisor's own register state, VTL0's and VTL1's CR3 for the same VP.

    uv run sklab --target <name> run validate.vtl-split --yes

A four-level walk, guarded against the self-map re-entering the descent.
"""

from __future__ import annotations

import json
import pathlib
import struct
import sys
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_k4_stop_step as k4  # noqa: E402
from h3_vtl1_debug_control import REGISTERS, Probe  # noqa: E402
from guest_physical import GuestVirtual, H3Source, find_secure_kernel_base, vtl1_identity  # noqa: E402

VM_ID = "6b1ed0f6-137e-469f-aeab-a3f4cfee398d"
CACHE = HERE / "k3-sk-syscall" / "discovery-cache.json"
IMAGE: pathlib.Path | None = None

PRESENT = 1 << 0
LARGE = 1 << 7


def vtl_cr3(probe: Probe, partition: int, vtl: int, vp: int = 0) -> int:
    status, low, _high = probe.get(partition, vtl, REGISTERS["cr3"], vp)
    if status != 0:
        raise k4.GateFailure(f"VTL{vtl} CR3 read failed: HV_STATUS 0x{status:04x}")
    return low


def walk(source: Any, root: int, va: int) -> dict[str, Any]:
    """
    Translate one VA through a four-level table, returning the GPA or why it stopped.

    The self-map makes a page-table hierarchy cyclic, so a descent can re-enter it and loop; the
    visited set is that guard rather than caution. Entries are read eight bytes at a time at the
    index being resolved, which is a translation and not a census -- a prefix of a table would be
    the wrong tool for counting entries but is exactly right for following one.
    """
    indices = [(va >> shift) & 0x1FF for shift in (39, 30, 21, 12)]
    table = root & ~0xFFF
    visited: set[int] = set()
    for level, index in enumerate(indices):
        if table in visited:
            return {"resolved": False, "why": f"self-map cycle re-entered at level {4 - level}"}
        visited.add(table)
        entry_gpa = table + index * 8
        raw, why = source.read(entry_gpa, 8)
        if raw is None:
            return {"resolved": False, "why": f"level {4 - level} table page unreadable ({why})"}
        entry, = struct.unpack("<Q", raw)
        if not entry & PRESENT:
            return {"resolved": False, "why": f"not present at level {4 - level}", "entry": f"0x{entry:016x}"}
        if entry & LARGE and level in (1, 2):
            size = 1 << (30 if level == 1 else 21)
            base = entry & ~0xFFF & ~(size - 1)
            return {"resolved": True, "gpa": f"0x{base + (va & (size - 1)):016x}", "page": size}
        table = entry & 0x000F_FFFF_FFFF_F000
    return {"resolved": True, "gpa": f"0x{table + (va & 0xFFF):016x}", "page": 4096}


def main() -> int:
    data = json.loads(CACHE.read_text(encoding="utf-8"))
    partition = int(str(data["partition_id"]), 0)
    pid = int(data["vmwp_pid"])
    handle = int(str(data["partition_handle"]), 0)

    probe = Probe()
    try:
        cr3_vtl0 = vtl_cr3(probe, partition, 0)
        cr3_vtl1 = vtl_cr3(probe, partition, 1)
    finally:
        probe.close()

    source = H3Source(pid, handle, partition)
    try:
        identity = vtl1_identity(partition, 0)
        sk_base, _evidence = find_secure_kernel_base(
            GuestVirtual(source, identity["cr3"]),
            identity["idtr_base"],
            identity["idtr_limit"],
            IMAGE,
        )
        targets = [
            ("securekernel!KiSystemCall64", sk_base + 0xEEEC0),
            ("securekernel!KiBreakpointTrap", sk_base + 0xEB380),
            ("securekernel image base", sk_base),
        ]
        report: dict[str, Any] = {
            "partition_id": f"0x{partition:x}",
            "cr3_vtl0": f"0x{cr3_vtl0:016x}",
            "cr3_vtl1": f"0x{cr3_vtl1:016x}",
            "securekernel_base": f"0x{sk_base:016x}",
            "targets": [],
        }
        print(f"partition 0x{partition:x}   VTL0 CR3 0x{cr3_vtl0:x}   VTL1 CR3 0x{cr3_vtl1:x}")
        print()
        for name, va in targets:
            in_vtl1 = walk(source, cr3_vtl1, va)
            in_vtl0 = walk(source, cr3_vtl0, va)
            same = (
                in_vtl1.get("resolved")
                and in_vtl0.get("resolved")
                and in_vtl1.get("gpa") == in_vtl0.get("gpa")
            )
            row = {"name": name, "va": f"0x{va:016x}", "vtl1": in_vtl1, "vtl0": in_vtl0, "same_page": bool(same)}
            report["targets"].append(row)
            print(f"{name}  va 0x{va:016x}")
            print(f"   VTL1: {in_vtl1}")
            print(f"   VTL0: {in_vtl0}")
            print(f"   -> same physical page: {bool(same)}")
            print()
        protected = [
            r for r in report["targets"] if not r["same_page"] and r["vtl1"].get("resolved")
        ]
        report["verdict"] = (
            "every Secure Kernel address resolved in VTL1 and reached a different page (or none) "
            "in VTL0"
            if len(protected) == len(report["targets"])
            else "AT LEAST ONE ADDRESS SHARED A PHYSICAL PAGE WITH VTL0"
        )
        print(report["verdict"])
        out = HERE / "k3-vtl-split.json"
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("written:", out)
        return 0 if len(protected) == len(report["targets"]) else 1
    finally:
        source.close()


if __name__ == "__main__":
    raise SystemExit(main())
