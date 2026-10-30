"""Gate H3: may the root partition read a child partition's VTL1 registers?

`IOCTL_H3_RUN` asks `h3probe.sys` to enumerate the root's children (`HvCallGetNextChildPartition`)
and, for VP 0 of each, read CR3 at VTL0 (the control), CR3 at VTL1 (the test), and the two VSM status
registers that say independently whether VTL1 exists there at all. The layout below is
`H3_RESULTS`/`H3_VP_RESULT` from `drivers/h3probe/h3probe.c`, which is `#pragma pack(1)`.

Only `HV_STATUS_SUCCESS` is named. Refusals are reported as the raw code: the gate's reading never
depended on decoding one, and an unnamed code is better than a guessed name.
"""

from __future__ import annotations

import struct
from typing import Any


HEADER = struct.Struct("<IIII")
# PartitionId, VpIndex, Vtl0Status, Vtl0Cr3, Vtl1Status, Vtl1Cr3,
# VsmVpStatusStatus, VsmVpStatus, VsmPartStatusStatus, VsmPartitionStatus
CHILD = struct.Struct("<QIIQIQIQIQ")
SLOTS = 8
RESULT_SIZE = HEADER.size + SLOTS * CHILD.size

VTL1 = 1 << 1


def _status(code: int) -> str:
    return "success" if code == 0 else f"0x{code:04x}"


def verdict(child: dict[str, Any]) -> str:
    """The H3 reading for one child, in the order the gate's controls make it meaningful."""
    if child["vtl0"]["status"] != "success":
        # Both VTLs refused is a statement about privilege or plumbing, not about VTL1.
        return "control-failed"
    partition = child["vsm_partition_status"]
    has_vtl1 = None if partition["status"] != "success" else bool(partition["enabled_vtl_set"] & VTL1)
    read = child["vtl1"]["status"] == "success"
    if has_vtl1 is False:
        return "unexpected" if read else "no-vtl1"
    if not read:
        return "refused"
    if child["vtl1"]["cr3"] == child["vtl0"]["cr3"]:
        return "same-cr3"
    return "granted" if has_vtl1 else "granted-unconfirmed"


def parse(raw: bytes) -> dict[str, Any]:
    if len(raw) < HEADER.size:
        raise ValueError(f"H3 result is {len(raw)} bytes, shorter than its {HEADER.size}-byte header")
    version, enum_status, count, _reserved = HEADER.unpack_from(raw, 0)
    if count > SLOTS:
        raise ValueError(f"H3 result claims {count} children; the driver has {SLOTS} slots")
    if len(raw) < HEADER.size + count * CHILD.size:
        raise ValueError(f"H3 result is {len(raw)} bytes, too short for {count} children")
    children = []
    for index in range(count):
        (
            partition,
            vp,
            vtl0_status,
            vtl0_cr3,
            vtl1_status,
            vtl1_cr3,
            vp_status_status,
            vp_status,
            partition_status_status,
            partition_status,
        ) = CHILD.unpack_from(raw, HEADER.size + index * CHILD.size)
        child = {
            "partition_id": f"0x{partition:x}",
            "vp": vp,
            "vtl0": {"status": _status(vtl0_status), "cr3": f"0x{vtl0_cr3:x}"},
            "vtl1": {"status": _status(vtl1_status), "cr3": f"0x{vtl1_cr3:x}"},
            # HV_REGISTER_VSM_VP_STATUS: ActiveVtl:4, ActiveMbecEnabled:1, Reserved:3, EnabledVtlSet:16
            "vsm_vp_status": {
                "status": _status(vp_status_status),
                "raw": f"0x{vp_status:x}",
                "active_vtl": vp_status & 0xF,
                "enabled_vtl_set": (vp_status >> 8) & 0xFFFF,
            },
            # HV_REGISTER_VSM_PARTITION_STATUS: EnabledVtlSet:16, MaximumVtl:4, MbecEnabledVtlSet:16
            "vsm_partition_status": {
                "status": _status(partition_status_status),
                "raw": f"0x{partition_status:x}",
                "enabled_vtl_set": partition_status & 0xFFFF,
                "maximum_vtl": (partition_status >> 16) & 0xF,
            },
        }
        child["verdict"] = verdict(child)
        children.append(child)
    return {"version": version, "enum_status": _status(enum_status), "children": children}


def rows(gate: dict[str, Any], target_partition: str | None = None) -> list[dict[str, Any]]:
    """The gate as a table, one line per child, in the shape the feasibility doc printed it."""

    def cr3(read: dict[str, Any]) -> str:
        return read["cr3"] if read["status"] == "success" else f"refused {read['status']}"

    result = []
    for child in gate["children"]:
        partition = child["vsm_partition_status"]
        known = partition["status"] == "success"
        result.append(
            {
                "partition": child["partition_id"],
                "vtl0 cr3": cr3(child["vtl0"]),
                "vtl1 cr3": cr3(child["vtl1"]),
                "vtl set": f"0x{partition['enabled_vtl_set']:04x}" if known else "?",
                "max vtl": partition["maximum_vtl"] if known else "?",
                "verdict": child["verdict"],
                "target": "<- target" if child["partition_id"] == target_partition else "",
            }
        )
    return result
