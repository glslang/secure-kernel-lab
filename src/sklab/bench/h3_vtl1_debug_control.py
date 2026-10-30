"""Private exact-partition VTL1 debug-register controller for the K4 bench gate."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import pathlib
import struct


DEVICE = r"\\.\H3Probe"
IOCTL_H3_RUN = (0x22 << 16) | (0x800 << 2)
IOCTL_H3_CALL = (0x22 << 16) | (0x804 << 2)
HV_CALL_GET_VP_REGISTERS = 0x0050
HV_CALL_SET_VP_REGISTERS = 0x0051

REGISTERS = {
    "explicit_suspend": 0x00000000,
    "rax": 0x00020000,
    "rcx": 0x00020001,
    "rdx": 0x00020002,
    "rbx": 0x00020003,
    "rip": 0x00020010,
    "rflags": 0x00020011,
    "rsp": 0x00020004,
    "rbp": 0x00020005,
    "rsi": 0x00020006,
    "rdi": 0x00020007,
    "r8": 0x00020008,
    "r9": 0x00020009,
    "r10": 0x0002000A,
    "r11": 0x0002000B,
    "r12": 0x0002000C,
    "r13": 0x0002000D,
    "r14": 0x0002000E,
    "r15": 0x0002000F,
    "cr3": 0x00040002,
    "dr0": 0x00050000,
    "dr1": 0x00050001,
    "dr2": 0x00050002,
    "dr3": 0x00050003,
    "dr6": 0x00050004,
    "dr7": 0x00050005,
    "cs": 0x00060001,
    "es": 0x00060000,
    "ss": 0x00060002,
    "ds": 0x00060003,
    "fs": 0x00060004,
    "gs": 0x00060005,
    # HV_X64_TABLE_REGISTER: the limit in bits 48-63 of the low half, the base in the high half.
    "idtr": 0x00070000,
    "vsm_vp_status": 0x000D0003,
}
SNAPSHOT_NAMES = (
    "rip", "rsp", "rflags", "cr3", "cs",
    "dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
)

# `HvGetVpRegisters` input: an `HV_INPUT_GET_VP_REGISTERS` header (partition id, VP index, InputVtl,
# padding) followed by an array of `HV_REGISTER_NAME`. Output: an array of 16-byte `HV_REGISTER_VALUE`.
# The names are spelled out so the batch arithmetic below is not a row of literals.
HEADER_SIZE = 16
NAME_SIZE = 4
VALUE_SIZE = 16
# h3probe's bounded hypercall input block, from `Probe.call`'s own guard.
INPUT_CAP = 64
# Twelve, which is exactly the snapshot's eleven VTL1 registers with room to spare -- so the input
# block is never the limit here. The *output* buffer is, and it is measured rather than assumed.
MAX_NAMES_PER_CALL = (INPUT_CAP - HEADER_SIZE) // NAME_SIZE
# sizeof(H3_CALL_OUT): the driver refuses IOCTL_H3_CALL with STATUS_BUFFER_TOO_SMALL (Win32 122) when
# the output buffer is smaller, however few values the call asks for.
CALL_OUTPUT_MIN = 80


class RepLimit(RuntimeError):
    """The driver's output buffer could not hold the requested number of register values."""


class Probe:
    def __init__(self) -> None:
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k32.CreateFileW.restype = ctypes.c_void_p
        self.k32.DeviceIoControl.argtypes = [
            ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD,
            ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p,
        ]
        self.k32.DeviceIoControl.restype = wt.BOOL
        self.k32.CloseHandle.argtypes = [ctypes.c_void_p]
        self.handle = self.k32.CreateFileW(DEVICE, 0xC0000000, 0, None, 3, 0, None)
        if not self.handle or self.handle == ctypes.c_void_p(-1).value:
            raise RuntimeError(f"cannot open {DEVICE}: Win32 {ctypes.get_last_error()}")

    def close(self) -> None:
        if self.handle:
            self.k32.CloseHandle(ctypes.c_void_p(self.handle))
            self.handle = None

    def ioctl(self, code: int, payload: bytes | None, out_size: int) -> bytes:
        inp = ctypes.create_string_buffer(payload) if payload else None
        out = ctypes.create_string_buffer(out_size)
        returned = wt.DWORD()
        ok = self.k32.DeviceIoControl(
            ctypes.c_void_p(self.handle), code, inp,
            len(payload) if payload else 0, out, out_size,
            ctypes.byref(returned), None,
        )
        if not ok:
            raise RuntimeError(f"DeviceIoControl 0x{code:X}: Win32 {ctypes.get_last_error()}")
        return out.raw[:returned.value]

    def call(self, control: int, block: bytes) -> tuple[int, int, int]:
        if len(block) > 64:
            raise ValueError("hypercall block exceeds h3probe's bounded buffer")
        payload = struct.pack("<QII64s", control, len(block), 0, block.ljust(64, b"\0"))
        raw = self.ioctl(IOCTL_H3_CALL, payload, 80)
        result, = struct.unpack_from("<Q", raw, 0)
        low, high = struct.unpack_from("<QQ", raw, 16)
        return result & 0xFFFF, low, high

    def call_rep(self, control: int, block: bytes, values: int) -> tuple[int, int, list[tuple[int, int]]]:
        """
        One *rep* hypercall, asking for `values` output slots.

        `call` above is the single-rep form: it fixes the output at 80 bytes and reads one 16-byte
        value at offset 16. `HvGetVpRegisters` is a rep hypercall -- a 16-byte header followed by an
        array of 4-byte register names, with the count in bits 32..43 of the input value -- so the
        hypervisor serves many registers per call and this crate was asking for one at a time.

        Two different limits bound a batch, and only one of them is in this file. The **input** block
        is capped at 64 bytes by the driver's bounded buffer, which is twelve names after the header.
        The **output** is whatever `IOCTL_H3_CALL` copies back, and that is the driver's business:
        `call` hardcodes 80 bytes, of which 64 is the value area, so four values. This asks for the
        larger buffer and **measures** whether it was honoured rather than trusting it -- the ioctl
        reports how many bytes came back, so a driver that caps the output is detected instead of
        handing over zero-filled buffer that would read as twelve successful reads of 0.

        Returns the HV status, the number of reps the hypervisor completed (bits 32..43 of the
        result, which says how many values are valid when the status is nonzero), and the values.
        """
        if len(block) > 64:
            raise ValueError("hypercall block exceeds h3probe's bounded buffer")
        want = 16 + values * 16
        payload = struct.pack("<QII64s", control, len(block), 0, block.ljust(64, b"\0"))
        raw = self.ioctl(IOCTL_H3_CALL, payload, max(want, CALL_OUTPUT_MIN))
        if len(raw) < want:
            fits = max(0, (len(raw) - 16) // 16)
            raise RepLimit(
                f"h3probe returned {len(raw)} bytes for {values} register(s), needed {want}: "
                f"its IOCTL_H3_CALL output buffer holds {fits} value(s)"
            )
        result, = struct.unpack_from("<Q", raw, 0)
        reps = (result >> 32) & 0xFFF
        out = [struct.unpack_from("<QQ", raw, 16 + index * 16) for index in range(values)]
        return result & 0xFFFF, reps, out

    def get(self, partition: int, vtl: int, register: int, vp: int = 0) -> tuple[int, int, int]:
        block = struct.pack("<QIBxxxI", partition, vp, (vtl & 0xF) | 0x10, register)
        return self.call(HV_CALL_GET_VP_REGISTERS | (1 << 32), block)

    def set(self, partition: int, vtl: int, register: int, low: int, high: int = 0, vp: int = 0) -> int:
        head = struct.pack("<QIBxxx", partition, vp, (vtl & 0xF) | 0x10)
        assoc = struct.pack("<I12xQQ", register, low, high)
        return self.call(HV_CALL_SET_VP_REGISTERS | (1 << 32), head + assoc)[0]

    def children(self) -> dict[int, int | None]:
        fmt = "<QI I Q I Q I Q I Q"
        size = struct.calcsize(fmt)
        raw = self.ioctl(IOCTL_H3_RUN, None, 16 + 8 * size)
        _, _, count, _ = struct.unpack_from("<IIII", raw, 0)
        result: dict[int, int | None] = {}
        for index in range(count):
            fields = struct.unpack_from(fmt, raw, 16 + index * size)
            result[fields[0]] = (fields[9] & 0xFFFF) if fields[8] == 0 else None
        return result


def read_named(probe: Probe, partition: int, name: str, vp: int = 0) -> dict[str, object]:
    vtl = 0 if name == "vsm_vp_status" else 1
    status, low, high = probe.get(partition, vtl, REGISTERS[name], vp)
    return {"status": status, "low": f"0x{low:016x}", "high": f"0x{high:016x}"}


def low_value(row: dict[str, object]) -> int:
    if row["status"] != 0:
        raise RuntimeError(f"register read failed: HV_STATUS 0x{row['status']:04x}")
    return int(str(row["low"]), 0)


def snapshot(probe: Probe, partition: int, vp: int = 0) -> dict[str, object]:
    rows = {name: read_named(probe, partition, name, vp) for name in SNAPSHOT_NAMES}
    rows["vsm_vp_status"] = read_named(probe, partition, "vsm_vp_status", vp)
    return {"partition_id": f"0x{partition:x}", "vp": vp, "vtl": 1, "registers": rows}


def rep_limit(probe: Probe, partition: int, vp: int = 0, vtl: int = 1) -> int:
    """
    How many register values this driver will return from one `HvGetVpRegisters`, measured.

    Tried largest first and cached on the probe. The candidate is read as the same register
    repeated, which exercises the N-rep path without needing N interesting registers. A candidate
    is accepted only on `HV_STATUS_SUCCESS`: a nonzero status cannot be told apart from a plumbing
    problem here, so it is treated as unsupported and the next size down is tried. Worst case is 1,
    which is what this file did everywhere before `call_rep` existed.
    """
    cached = getattr(probe, "_rep_limit", None)
    if cached is not None:
        return int(cached)
    for candidate in (MAX_NAMES_PER_CALL, 8, 4, 2, 1):
        block = struct.pack("<QIBxxx", partition, vp, (vtl & 0xF) | 0x10)
        block += struct.pack("<I", REGISTERS["rip"]) * candidate
        try:
            status, _, _ = probe.call_rep(
                HV_CALL_GET_VP_REGISTERS | (candidate << 32), block, candidate
            )
        except (RepLimit, RuntimeError, ValueError):
            continue
        if status == 0:
            probe._rep_limit = candidate  # noqa: SLF001 - cache on the handle it was measured for
            return candidate
    raise RuntimeError("h3probe would not serve even a single-register read")


def get_many(
    probe: Probe,
    partition: int,
    vtl: int,
    names: tuple[str, ...],
    vp: int = 0,
    per_call: int | None = None,
) -> dict[str, dict[str, object]]:
    """
    Read several VP registers in as few hypercalls as the driver allows.

    Rows come back in `read_named`'s shape, so this is a drop-in for a loop over it. **All names
    share one `InputVtl`**, because that field is in the one header the batch carries -- so a
    register read at a different VTL (`vsm_vp_status`, which is VTL0) cannot be in the same call and
    needs its own.

    On a nonzero status the hypervisor reports how many reps it completed; the registers before that
    point carry their values and status 0, and the rest carry the failing status. Partial success is
    therefore visible per register rather than collapsing the whole batch.
    """
    size = per_call or rep_limit(probe, partition, vp, vtl)
    rows: dict[str, dict[str, object]] = {}
    for start in range(0, len(names), size):
        chunk = names[start : start + size]
        block = struct.pack("<QIBxxx", partition, vp, (vtl & 0xF) | 0x10)
        block += b"".join(struct.pack("<I", REGISTERS[name]) for name in chunk)
        status, reps, values = probe.call_rep(
            HV_CALL_GET_VP_REGISTERS | (len(chunk) << 32), block, len(chunk)
        )
        for index, name in enumerate(chunk):
            ok = status == 0 or index < reps
            low, high = values[index] if ok else (0, 0)
            rows[name] = {
                "status": 0 if ok else status,
                "low": f"0x{low:016x}",
                "high": f"0x{high:016x}",
            }
    return rows


def snapshot_coherent(probe: Probe, partition: int, vp: int = 0) -> dict[str, object]:
    """
    `snapshot`, in as few hypercalls as the driver allows, with the cost recorded.

    Why it matters: `snapshot` reads twelve registers in twelve separate hypercalls, so on a
    **running** VP the result is twelve different instants -- which is how a `cr3` can disagree with
    the `rip` printed beside it, and why the bench's harnesses suspend the VM before reading rather
    than for any checkpointing reason. Fewer calls means less smear.

    What it does NOT do, so nobody reads more into it than it earns:
      * It is not one atomic read unless the driver serves all eleven VTL1 registers at once, and
        `vsm_vp_status` is **always** a second call because it is read at VTL0 (see `get_many`).
      * It does not say whose address space a `cr3` belongs to. The Secure Kernel is mapped into
        every secure address space, the way the NT kernel is mapped into every process, so a
        coherent read still reports whatever root was live on that VP.
    The `coherence` block records the reads it took, so a claim about smear can cite a number.
    """
    size = rep_limit(probe, partition, vp, 1)
    rows = get_many(probe, partition, 1, SNAPSHOT_NAMES, vp, size)
    rows["vsm_vp_status"] = get_many(probe, partition, 0, ("vsm_vp_status",), vp, 1)[
        "vsm_vp_status"
    ]
    calls = -(-len(SNAPSHOT_NAMES) // size) + 1
    return {
        "partition_id": f"0x{partition:x}",
        "vp": vp,
        "vtl": 1,
        "registers": rows,
        "coherence": {
            "hypercalls": calls,
            "registers_per_call": size,
            "unbatched_hypercalls": len(SNAPSHOT_NAMES) + 1,
            "vsm_vp_status_separate": "read at VTL0; InputVtl is per call",
        },
    }


def guard(probe: Probe, partition: int, expected_cr3: int, vp: int = 0) -> dict[str, object]:
    children = probe.children()
    if children.get(partition) != 3:
        raise RuntimeError(
            f"partition 0x{partition:X} is not the selected VTL0+VTL1 child: {children}"
        )
    row = read_named(probe, partition, "cr3", vp)
    observed = low_value(row)
    if observed != expected_cr3:
        raise RuntimeError(f"CR3 mismatch: got 0x{observed:X}, expected 0x{expected_cr3:X}")
    return row


def write_checked(probe: Probe, partition: int, name: str, value: int, vp: int = 0) -> dict[str, object]:
    status = probe.set(partition, 1, REGISTERS[name], value, vp=vp)
    if status != 0:
        raise RuntimeError(f"set {name}: HV_STATUS 0x{status:04X}")
    row = read_named(probe, partition, name, vp)
    observed = low_value(row)
    if observed != value:
        raise RuntimeError(f"verify {name}: got 0x{observed:X}, expected 0x{value:X}")
    return row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--partition-id", required=True, type=lambda value: int(value, 0))
    ap.add_argument("--expected-cr3", required=True, type=lambda value: int(value, 0))
    ap.add_argument("--vp", type=int, default=0)
    ap.add_argument("--snapshot-out", type=pathlib.Path)
    ap.add_argument("--roundtrip-debug", action="store_true")
    ap.add_argument("--arm-hardware", type=lambda value: int(value, 0))
    ap.add_argument("--arm-step", type=lambda value: int(value, 0))
    ap.add_argument("--restore", type=pathlib.Path)
    args = ap.parse_args()

    probe = Probe()
    try:
        guard(probe, args.partition_id, args.expected_cr3, args.vp)
        before = snapshot(probe, args.partition_id, args.vp)
        result: dict[str, object] = {"before": before, "writes": []}

        if args.snapshot_out:
            args.snapshot_out.write_text(json.dumps(before, indent=2) + "\n", encoding="utf-8")

        if args.roundtrip_debug:
            for name in ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7"):
                value = low_value(before["registers"][name])
                row = write_checked(probe, args.partition_id, name, value, args.vp)
                result["writes"].append({"name": name, "value": f"0x{value:016x}", "readback": row})

        if args.arm_hardware is not None:
            original_dr7 = low_value(before["registers"]["dr7"])
            if original_dr7 & 0xFF:
                raise RuntimeError(f"refusing to replace active guest debug breakpoint: DR7=0x{original_dr7:X}")
            original_flags = low_value(before["registers"]["rflags"])
            original_dr6 = low_value(before["registers"]["dr6"])
            writes = (
                ("dr7", original_dr7 & ~0xFF),
                ("dr0", args.arm_hardware),
                ("dr6", original_dr6 & ~0xE00F),
                ("rip", args.arm_hardware),
                ("rflags", original_flags & ~(0x100 | 0x10000)),
                ("dr7", 0x401),
            )
            for name, value in writes:
                row = write_checked(probe, args.partition_id, name, value, args.vp)
                result["writes"].append({"name": name, "value": f"0x{value:016x}", "readback": row})

        if args.arm_step is not None:
            regs = before["registers"]
            dr7 = low_value(regs["dr7"])
            dr6 = low_value(regs["dr6"])
            flags = low_value(regs["rflags"])
            writes = (
                ("dr7", dr7 & ~0xFF),
                ("dr6", dr6 & ~0xE00F),
                ("rip", args.arm_step),
                ("rflags", (flags | 0x100) & ~0x10000),
            )
            for name, value in writes:
                row = write_checked(probe, args.partition_id, name, value, args.vp)
                result["writes"].append({"name": name, "value": f"0x{value:016x}", "readback": row})

        if args.restore:
            saved = json.loads(args.restore.read_text(encoding="utf-8"))
            if int(saved["partition_id"], 0) != args.partition_id:
                raise RuntimeError("snapshot partition does not match requested partition")
            if int(saved.get("vp", 0)) != args.vp:
                raise RuntimeError("snapshot VP does not match requested VP")
            regs = saved["registers"]
            original = {name: low_value(regs[name]) for name in SNAPSHOT_NAMES}
            writes = (
                ("dr7", original["dr7"] & ~0xFF),
                ("rflags", original["rflags"]),
                ("rip", original["rip"]),
                ("dr0", original["dr0"]),
                ("dr1", original["dr1"]),
                ("dr2", original["dr2"]),
                ("dr3", original["dr3"]),
                ("dr6", original["dr6"]),
                ("dr7", original["dr7"]),
            )
            for name, value in writes:
                row = write_checked(probe, args.partition_id, name, value, args.vp)
                result["writes"].append({"name": name, "value": f"0x{value:016x}", "readback": row})

        result["after"] = snapshot(probe, args.partition_id, args.vp)
        print(json.dumps(result, indent=2))
        return 0
    finally:
        probe.close()


if __name__ == "__main__":
    raise SystemExit(main())
