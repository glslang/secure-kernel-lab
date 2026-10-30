from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
from typing import Any

from .. import backing, bench_bridge, drivers, h3_memory, h3_memory_probe, h3_migration, m8
from ..context import RunContext
from ..doctor import passed, run as doctor
from ..errors import ExecutionFailure, PrerequisiteError, RecoveryRequired
from ..mcp import McpClient
from ..policy import control_transport, live_transport, write_policy
from ..util import atomic_json, module_loaded, pe_identity, temporary_environment
from .spec import ModuleSpec


def _checks(ctx: RunContext, _options: dict[str, Any]) -> list[dict[str, Any]]:
    return doctor(ctx.config, ctx.target)


def _require(ctx: RunContext, options: dict[str, Any]) -> None:
    checks = _checks(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("advanced workflow prerequisites failed")
    ctx.require_disposable()


def _write_checks(ctx: RunContext, _options: dict[str, Any]) -> list[dict[str, Any]]:
    # This proof owns the full boot and driver lifecycle, so stopped drivers are informational here.
    return doctor(
        ctx.config,
        ctx.target,
        required={"administrator", "mcp", "repo", "profile", "image", "identity", "disposable"},
    )


def _read_exact(reader: Any, gpa: int, size: int) -> bytes:
    data, failure = reader.read(gpa, size)
    if data is None or failure is not None:
        raise ExecutionFailure(f"read at 0x{gpa:x} failed: {failure}")
    return data


def _memory_provider(pid: int, handle: int, partition: int) -> tuple[Any, Any, list[Any]]:
    """A reader and a writer over h3probe's memory operation, and what must be closed after them."""
    device = h3_memory.Device()
    return (
        h3_memory.Reader(device, pid, handle, partition),
        h3_memory.Writer(device, pid, handle, partition),
        [device],
    )


def memory_write_restore(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    """Prove a raw VTL1 write, exact readback, restoration, and guest survival without hvlib.

    Through h3probe's memory operation, which applies a write as read, patch, write and full-page
    read-back: pause the exact disposable VM, hash the page, change one reserved Secure Kernel
    PE-header byte, prove it is the page's only delta, restore it, hash the restored page, and resume
    only after that is proved; otherwise the VM is forced off without resuming. Then the same boot
    is audited. This was `validate.hvmm-write` before the h3probe-only migration.
    """
    checks = _write_checks(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("memory write proof prerequisites failed")
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    ctx.confirm(
        f"Write one reserved Secure Kernel PE-header byte in {target.vm_name} through h3probe, "
        "verify it, and restore it?"
    )

    runner, configured = bench_bridge.configure_runner(ctx, "run_k3_sk_live")
    k4 = runner.k4
    h3 = configured["h3"]
    memory = bench_bridge._module("guest_physical")
    report = ctx.run_dir / "memory-write-proof.json"
    result: dict[str, Any] = {
        "schema": "secure-kernel-lab.memory-write-proof.v1",
        "provider": "h3",
        "vm_id": target.vm_id,
        "vm_name": target.vm_name,
        "target": "securekernel.exe IMAGE_DOS_HEADER.e_res2[0]",
        "target_rva": "0x30",
        "hvlib_loaded_before": module_loaded("hvlib.dll"),
        "restored": False,
    }
    state = drivers.status(ctx.config.drivers.h3probe_service)
    result["driver"] = {
        "state_before": state.state,
        "sha256": _sha256_file(state.image) if state.image is not None else None,
    }
    if result["hvlib_loaded_before"]:
        raise ExecutionFailure("hvlib.dll was already loaded before the no-hvlib write proof")

    booted = paused = write_started = restored = False
    closers: list[Any] = []
    probe = None
    reader: Any = None
    writer: Any = None
    original_page: bytes | None = None
    page_gpa: int | None = None
    byte_gpa: int | None = None
    pid = 0
    if k4.vm_state() != "Off":
        raise PrerequisiteError(f"{target.vm_name} must be Off before the write proof boots it")
    try:
        try:
            pid, uptime = k4.start_bench()
        finally:
            booted = k4.vm_state() != "Off"
        vnd, source_handle, partition, how = runner.discovery(pid)
        result["boot"] = {"vmwp_pid": pid, "uptime_seconds": uptime}
        result["identity"] = {
            "dispatcher_vnd": hex(vnd),
            "partition_handle": hex(source_handle),
            "partition_id": hex(partition),
            "discovery": how,
        }
        probe = h3.Probe()
        result["state_before"] = h3.snapshot_coherent(probe, partition, target.vp)
        result["health_before"] = k4.health(pid, "before-memory-write")

        k4.pause_vm()
        paused = True
        reader, writer, closers = _memory_provider(pid, source_handle, partition)
        vtl1 = memory.vtl1_identity(partition, target.vp)
        guest = memory.GuestVirtual(reader, int(vtl1["cr3"]))
        base, base_evidence = memory.find_secure_kernel_base(
            guest,
            int(vtl1["idtr_base"]),
            int(vtl1["idtr_limit"]),
            target.secure_kernel_image,
        )
        target_va = base + 0x30
        byte_gpa = guest.translate(target_va)
        page_gpa = byte_gpa & ~(h3_memory.PAGE - 1)

        original_page = _read_exact(reader, page_gpa, h3_memory.PAGE)
        offset = byte_gpa - page_gpa
        original = original_page[offset : offset + 1]
        changed = bytes([original[0] ^ 1])
        result["identity"].update(
            cr3=hex(int(vtl1["cr3"])),
            idtr_base=hex(int(vtl1["idtr_base"])),
            idtr_limit=hex(int(vtl1["idtr_limit"])),
            secure_kernel_base=hex(base),
            base_discovery=base_evidence,
            target_va=hex(target_va),
            target_gpa=hex(byte_gpa),
        )
        result["original"] = {
            "byte": original.hex(),
            "page_sha256": hashlib.sha256(original_page).hexdigest(),
        }
        atomic_json(report, result)

        write_started = True
        written, failure = writer.write(byte_gpa, changed)
        if failure is not None or written != 1:
            raise RecoveryRequired(f"the write completed {written} of 1 bytes: {failure or 'short write'}")
        changed_page = _read_exact(reader, page_gpa, h3_memory.PAGE)
        deltas = [index for index, pair in enumerate(zip(original_page, changed_page)) if pair[0] != pair[1]]
        if deltas != [offset] or changed_page[offset : offset + 1] != changed:
            raise RecoveryRequired(f"write readback changed offsets {deltas[:16]}, expected only 0x{offset:x}")
        result["write"] = {
            "byte": changed.hex(),
            "changed_offsets": [hex(index) for index in deltas],
            "page_sha256": hashlib.sha256(changed_page).hexdigest(),
            "writer_calls": writer.calls,
        }
        atomic_json(report, result)

        written, failure = writer.write(byte_gpa, original)
        if failure is not None or written != 1:
            raise RecoveryRequired(f"the restoration completed {written} of 1 bytes: {failure or 'short write'}")
        restored_page = _read_exact(reader, page_gpa, h3_memory.PAGE)
        if restored_page != original_page:
            raise RecoveryRequired("the complete 4 KiB page did not match after restoration")
        restored = True
        result["restored"] = True
        result["restoration"] = {
            "byte": restored_page[offset : offset + 1].hex(),
            "page_sha256": hashlib.sha256(restored_page).hexdigest(),
            "matches_original_page": True,
        }
        result["hvlib_loaded_after"] = module_loaded("hvlib.dll")
        if result["hvlib_loaded_after"]:
            raise ExecutionFailure("hvlib.dll was loaded during the no-hvlib write proof")
        atomic_json(report, result)
    finally:
        if write_started and not restored and writer is not None and reader is not None:
            try:
                if k4.vm_state() == "Running":
                    k4.pause_vm()
                    paused = True
                if original_page is not None and page_gpa is not None and byte_gpa is not None:
                    original = original_page[byte_gpa - page_gpa : byte_gpa - page_gpa + 1]
                    for _attempt in range(3):
                        writer.write(byte_gpa, original)
                        if _read_exact(reader, page_gpa, h3_memory.PAGE) == original_page:
                            restored = True
                            result["restored"] = True
                            result["emergency_restoration"] = "verified"
                            break
            except Exception as error:
                result["emergency_restoration_error"] = str(error)
        for resource in closers:
            try:
                resource.close()
            except Exception as error:
                result.setdefault("close_errors", []).append(str(error))
        if booted:
            if write_started and not restored:
                if probe is not None:
                    probe.close()
                k4.ps(
                    f"$v=Get-VM -Id '{target.vm_id}' -ErrorAction Stop; "
                    "Stop-VM -VM $v -TurnOff -Force -ErrorAction Stop; "
                    "foreach($n in @('h3probe')){$s=Get-Service -Name $n -ErrorAction SilentlyContinue;"
                    "if($s -and $s.Status -ne 'Stopped'){Stop-Service -Name $n -ErrorAction Stop}}"
                )
                atomic_json(report, result)
                raise RecoveryRequired(
                    "the original page could not be verified; the disposable VM was forced off without resuming"
                )
            if paused and k4.vm_state() == "Paused":
                k4.resume_vm()
                paused = False
            try:
                if restored and probe is not None:
                    time.sleep(60)
                    result["state_after"] = h3.snapshot_coherent(probe, partition, target.vp)
                    result["health"] = k4.health(pid, "after-memory-write-restore-60s")
                    result["driver_after"] = drivers.status(ctx.config.drivers.h3probe_service).state
            finally:
                if probe is not None:
                    probe.close()
                result.update(_stop_read_only_target(k4, target.vm_id))
            booted = False

    before = result["state_before"]["registers"]
    after = result["state_after"]["registers"]
    audited = ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")
    result["audit"] = {
        "same_boot": result["health"]["pid"] == pid,
        "debug_registers_unchanged": all(before[name] == after[name] for name in audited),
        "trap_flag_clear": not int(str(after["rflags"]["low"]), 0) & (1 << 8),
    }
    result["result"] = "pass" if all(result["audit"].values()) else "fail"
    atomic_json(report, result)
    if result["result"] != "pass":
        raise ExecutionFailure(f"post-write audit failed: {result['audit']}")
    return {"report": str(report), **result}


def _stop_read_only_target(k4: Any, vm_id: str) -> dict[str, Any]:
    """Return a target nothing wrote to Off, gracefully whenever the guest will answer.

    A turn-off while the guest is still booting counts as a failed boot, and two of those leave K3
    in the recovery environment, where nothing answers and the next run cannot boot it. So a guest
    that refuses a graceful shutdown is given time to reach a heartbeat first, and is forced off
    only if it never does.
    """
    record: dict[str, Any] = {}
    try:
        record["cleanup"] = k4.stop_bench()
        return record
    except Exception as error:
        record["cleanup_error"] = str(error)
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        vm = k4.vm_json()
        if vm["State"] == "Off":
            break
        if vm["State"] == "Running" and vm.get("Heartbeat") == "OK":
            try:
                record["cleanup"] = k4.stop_bench()
                return record
            except Exception as error:
                record["cleanup_retry_error"] = str(error)
                break
        time.sleep(5)
    k4.ps(
        f"$v=Get-VM -Id '{vm_id}' -ErrorAction Stop; "
        "if($v.State -ne 'Off'){Stop-VM -VM $v -TurnOff -Force -ErrorAction Stop}; "
        "foreach($n in @('h3probe')){$s=Get-Service -Name $n -ErrorAction SilentlyContinue;"
        "if($s -and $s.Status -ne 'Stopped'){Stop-Service -Name $n -ErrorAction Stop}}"
    )
    record["cleanup_forced_off"] = k4.vm_json()
    return record


def _sha256_file(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper() if path.is_file() else None


def _h3_corpus(
    ctx: RunContext,
    k4: Any,
    h3: Any,
    memory: Any,
    probe: Any,
    pid: int,
    handle: int,
    partition: int,
    map_step: int,
    result: dict[str, Any],
    report: Path,
) -> tuple[dict[str, int], dict[str, int], list[dict[str, Any]]]:
    """The paused target's corpus pages, controls and VID range map, recorded into `result`.

    The Secure Kernel pages come from its live IDT, read through h3probe's memory operation, and
    finding them is itself a check: the base is accepted only where the page read there carries the
    pinned image's PE identity. The edges of RAM come from VID's own ranges, mapped through h3probe's
    translate probe, and are read rather than assumed: K3 went from 4 GiB to 8 GiB under an end of RAM
    once written in as a constant.
    """
    target = ctx.target
    assert target is not None
    vtl1 = memory.vtl1_identity(partition, target.vp)
    source = memory.H3Source(pid, handle, partition)
    try:
        guest = memory.GuestVirtual(source, int(vtl1["cr3"]))
        base, base_evidence = memory.find_secure_kernel_base(
            guest,
            int(vtl1["idtr_base"]),
            int(vtl1["idtr_limit"]),
            target.secure_kernel_image,
        )
        handler_va = int(str(base_evidence["handler"]), 0)
        code_page = guest.translate(handler_va) & ~0xFFF
        header_page = guest.translate(base) & ~0xFFF
    finally:
        source.close()

    configured = int(k4.ps(f"(Get-VM -Id '{target.vm_id}' -ErrorAction Stop).MemoryStartup"))
    limit = configured + 0x140000000  # the RAM, a gap of at most 4 GiB, and 1 GiB
    started = time.monotonic()
    runs = h3_migration.range_map(
        lambda gpn: h3_memory_probe.translate(probe, pid, handle, gpn << 12),
        limit >> 12,
        map_step,
    )
    ram_runs = [run for run in runs if run["kind"] == "memory-block"]
    end_of_ram = max((int(run["end"], 16) for run in ram_runs), default=0)
    gaps = [
        int(run["start"], 16)
        for run in runs
        if run["kind"] == "none" and int(run["start"], 16) < 0x100000000
    ]
    result["vid_ranges"] = {
        "limit": hex(limit),
        "step_pages": hex(map_step),
        "dense_below": "0x100000",
        "configured_memory": hex(configured),
        "ram_bytes": hex(sum(run["pages"] for run in ram_runs) << 12),
        "end_of_ram": hex(end_of_ram),
        "seconds": round(time.monotonic() - started, 3),
        "runs": runs,
    }
    atomic_json(report, result)
    if not ram_runs or end_of_ram >= limit:
        raise ExecutionFailure(f"VID's RAM reaches the map's limit 0x{limit:x}, so its end is unseen")
    if not gaps:
        raise ExecutionFailure("VID reports no range-free gap below 4 GiB to stand for the device gap")

    addresses = {
        "mapped_code": code_page,
        "mapped_data": int(vtl1["cr3"]) & ~0xFFF,
        # Page 0: the hypervisor accepts it and it holds zeros (sklab.backing).
        "mapped_zero": 0,
        # Inside the legacy hole NT leaves out of its runs, measured backed on K3.
        "ram_hole": 0xA0000,
        "device_gap": gaps[0],
        "end_of_ram": end_of_ram,
        # The page that exposed hvlib's open-time 4 GiB bound, before the migration.
        "above_4gib": 0x107FFF000,
    }

    status, vtl0_cr3, _ = probe.get(partition, 0, h3.REGISTERS["cr3"], target.vp)
    if status != 0:
        raise ExecutionFailure(f"VTL0 CR3 positive control failed: HV_STATUS 0x{status:04x}")
    controls = {
        "vtl0_positive_control": vtl0_cr3 & ~0xFFF,
        "secure_kernel_header": header_page,
        "last_ram_page": end_of_ram - 0x1000,
        "local_apic": 0xFEE00000,
        "far_above_ram": end_of_ram + 0x100000000,
    }
    result["addresses"] = {name: hex(gpa) for name, gpa in {**addresses, **controls}.items()}
    result["addresses"].update(
        secure_kernel_base=hex(base),
        secure_kernel_handler=hex(handler_va),
    )
    result["base_discovery"] = base_evidence
    result["pinned_image"] = {
        key: f"0x{value:x}" for key, value in memory.disk_pe_identity(target.secure_kernel_image).items()
    }
    return addresses, controls, runs


_H3_READ_LOOP = """
import sys
from sklab import h3_memory
device = h3_memory.Device()
reader = h3_memory.Reader(device, int(sys.argv[1]), int(sys.argv[2], 0), int(sys.argv[3], 0))
reads = 0
while True:
    data, failure = reader.read(int(sys.argv[4], 0), h3_memory.PAGE)
    if failure is not None:
        print("FAIL", failure, flush=True)
        raise SystemExit(1)
    reads += 1
    if reads == 1:
        print("READY", flush=True)
"""


def _h3_page(reader: h3_memory.Reader, gpa: int) -> tuple[bytes | None, dict[str, Any]]:
    data, answer, failure = reader.chunk(gpa, h3_memory.PAGE)
    record: dict[str, Any] = {
        "result": answer.result if answer is not None else "call-failed",
        "stage": answer.stage if answer is not None else None,
        "status": f"0x{answer.status:08x}" if answer is not None else None,
        "failure": failure,
        "all_zero": data == bytes(h3_memory.PAGE) if data is not None else None,
        "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
    }
    return data, record


def _h3_refusals(device: Any, pid: int, handle: int, partition: int, gpa: int) -> dict[str, Any]:
    """What the driver itself answers to requests it must not serve. Read requests only."""
    request = h3_memory.REQUEST

    def ask(payload: bytes, out_size: int) -> dict[str, Any]:
        try:
            raw = device.ioctl(h3_memory.IOCTL_H3_MEMREAD, payload, out_size)
            answer = h3_memory.parse_answer(raw, 8)
        except (OSError, ValueError) as error:
            return {"refused_by": "call", "detail": str(error)}
        data = raw[h3_memory.ANSWER.size :]
        return {
            "refused_by": "answer",
            "result": answer.result,
            "stage": answer.stage,
            "status": f"0x{answer.status:08x}",
            "data_zero": data == bytes(len(data)),
        }

    cases: dict[str, tuple[bytes, int, set[str]]] = {
        "wrong_partition": (request.pack(1, pid, handle, partition + 1, gpa, 8, 0), 0, {"identity/partition"}),
        "missing_process": (request.pack(1, 0xFFFFFFFC, handle, partition, gpa, 8, 0), 0, {"identity/process"}),
        "other_process": (request.pack(1, os.getpid(), handle, partition, gpa, 8, 0), 0, {"identity/handle", "identity/owner"}),
        "bad_handle": (request.pack(1, pid, 0xFFFFFC, partition, gpa, 8, 0), 0, {"identity/handle"}),
        "kernel_handle": (request.pack(1, pid, 0xFFFFFFFF80000004, partition, gpa, 8, 0), 0, {"identity/handle"}),
        "cross_page": (request.pack(1, pid, handle, partition, gpa | 0xFFF, 2, 0), 0, {"error/request"}),
        "oversized": (request.pack(1, pid, handle, partition, gpa, 0x1001, 0), 0, {"error/request"}),
        "empty": (request.pack(1, pid, handle, partition, gpa, 0, 0), 0, {"error/request"}),
        "bad_version": (request.pack(2, pid, handle, partition, gpa, 8, 0), 0, {"error/request"}),
        "reserved_set": (request.pack(1, pid, handle, partition, gpa, 8, 1), 0, {"error/request"}),
        "short_input": (request.pack(1, pid, handle, partition, gpa, 8, 0)[:-1], 0, {"call"}),
        "short_output": (request.pack(1, pid, handle, partition, gpa, 8, 0), h3_memory.ANSWER.size, {"call"}),
    }
    refusals: dict[str, Any] = {}
    for name, (payload, out_size, expected) in cases.items():
        got = ask(payload, out_size or h3_memory.READ_OUTPUT_SIZE)
        key = "call" if got["refused_by"] == "call" else f"{got['result']}/{got['stage']}"
        got["expected"] = sorted(expected)
        got["passed"] = key in expected and got.get("data_zero", True)
        refusals[name] = got
    return refusals


def _private_bytes(k4: Any, pid: int) -> int:
    return int(k4.ps(f"(Get-Process -Id {pid} -ErrorAction Stop).PrivateMemorySize64"))


def h3_memory_validation(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    """h3probe's memory operation, read-only, against the hypervisor and the pinned image, and how it
    is contained.

    One boot, paused while it is read. The corpus, the controls and a seeded sample of RAM are read
    through the memory operation, and every page the hypervisor accepts is checked against the sixteen
    bytes `HvCallReadGpa` reads there itself; the Secure Kernel's header page, which the hypervisor
    refuses to VTL0, must carry the pinned image's identity. Then the requests the driver must refuse,
    a burst of reads against vmwp's private bytes, a reading process killed mid-loop, and an unload
    and reload of h3probe. Then 60 healthy seconds, and a restart, after which the old boot's identity
    must be refused. The differential against hvmm that this replaced is recorded in the migration's
    runs (`docs/h3probe-only-plan.md`).
    """
    checks = _write_checks(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("h3 memory validation prerequisites failed")
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    sample_count = int(options.get("sample_pages", 256))
    seed = int(options.get("sample_seed", int(time.time())))
    burst = int(options.get("burst_reads", 2000))
    ctx.confirm(
        f"Boot {target.vm_name}, validate h3probe's read-only memory operation, unload and reload "
        "h3probe, restart the VM once, and return it to Off?"
    )

    runner, configured = bench_bridge.configure_runner(ctx, "run_k3_sk_live")
    k4 = runner.k4
    h3 = configured["h3"]
    memory = bench_bridge._module("guest_physical")
    report = ctx.run_dir / "h3-memory-validation.json"
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    service = ctx.config.drivers.h3probe_service
    state = drivers.status(service)
    result: dict[str, Any] = {
        "schema": "secure-kernel-lab.h3-memory-validation.v2",
        "target": target.name,
        "vm_id": target.vm_id,
        "abi_version": h3_memory.VERSION,
        "host_images": {
            "vid.sys": _sha256_file(system / "drivers" / "vid.sys"),
            "vid.dll": _sha256_file(system / "vid.dll"),
            "vmwp.exe": _sha256_file(system / "vmwp.exe"),
        },
        "driver": {
            "service": service,
            "state_before": state.state,
            "image": str(state.image or ""),
            "sha256": _sha256_file(state.image) if state.image is not None else None,
        },
        "options": {"sample_pages": sample_count, "sample_seed": seed, "burst_reads": burst},
        "hvlib_loaded_before": module_loaded("hvlib.dll"),
        "comparisons": {},
        "controls": {},
    }
    atomic_json(report, result)
    if result["hvlib_loaded_before"]:
        raise ExecutionFailure("hvlib.dll was already loaded before the no-hvlib validation")

    booted = paused = False
    pid = 0
    probe = device = None
    if k4.vm_state() != "Off":
        raise PrerequisiteError(f"{target.vm_name} must be Off before the validation boots it")
    try:
        try:
            pid, uptime = k4.start_bench()
        finally:
            booted = k4.vm_state() != "Off"
        vnd, handle, partition, how = runner.discovery(pid)
        result["boot"] = {"vmwp_pid": pid, "uptime_seconds": uptime}
        result["identity"] = {
            "dispatcher_vnd": hex(vnd),
            "partition_handle": hex(handle),
            "partition_id": hex(partition),
            "discovery": how,
        }
        probe = h3.Probe()
        result["state_before"] = h3.snapshot_coherent(probe, partition, target.vp)
        result["health_before"] = k4.health(pid, "before-h3-memory-validation")
        atomic_json(report, result)

        k4.pause_vm()
        paused = True
        addresses, controls, runs = _h3_corpus(
            ctx, k4, h3, memory, probe, pid, handle, partition, 0x40, result, report
        )
        device = h3_memory.Device()
        reader = h3_memory.Reader(device, pid, handle, partition)
        oracle = backing.Hypervisor(probe, partition)

        def compare(gpa: int) -> dict[str, Any]:
            _backed, answer, head = oracle.read(gpa)
            data, record = _h3_page(reader, gpa)
            return {
                "gpa": hex(gpa),
                "h3": record,
                "backing": answer,
                "hypervisor_bytes_agree": data[: len(head)] == head
                if data is not None and head is not None
                else None,
            }

        for name, gpa in addresses.items():
            result["comparisons"][name] = compare(gpa)
        for name, gpa in controls.items():
            result["controls"][name] = compare(gpa)
        header, _ = _h3_page(reader, controls["secure_kernel_header"])
        found = pe_identity(header) if header is not None else None
        result["controls"]["secure_kernel_header"]["pe_identity"] = (
            {key: f"0x{value:x}" for key, value in found.items()} if found else None
        )
        atomic_json(report, result)

        pages = h3_migration.sample_pages(runs, sample_count, seed)
        read = checked = agreed = 0
        disagreements: list[dict[str, Any]] = []
        for gpa in pages:
            entry = compare(gpa)
            read += entry["h3"]["result"] == "ok"
            if entry["hypervisor_bytes_agree"] is not None:
                checked += 1
                agreed += entry["hypervisor_bytes_agree"]
            if (entry["h3"]["result"] != "ok" or entry["hypervisor_bytes_agree"] is False) and len(
                disagreements
            ) < 16:
                disagreements.append(entry)
        result["sample"] = {
            "seed": seed,
            "pages": len(pages),
            "read": read,
            "hypervisor_checked": checked,
            "hypervisor_agreed": agreed,
            "above_4gib": sum(1 for gpa in pages if gpa >= 0x100000000),
            "disagreements": disagreements,
        }
        atomic_json(report, result)

        code_page = addresses["mapped_code"]
        result["refusals"] = _h3_refusals(device, pid, handle, partition, code_page)
        atomic_json(report, result)

        reference, _ = _h3_page(reader, code_page)
        before = _private_bytes(k4, pid)
        started = time.monotonic()
        same = sum(1 for _ in range(burst) if _h3_page(reader, code_page)[0] == reference)
        after = _private_bytes(k4, pid)
        result["leak"] = {
            "reads": burst,
            "identical": same,
            "seconds": round(time.monotonic() - started, 3),
            "vmwp_private_before": before,
            "vmwp_private_after": after,
            "delta": after - before,
            # Three scratch pages kept per read would be 12 KiB each; 4 MiB is a sixth of that.
            "passed": reference is not None and same == burst and after - before < 4 * 1024 * 1024,
        }
        atomic_json(report, result)

        child = subprocess.Popen(
            [sys.executable, "-c", _H3_READ_LOOP, str(pid), hex(handle), hex(partition), hex(code_page)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        lines: list[str] = []
        waiter = threading.Thread(
            target=lambda: lines.append(child.stdout.readline().strip() if child.stdout else ""),
            daemon=True,
        )
        waiter.start()
        waiter.join(timeout=30)
        first = lines[0] if lines else "no line within 30 s"
        time.sleep(1)
        child.kill()
        child.wait(timeout=30)
        after_kill, record = _h3_page(reader, code_page)
        result["cancellation"] = {
            "child_first_line": first,
            "child_exit": child.returncode,
            "read_after": record,
            "vmwp_private_after": _private_bytes(k4, pid),
            "passed": first == "READY" and after_kill == reference,
        }
        atomic_json(report, result)

        text_after, _ = _h3_page(reader, code_page)
        result["vtl1_text"] = {
            "gpa": hex(code_page),
            "sha256_before": result["comparisons"]["mapped_code"]["h3"]["sha256"],
            "sha256_after": hashlib.sha256(text_after).hexdigest() if text_after is not None else None,
        }
        result["hvlib_loaded_after"] = module_loaded("hvlib.dll")

        # Every handle to the device is closed first: unloading under an open handle is not tested.
        device.close()
        probe.close()
        device = probe = None
        stopped = drivers.stop(service)
        try:
            h3_memory.Device().close()
            open_after_stop = "opened"
        except OSError as error:
            open_after_stop = str(error)
        started_again = drivers.start(service)
        device = h3_memory.Device()
        reader = h3_memory.Reader(device, pid, handle, partition)
        reloaded, record = _h3_page(reader, code_page)
        probe = h3.Probe()
        result["unload"] = {
            "state_after_stop": stopped.state,
            "open_after_stop": open_after_stop,
            "state_after_start": started_again.state,
            "read_after_reload": record,
            "passed": stopped.state == "stopped"
            and open_after_stop != "opened"
            and started_again.running
            and reloaded == reference,
        }
        atomic_json(report, result)

        k4.resume_vm()
        paused = False
        time.sleep(60)
        result["state_after"] = h3.snapshot_coherent(probe, partition, target.vp)
        result["health_after_60s"] = k4.health(pid, "after-h3-memory-validation-60s")
        result["same_boot"] = result["health_before"]["pid"] == result["health_after_60s"]["pid"]
        device.close()
        probe.close()
        device = probe = None
        atomic_json(report, result)

        # A restart gives vmwp a new PID and the partition a new ID. The old boot's identity,
        # whole or with only the PID refreshed, must be refused as identity and never served.
        result["restart"] = {"stop": k4.stop_bench()}
        booted = False
        try:
            new_pid, new_uptime = k4.start_bench()
        finally:
            booted = k4.vm_state() != "Off"
        result["restart"].update(vmwp_pid=new_pid, uptime_seconds=new_uptime)
        device = h3_memory.Device()
        stale: dict[str, Any] = {}
        for name, owner in (("old_identity", pid), ("old_handle_and_partition", new_pid)):
            try:
                answer, data = h3_memory.read(device, owner, handle, partition, code_page, 8)
                stale[name] = {"result": answer.result, "stage": answer.stage, "bytes": len(data)}
            except (OSError, ValueError) as error:
                stale[name] = {"result": "call-failed", "detail": str(error)}
        result["identity_change"] = {
            "old": {"vmwp_pid": pid, "partition_handle": hex(handle), "partition_id": hex(partition)},
            "new_vmwp_pid": new_pid,
            "answers": stale,
            "passed": new_pid != pid and all(entry["result"] == "identity" for entry in stale.values()),
        }
        result["health_after_restart"] = k4.health(new_pid, "after-restart")
        result["verdict"] = h3_migration.validation_verdict(result)
        result["result"] = "pass" if result["verdict"]["passed"] else "fail"
        atomic_json(report, result)
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        result["result"] = "error"
        if booted:
            try:
                result["vm_at_error"] = k4.vm_json()
            except Exception as state_error:
                result["vm_at_error"] = f"unreadable: {state_error}"
        atomic_json(report, result)
        raise
    finally:
        for resource in (device, probe):
            if resource is not None:
                try:
                    resource.close()
                except Exception as error:
                    result.setdefault("close_errors", []).append(str(error))
        if booted:
            if paused and k4.vm_state() == "Paused":
                k4.resume_vm()
            # Nothing here wrote to the guest, so there is nothing to restore before power-off.
            result.update(_stop_read_only_target(k4, target.vm_id))
            atomic_json(report, result)
    if result["result"] != "pass":
        failed = [name for name, ok in result["verdict"]["criteria"].items() if not ok]
        raise ExecutionFailure(f"h3 memory validation failed: {', '.join(failed)}; see {report}")
    return {"report": str(report), **result}


def _kd_post_audit_checks(ctx: RunContext, _options: dict[str, Any]) -> list[dict[str, Any]]:
    return doctor(
        ctx.config,
        ctx.target,
        required={
            "administrator",
            "mcp",
            "repo",
            "profile",
            "image",
            "identity",
            "running",
            "disposable",
            "h3probe",
            "h3_memory",
        },
    )


def kd_post_audit(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    """Run the same restoration audit `kd.manual` performs after releasing its controller."""
    checks = _kd_post_audit_checks(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("KD post-release audit prerequisites failed")
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    ctx.confirm(f"Pause {target.vm_name} and run the KD post-release restoration audit?")
    from .core import _post_kd_audit

    return _post_kd_audit(ctx, survival_seconds=int(options.get("survival_seconds", 0)))


def vtl_split(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    _require(ctx, options)
    ctx.confirm(f"Read VTL0 and VTL1 page tables for {ctx.target.vm_name}?")  # type: ignore[union-attr]
    bench_bridge.configure(ctx)
    module = bench_bridge._module("probe_vtl_split")
    module.HERE = ctx.run_dir
    module.VM_ID = ctx.target.vm_id  # type: ignore[union-attr]
    module.CACHE = ctx.config.paths.state_root / ctx.target.name / "discovery-cache.json"  # type: ignore[union-attr]
    module.IMAGE = ctx.target.secure_kernel_image  # type: ignore[union-attr]
    if not module.CACHE.is_file():
        bench_bridge.discover(ctx)
    code = bench_bridge.invoke_main(module, [])
    if code:
        raise ExecutionFailure(f"VTL split probe exited {code}")
    return {"report": str(ctx.run_dir / "k3-vtl-split.json")}


def _cargo_acceptance(ctx: RunContext, options: dict[str, Any], *, kd: bool) -> dict[str, Any]:
    _require(ctx, options)
    config_path = Path(str(options.get("config", ""))).expanduser().resolve(strict=False)
    if not config_path.is_file():
        raise PrerequisiteError("set config to a prepared live acceptance JSON file")
    ctx.confirm(f"Run the {'KD' if kd else 'live-control'} acceptance tier against {ctx.target.vm_name}?")  # type: ignore[union-attr]
    policy = ctx.run_dir / "sk-live-policy.json"
    write_policy(ctx.config, ctx.target, policy)  # type: ignore[arg-type]
    test = (
        "a_managed_secure_kernel_kd_session_resolves_symbols_and_unwinds_a_natural_stop"
        if kd
        else "a_live_secure_kernel_session_stops_steps_inspects_resumes_and_closes"
    )
    variable = "WINDBG_MCP_SMOKE_SK_KD" if kd else "WINDBG_MCP_SMOKE_SK_LIVE"
    environment = {
        variable: str(config_path),
        "WINDBG_MCP_SK_LIVE_POLICY": str(policy),
        "WINDBG_MCP_TRANSCRIPT": str(ctx.run_dir / "mcp.jsonl"),
        "WINDBG_MCP_TRANSCRIPT_MAX_FIELD": "0",
    }
    command = [
        "cargo",
        "test",
        "--test",
        "mcp_smoke",
        "--",
        "--ignored",
        "--exact",
        test,
        "--nocapture",
        "--test-threads=1",
    ]
    ctx.run_process(command, env=environment, name="kd-acceptance" if kd else "live-acceptance", timeout=float(options.get("timeout", 900)))
    return {"test": test, "config": str(config_path)}


def live_acceptance(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    return _cargo_acceptance(ctx, options, kd=False)


def kd_acceptance(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    return _cargo_acceptance(ctx, options, kd=True)


def _m8_checks(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    scope = str(options.get("scope", "composite"))
    required = {
        "administrator",
        "mcp",
        "repo",
        "profile",
        "image",
        "identity",
        "running",
        "disposable",
        "h3probe",
        "h3_memory",
        "symbols",
    }
    if scope.startswith("external"):
        required |= {"windbg_classic", "windbgx"}
    checks = doctor(ctx.config, ctx.target, required=required)
    credential = ctx.target.guest_credential_file if ctx.target is not None else None
    checks.append(
        {
            "name": "guest credential file",
            "status": "ok" if credential is not None and credential.is_file() else "error",
            "detail": str(credential or "not configured"),
            "required": True,
        }
    )
    checks.append(
        {
            "name": "M8 debugger control helper",
            "status": "ok" if m8.debugger_control_script().is_file() else "error",
            "detail": str(m8.debugger_control_script()),
            "required": scope.startswith("external"),
        }
    )
    return checks


def m8_acceptance(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    checks = _m8_checks(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("M8 qualification prerequisites failed")
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    scope = str(options.get("scope", "composite"))
    tests = {
        "composite": (
            "a_managed_secure_kernel_kd_session_is_driven_by_this_servers_own_kernel_attach",
            "WINDBG_MCP_SMOKE_SK_KD",
        ),
        "external-preflight": (
            "sk_m8::qualification_preflight_reads_one_healthy_static_boot",
            "WINDBG_MCP_SMOKE_SK_KD_M8",
        ),
        "external-breakpoints": (
            "sk_m8::qualification_runner_executes_breakpoint_matrix_on_one_boot",
            "WINDBG_MCP_SMOKE_SK_KD_M8",
        ),
        "external-full": (
            "sk_m8::qualification_runner_executes_full_m8_2a_matrix_on_one_boot",
            "WINDBG_MCP_SMOKE_SK_KD_M8",
        ),
    }
    if scope not in tests:
        raise PrerequisiteError(
            "scope must be composite, external-preflight, external-breakpoints, or external-full"
        )
    if scope == "external-full" and not options.get("include_non_gating_gui_controls", False):
        raise PrerequisiteError(
            "external-full contains the non-gating GUI Ctrl+Break/reset race rig; set "
            "include_non_gating_gui_controls=true to request it explicitly"
        )
    ctx.confirm(f"Run the exact M8 {scope} qualification against {target.vm_name}?")

    breakpoint = str(options.get("breakpoint", m8.DEFAULT_BREAKPOINT))
    if scope == "composite":
        config_path = m8.write_composite_config(
            ctx.config,
            target,
            ctx.run_dir / "m8-composite-config.json",
            breakpoint=breakpoint,
        )
        policy_path = ctx.run_dir / "sk-live-policy.json"
        write_policy(ctx.config, target, policy_path)
    else:
        config_path = m8.write_qualification_config(
            ctx.config,
            target,
            ctx.run_dir / "m8-external",
            breakpoint=breakpoint,
        )
        policy_path = ctx.run_dir / "m8-external" / "m8-policy-hardware.json"

    test, variable = tests[scope]
    environment = {
        variable: str(config_path),
        "WINDBG_MCP_SK_LIVE_POLICY": str(policy_path),
        "WINDBG_MCP_TRANSCRIPT": str(ctx.run_dir / "mcp.jsonl"),
        "WINDBG_MCP_TRANSCRIPT_MAX_FIELD": "0",
    }
    command = [
        "cargo",
        "test",
        "--test",
        "mcp_smoke",
        "--",
        "--ignored",
        "--exact",
        test,
        "--nocapture",
        "--test-threads=1",
    ]
    ctx.run_process(
        command,
        env=environment,
        name=f"m8-{scope}",
        timeout=float(options.get("timeout", 14_400)),
    )
    return {"scope": scope, "test": test, "config": str(config_path)}


def _resolve_guard(ctx: RunContext, options: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    address = options.get("address")
    raw_bytes = options.get("bytes")
    if address and raw_bytes:
        return str(address), str(raw_bytes), {"source": "operator"}
    target = ctx.target
    assert target is not None
    pid, vnd, handle, partition, how = bench_bridge.discover(ctx)
    memory = bench_bridge._module("guest_physical")
    identity = memory.vtl1_identity(partition, target.vp)
    source = memory.H3Source(pid, handle, partition)
    try:
        sk_base, _evidence = memory.find_secure_kernel_base(
            memory.GuestVirtual(source, identity["cr3"]),
            identity["idtr_base"],
            identity["idtr_limit"],
            target.secure_kernel_image,
        )
        profile = json.loads(target.profile.read_text(encoding="utf-8"))
        initial = profile["secure_kernel_kd"]["initial"]
        rva = int(str(initial["rva"]), 0)
        address = sk_base + rva
        raw_bytes = bytes(int(value) for value in initial["original"]).hex()
        evidence = {
            "source": "profile_rva_plus_live_base",
            "vmwp_pid": pid,
            "dispatcher_vnd": hex(vnd),
            "partition_id": hex(partition),
            "discovery": how,
            "secure_kernel_base": hex(sk_base),
        }
        return hex(address), raw_bytes, evidence
    finally:
        source.close()


def build_mismatch(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    """Prove a vmwp profile whose image hash is wrong is refused before any live mutation.

    The open only reserves the controller; the first arm is where the dispatcher hashes the loaded
    vmwp image, before the provider writes a register. So the arm must fail naming that guard, and
    the session must then end released. That nothing changed is the same boot's post-release audit.
    """
    _require(ctx, options)
    ctx.confirm(f"Run the pre-mutation build-mismatch refusal against {ctx.target.vm_name}?")  # type: ignore[union-attr]
    target = ctx.target
    assert target is not None
    address, raw_bytes, guard_evidence = _resolve_guard(ctx, options)
    profile = json.loads(target.profile.read_text(encoding="utf-8"))
    profile["vmwp_sha256"] = "0" * 64
    bad_profile = ctx.run_dir / "vmwp-profile-mismatch.json"
    atomic_json(bad_profile, profile)
    policy_path = ctx.run_dir / "sk-live-policy.json"
    policy = write_policy(ctx.config, target, policy_path)
    policy["profile_roots"].append(str(ctx.run_dir))  # type: ignore[union-attr]
    atomic_json(policy_path, policy)
    client = McpClient(ctx.config.paths.windbg_mcp_exe, cwd=ctx.config.paths.windbg_mcp_repo, policy=policy_path, transcript=ctx.run_dir / "mcp.jsonl")
    result: dict[str, Any] = {"profile": str(bad_profile), "guard": guard_evidence}
    try:
        client.initialize()
        try:
            opened = client.tool(
                "open_sk_live_control",
                {
                    "profile": str(bad_profile),
                    "control_transport": control_transport(target),
                    "live_transport": live_transport(target),
                    "vm_id": target.vm_id,
                    "vp": target.vp,
                },
                60,
            )
        except ExecutionFailure as error:
            # A server that validated the profile at open refused it there.
            if "SHA-256" not in str(error):
                raise
            return {**result, "refused": True, "refused_at": "open", "reason": str(error)}
        session_id = str(opened["session_id"])
        try:
            client.tool(
                "sk_live_arm",
                {"session_id": session_id, "address": address, "bytes": raw_bytes, "mode": str(options.get("arm_mode", ctx.config.defaults.arm_mode))},
                120,
            )
        except (ExecutionFailure, RecoveryRequired) as error:
            if "vmwp SHA-256 does not match" not in str(error):
                raise
            result.update(refused=True, refused_at="arm", reason=str(error))
        else:
            client.end_session(session_id)
            raise ExecutionFailure("the mismatched vmwp profile was armed")
        try:
            result["teardown"] = client.end_session(session_id)
        except RecoveryRequired as error:
            raise ExecutionFailure(f"the refused build mismatch left unresolved ownership: {error}") from error
        row = client.session(session_id)
        if row is not None and (row.get("state") or {}).get("state") != "closed":
            raise ExecutionFailure(f"the refused build mismatch did not release: {row}")
        return result
    finally:
        (ctx.run_dir / "server.stderr.log").write_text(client.stderr, encoding="utf-8")
        client.close(terminate=True)


def _fault_session(
    ctx: RunContext,
    options: dict[str, Any],
    *,
    kind: str,
) -> dict[str, Any]:
    _require(ctx, options)
    target = ctx.target
    assert target is not None
    address, raw_bytes, guard_evidence = _resolve_guard(ctx, options)
    ctx.confirm(
        f"Inject {kind.replace('_', ' ')} into {target.vm_name}; unresolved ownership may be retained?"
    )
    policy_path = ctx.run_dir / "sk-live-policy.json"
    policy = write_policy(ctx.config, target, policy_path)
    control = control_transport(target)
    environment: dict[str, str | None] = {}
    signal: Path | None = None
    if kind == "provider_death":
        control += " --exit-before-response publish_stop"
        policy["transport_commands"].append(control)  # type: ignore[union-attr]
        atomic_json(policy_path, policy)
    elif kind == "debugger_loss":
        environment["WINDBG_MCP_SK_LIVE_FAULT"] = "debugger_loss_after_restore"
    elif kind == "identity_change":
        signal = ctx.run_dir / "identity-change.signal"
        control += f' --identity-change-signal "{signal}"'
        policy["transport_commands"].append(control)  # type: ignore[union-attr]
        atomic_json(policy_path, policy)
    result: dict[str, Any] = {"fault": kind, "guard": guard_evidence}
    with temporary_environment(environment):
        client = McpClient(ctx.config.paths.windbg_mcp_exe, cwd=ctx.config.paths.windbg_mcp_repo, policy=policy_path, transcript=ctx.run_dir / "mcp.jsonl")
        session_id: str | None = None
        try:
            client.initialize()
            opened = client.tool(
                "open_sk_live_control",
                {
                    "profile": str(target.profile),
                    "control_transport": control,
                    "live_transport": live_transport(target),
                    "vm_id": target.vm_id,
                    "vp": target.vp,
                },
                60,
            )
            session_id = str(opened["session_id"])
            client.tool(
                "sk_live_arm",
                {"session_id": session_id, "address": address, "bytes": raw_bytes, "mode": str(options.get("arm_mode", ctx.config.defaults.arm_mode))},
                120,
            )
            if kind == "provider_death":
                try:
                    client.tool("sk_live_wait", {"session_id": session_id}, 180)
                except (ExecutionFailure, RecoveryRequired) as error:
                    result["fault_result"] = str(error)
                else:
                    raise ExecutionFailure("provider-death injection did not fault the wait")
            else:
                stopped = client.tool("sk_live_wait", {"session_id": session_id}, 240)
                result["stop"] = stopped
                if kind == "identity_change":
                    configured = bench_bridge.configure(ctx)
                    pid = configured["k4"].vmwp_pid()
                    configured["k4"].ps(
                        f"$p=Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\";"
                        f"if($p.Name -ne 'vmwp.exe' -or $p.CommandLine -notmatch '{target.vm_id}')"
                        "{throw 'refusing to terminate a vmwp without the exact target identity'};"
                        f"Stop-Process -Id {pid} -Force -ErrorAction Stop"
                    )
                    assert signal is not None
                    signal.write_text("identity changed\n", encoding="utf-8")
                try:
                    client.tool(
                        "sk_live_continue",
                        {"session_id": session_id, "epoch": stopped["epoch"]},
                        120,
                    )
                except (ExecutionFailure, RecoveryRequired) as error:
                    result["fault_result"] = str(error)
                else:
                    raise ExecutionFailure(f"{kind} injection did not fault continue")
            try:
                client.end_session(session_id)
            except (ExecutionFailure, RecoveryRequired) as error:
                result["teardown"] = str(error)
            row = client.session(session_id)
            result["retained_session"] = row
            state = (row or {}).get("state", {})
            unresolved = state.get("state") in {"live_control_unresolved", "secure_kernel_kd"}
            if not unresolved and "recovery" not in str(result.get("teardown", "")).lower():
                raise ExecutionFailure("fault did not retain or report unresolved ownership")
            return result
        finally:
            (ctx.run_dir / "server.stderr.log").write_text(client.stderr, encoding="utf-8")
            client.close()


def provider_death(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    return _fault_session(ctx, options, kind="provider_death")


def debugger_loss(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    return _fault_session(ctx, options, kind="debugger_loss")


def identity_change(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    return _fault_session(ctx, options, kind="identity_change")


ADVANCED_MODULES = [
    ModuleSpec("validate.h3-memory", "Validate h3probe's read-only memory operation", "advanced", "target-control", "Read the corpus, controls and a seeded RAM sample through h3probe's memory operation; check every page the hypervisor accepts against HvCallReadGpa's own bytes and the Secure Kernel's header against the pinned image; require typed absence, the driver's refusals, no scratch leakage, a contained killed reader and unload, and that a restarted VM's old identity is refused.", {"sample_pages": 256, "burst_reads": 2000}, _write_checks, h3_memory_validation),
    ModuleSpec("validate.vtl-split", "Validate VTL0/VTL1 page separation", "advanced", "read-only", "Compare VTL0 and VTL1 translations for Secure Kernel addresses.", {}, _checks, vtl_split),
    ModuleSpec("validate.memory-write", "Prove raw VTL1 write and restoration", "advanced", "target-control", "Write one reserved Secure Kernel header byte through h3probe's memory operation, verify the page delta, restore it, hash the restored page, resume only after that is proved, and audit the same boot without loading hvlib.", {}, _write_checks, memory_write_restore),
    ModuleSpec("validate.kd-post-audit", "Validate the KD post-release audit", "advanced", "target-control", "Run the same identity, guarded-text, debug-register, flags, and health audit used after managed KD release, without opening a KD client.", {"survival_seconds": 0}, _kd_post_audit_checks, kd_post_audit),
    ModuleSpec("validate.live", "Run the opt-in live MCP acceptance", "advanced", "target-control", "Run the exact live-control smoke tier from a prepared JSON config.", {"timeout": 900}, _checks, live_acceptance),
    ModuleSpec("validate.kd", "Run the opt-in managed KD acceptance", "advanced", "target-control", "Run the exact managed KD symbol/unwind tier from a prepared JSON config.", {"timeout": 900}, _checks, kd_acceptance),
    ModuleSpec(
        "validate.m8",
        "Run the exact M8 debugger qualification",
        "advanced",
        "target-control",
        "Generate the private inputs from sklab and run the product composite, external preflight, four-arm external breakpoint matrix, or explicitly requested non-gating GUI race rig.",
        {
            "scope": "composite",
            "breakpoint": m8.DEFAULT_BREAKPOINT,
            "timeout": 14_400,
            "include_non_gating_gui_controls": False,
        },
        _m8_checks,
        m8_acceptance,
    ),
    ModuleSpec("fault.build-mismatch", "Refuse a mismatched vmwp profile", "advanced", "target-control", "Prove an exact-build mismatch is refused before live mutation.", {}, _checks, build_mismatch),
    ModuleSpec("fault.provider-death", "Inject provider death", "advanced", "destructive-fault", "Exit the register provider at stop publication and preserve unresolved ownership.", {}, _checks, provider_death),
    ModuleSpec("fault.debugger-loss", "Inject debugger loss", "advanced", "destructive-fault", "Fail after provider baseline restoration and preserve recovery evidence.", {}, _checks, debugger_loss),
    ModuleSpec("fault.identity-change", "Inject target identity change", "advanced", "destructive-fault", "Terminate only the identity-checked vmwp during a held stop and preserve recovery evidence.", {}, _checks, identity_change),
]

