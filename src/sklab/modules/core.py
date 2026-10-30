from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

from .. import bench_bridge, guest_ram, h3, h3_memory, m8, sk_processes
from ..context import RunContext
from ..doctor import passed, run as doctor
from ..errors import Cancelled, ExecutionFailure, PrerequisiteError, RecoveryRequired
from ..mcp import McpClient
from ..policy import bench_directory, control_transport, live_transport, write_policy
from ..util import atomic_json, command_line, module_loaded, pe_identity, powershell_command
from .spec import ModuleSpec


LIVE_CAPABILITIES = {
    "administrator",
    "mcp",
    "repo",
    "profile",
    "image",
    "identity",
    "running",
}
# Every register read and write the control providers make goes through `\\.\H3Probe`, and so does
# every guest-physical page, through its memory operation.
CONTROL_CAPABILITIES = LIVE_CAPABILITIES | {"disposable", "h3probe", "h3_memory"}


def _common_checks(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    # Both decode modes read through h3probe: direct pages through its memory operation, hypercall
    # pages through HvCallReadGpa, which refuses VTL1. Neither loads hvlib.
    required = LIVE_CAPABILITIES | {"h3probe"}
    if options.get("mode", "direct") == "direct":
        required.add("h3_memory")
    return doctor(ctx.config, ctx.target, required=required)


def _control_checks(ctx: RunContext, _options: dict[str, Any]) -> list[dict[str, Any]]:
    return doctor(ctx.config, ctx.target, required=CONTROL_CAPABILITIES)


def _transition_checks(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    checks = doctor(ctx.config, ctx.target, required=CONTROL_CAPABILITIES)
    credential = ctx.target.guest_credential_file if ctx.target is not None else None
    checks.append(
        {
            "name": "guest credential file",
            "status": "ok" if credential is not None and credential.is_file() else "error",
            "detail": str(credential or "not configured"),
            "required": True,
        }
    )
    return checks


def _kd_checks(ctx: RunContext, _options: dict[str, Any]) -> list[dict[str, Any]]:
    return doctor(
        ctx.config,
        ctx.target,
        required=CONTROL_CAPABILITIES | {"windbg"},
    )


def _kd_external_checks(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    frontend = str(options.get("frontend", "classic")).lower()
    capability = "windbgx" if frontend == "windbgx" else "windbg_classic"
    return doctor(
        ctx.config,
        ctx.target,
        required=CONTROL_CAPABILITIES | {capability},
    )


def _kd_debugger_checks(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    checks = _transition_checks(ctx, options)
    symbol_path = Path(str(options.get("symbol_path") or ctx.config.paths.symbol_path or ""))
    checks.append(
        {
            "name": "Secure Kernel symbol store",
            "status": "ok" if symbol_path.is_dir() else "error",
            "detail": str(symbol_path or "not configured"),
            "required": True,
        }
    )
    return checks


def _require_checks(
    ctx: RunContext,
    options: dict[str, Any],
    checker=_common_checks,
) -> list[dict[str, Any]]:
    checks = checker(ctx, options)
    failures = [row for row in checks if row["status"] == "error"]
    if failures:
        raise PrerequisiteError("prerequisite checks failed: " + "; ".join(row["name"] for row in failures))
    return checks


def _capture_check(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    checks = doctor(ctx.config, None, required={"mcp", "repo", "kit"})
    kind = str(options.get("capture_kind", "vmrs"))
    capture = str(options.get("capture", ""))
    if kind not in {"vm", "vmrs", "split"}:
        checks.append({"name": "capture kind", "status": "error", "detail": kind, "required": True})
    if not capture:
        checks.append({"name": "capture selector", "status": "error", "detail": "set capture", "required": True})
    elif kind == "vmrs" and not Path(capture).is_file():
        checks.append({"name": "capture file", "status": "error", "detail": capture, "required": True})
    image = Path(str(options.get("image") or (ctx.target.secure_kernel_image if ctx.target else "")))
    checks.append({"name": "image", "status": "ok" if image.is_file() else "error", "detail": str(image), "required": True})
    return checks


def capture_inspect(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    checks = _capture_check(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("capture inspection prerequisites failed")
    kind = str(options.get("capture_kind", "vmrs"))
    capture = str(options["capture"])
    image = str(options.get("image") or ctx.target.secure_kernel_image)  # type: ignore[union-attr]
    command = [str(ctx.config.paths.windbg_mcp_exe), "--sk-inspect", "--image", image]
    if kind == "vm":
        command.extend(["--vm", capture])
        if options.get("snapshot"):
            command.extend(["--snapshot", str(options["snapshot"])])
    elif kind == "vmrs":
        command.extend(["--vmrs", capture])
    else:
        vsv = options.get("vsv")
        if not vsv:
            raise PrerequisiteError("split capture requires vsv")
        command.extend(["--bin", capture, "--vsv", str(vsv)])
    command.extend(["--vp", str(options.get("vp", 0)), "--vtl", str(options.get("vtl", 1))])
    command.extend(["--kit", str(ctx.config.paths.windows_kit_root)])
    if options.get("cross_check"):
        command.append("--cross-check")
    if options.get("symbols"):
        command.append("--symbols")
    if options.get("sympath"):
        command.extend(["--sympath", str(options["sympath"])])
    report = ctx.run_dir / "capture-report.json"
    command.extend(["--json", str(report)])
    ctx.run_process(command, name="capture-inspect", timeout=float(options.get("timeout", 600)))
    return {"report": str(report), "checks": checks}


def live_decode(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    _require_checks(ctx, options)
    if ctx.target is None:
        raise PrerequisiteError("live decode requires a target")
    mode = str(options.get("mode", "direct"))
    if mode not in {"direct", "hypercall"}:
        raise PrerequisiteError("mode must be direct or hypercall")
    requested_partition = options.get("partition_id")
    partition = requested_partition
    vmwp_pid: int | None = None
    partition_handle: int | None = None
    discovery: dict[str, Any] | None = None
    if partition in (None, "") or mode == "direct":
        pid, vnd, handle, discovered_partition, how = bench_bridge.discover(ctx)
        if partition not in (None, "") and int(str(partition), 0) != discovered_partition:
            raise ExecutionFailure(
                f"requested partition {partition} does not match worker discovery "
                f"{hex(discovered_partition)}"
            )
        partition = discovered_partition
        vmwp_pid, partition_handle = pid, handle
        discovery = {
            "vmwp_pid": pid,
            "dispatcher_vnd": hex(vnd),
            "partition_handle": hex(handle),
            "partition_id": hex(partition),
            "how": how,
        }
    partition_text = hex(partition) if isinstance(partition, int) else str(partition)
    image = str(options.get("image") or ctx.target.secure_kernel_image)
    server = [sys.executable, str(bench_directory() / "gpa_server.py")]
    if mode == "direct":
        assert vmwp_pid is not None and partition_handle is not None
        server += ["--vmwp-pid", str(vmwp_pid), "--partition-handle", hex(partition_handle)]
    else:
        server += ["--pages", "hypercall"]
    server += ["--partition-id", partition_text, "--vp", str(ctx.target.vp)]
    if mode == "direct":
        server += ["--image", image]
    command = [
        str(ctx.config.paths.windbg_mcp_exe),
        "--sk-live",
        "--transport",
        command_line(server),
        "--image",
        image,
    ]
    if options.get("cross_check"):
        command.append("--cross-check")
    environment = {"PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    ctx.run_process(command, env=environment, name="live-decode", timeout=float(options.get("timeout", 600)))
    return {
        "mode": mode,
        "partition_id": partition_text,
        "discovery": discovery,
        # The transport follows only mappings present in the VTL1 page tables.
        "pages": "h3 memory operation" if mode == "direct" else "HvCallReadGpa, which refuses VTL1",
    }


def _registers_checks(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    required = {"administrator", "h3probe"}
    if options.get("snapshot"):
        required |= {"repo", "mcp", "identity", "running"}
        if options.get("root_check", True):
            required |= {"image", "h3_memory"}
    return doctor(ctx.config, ctx.target, required=required)


def _root_check(
    ctx: RunContext,
    partition: int,
    snapshots: dict[str, Any],
    vtl0_cr3: int | None = None,
    vmwp_pid: int | None = None,
    partition_handle: int | None = None,
) -> dict[str, Any]:
    """Whether each VP's VTL1 root maps the pinned securekernel.exe at the base its IDT points into,
    and whose root it is.

    A root that maps the image carries the Secure Kernel's mappings. That alone does not say the root
    is the Secure Kernel's own: a trustlet's kernel-mode root maps the Secure Kernel as well, the way
    every process's kernel half maps NT. So the owner is read from the Secure Kernel's own records
    (`sk_processes`) through a root that passed, for a build whose layout is known: its process list,
    and what each VP has loaded. `vtl0_cr3`, any VTL0 root of the partition, names the VTL0 process
    each secure process belongs to.

    Pages come from h3probe's memory operation through the profiled vmwp handle, used inside vmwp:
    nothing is duplicated, no hvlib code is loaded, and a page with no RAM behind it is refused by
    type rather than read as zeros, so no RAM map is needed to tell the two apart.
    """
    target = ctx.target
    assert target is not None
    expected = pe_identity(target.secure_kernel_image.read_bytes()[:0x1000])
    if expected is None:
        raise PrerequisiteError(f"{target.secure_kernel_image} is not a PE image")
    if vmwp_pid is None or partition_handle is None:
        raise ExecutionFailure("the root check requires vmwp discovery's PID and partition handle")
    walker = bench_bridge._module("vtl0_find_matching_image")
    try:
        device = h3_memory.Device()
    except OSError as error:
        raise ExecutionFailure(f"could not open h3probe for its memory operation: {error}") from error
    physical = h3_memory.Reader(device, vmwp_pid, partition_handle, partition)
    try:
        strict = sk_processes.StrictSource(physical)
        located = _locate_secure_kernel(lambda cr3: walker.Guest(strict, cr3), snapshots)
        base = located["base"]
        rows: dict[str, Any] = {}
        for vp, snapshot in snapshots.items():
            cr3 = int(str(snapshot["registers"]["cr3"]["low"]), 0)
            row: dict[str, Any] = {"cr3": hex(cr3)}
            try:
                found = pe_identity(walker.Guest(strict, cr3).virtual(base, 0x1000))
            except sk_processes.UnreadablePage as error:  # says nothing about what the root maps
                row.update(verdict="root-unreadable", detail=str(error))
            except KeyError as error:  # the walker's "not present" at some paging level
                row.update(verdict="base-unmapped", detail=str(error))
            else:
                row.update(
                    verdict="maps-pinned-image" if found == expected else "maps-other-image",
                    found=found,
                )
            rows[vp] = row
        identification = _identify_roots(
            lambda cr3: walker.Guest(strict, cr3), base, expected, rows, vtl0_cr3
        )
    finally:
        device.close()
    return {
        "reader": "h3",
        "secure_kernel_base": hex(base),
        "located": {**located, "base": hex(base)},
        "partition_handle": hex(partition_handle),
        "h3_memory": {
            "reads": physical.calls,
            "failed_calls": physical.failed_calls,
            "results": physical.results,
        },
        "expected": expected,
        "identification": identification,
        "vps": rows,
    }


def _locate_secure_kernel(open_root: Any, snapshots: dict[str, Any]) -> dict[str, Any]:
    """Where securekernel.exe is mapped, from a VP's own VTL1 state.

    Vector 0's handler is code in the image that installed the IDT, so the nearest page at or below it
    that starts with PE headers is that image's base. That page is found, not matched: the image there
    is whatever it is, and each root's check then compares it with the pinned one, so a VTL1 running
    another build is reported as such rather than not found. The walk is through the VP's own root and
    stops after 0x400 pages (4 MiB), far beyond the Secure Kernel's 1.5 MiB. A page the root does not
    map, such as a discarded section, is skipped.
    """
    attempts: dict[str, str] = {}
    for vp, snapshot in snapshots.items():
        idtr = snapshot["registers"].get("idtr")
        if idtr is None or idtr["status"] != 0:
            attempts[vp] = f"IDTR not read: {idtr}"
            continue
        idt = int(str(idtr["high"]), 0)
        limit = int(str(idtr["low"]), 0) >> 48
        root = open_root(int(str(snapshot["registers"]["cr3"]["low"]), 0))
        try:
            handler = guest_ram.idt_handler(root.virtual(idt, guest_ram.IDT_GATE))
            base = guest_ram.image_base_below(root, handler, 0x400)
        except KeyError as error:  # the IDT itself, or a page the reader could not read
            attempts[vp] = str(error)
            continue
        if base is not None:
            return {"vp": vp, "idt": hex(idt), "idt_limit": hex(limit), "handler": hex(handler), "base": base}
        attempts[vp] = f"no PE headers within 4 MiB below vector 0's handler 0x{handler:X}"
    raise ExecutionFailure(f"the Secure Kernel's base was not found from any VP's IDT: {attempts}")


def _identify_roots(
    open_root: Any, base: int, expected: dict[str, int], rows: dict[str, Any], vtl0_root: int | None = None
) -> dict[str, Any]:
    """Names each row's owner in place, from a census read through the first root that maps the image,
    and records what each VP has loaded by the Secure Kernel's per-VP record."""
    layout = sk_processes.layout_for(expected)
    if layout is None:
        return {"skipped": "no process layout for this securekernel.exe build"}
    kernel_root = next((int(row["cr3"], 16) for row in rows.values() if row["verdict"] == "maps-pinned-image"), None)
    if kernel_root is None:
        return {"skipped": "no root maps the pinned image"}
    try:
        found = sk_processes.census(open_root, kernel_root, base, layout, vtl0_root)
    except KeyError as error:
        return {"read_through": hex(kernel_root), "error": str(error)}
    for vp, row in rows.items():
        row["owner"] = sk_processes.owner(int(row["cr3"], 16), found)
        try:
            current = sk_processes.current_process(open_root, kernel_root, base, layout, int(vp), vtl0_root)
        except KeyError as error:
            row["current"] = {"error": str(error)}
        else:
            current["matches_sample"] = int(current["root"], 16) & sk_processes.ROOT == int(row["cr3"], 16) & sk_processes.ROOT
            row["current"] = current
    return {"read_through": hex(kernel_root), **found}


def _vtl0_text(record: dict[str, Any], vtl0_check: str | None) -> str:
    vtl0 = record.get("vtl0")
    if vtl0 is None:
        return f"VTL0 process {record['normal_process']}"
    if "error" in vtl0:
        return f"VTL0 process {record['normal_process']} not read: {vtl0['error']}"
    text = f"VTL0 pid {vtl0['pid']} {vtl0['image']}"
    return text if vtl0_check == "agrees" else f"{text} (EPROCESS offsets {vtl0_check or 'unchecked'})"


def _owner_text(row: dict[str, Any], vtl0_check: str | None = None) -> str:
    """The owner by the process list, unless the VP's own record names a process the list does not hold."""
    owner, current = row.get("owner"), row.get("current") or {}
    if owner is None:
        return "owner not read"
    if owner["owner"] in {"unlisted", "unknown"} and current.get("matches_sample"):
        text = f"{current['kind']}, {_vtl0_text(current, vtl0_check)}"
        if current.get("container_check") == "disagrees":
            text += f" (its container {current['container']} does not confirm it)"
        return text
    if owner["owner"] == "secure-process":
        text = f"pid {owner['pid']}, trustlet id {owner['trustlet_id']}, {owner.get('image_path', 'no image path')}"
        return f"{text}, {_vtl0_text(owner, vtl0_check)}" if "vtl0" in owner else text
    if "error" in current:
        return f"{owner['owner']}; the VP's own record was not read: {current['error']}"
    if owner["owner"] in {"unlisted", "unknown"} and current:
        return f"{owner['owner']}; the VP has since loaded {current['kind']} root {current['root']}"
    return owner["owner"]


def _vtl0_register(control: Any, probe: Any, partition: int, name: str, vp: int) -> dict[str, Any]:
    """A VTL0 register in `read_named`'s shape, which reads every name but one at VTL1."""
    status, low, high = probe.get(partition, 0, control.REGISTERS[name], vp)
    return {"status": status, "low": f"0x{low:016x}", "high": f"0x{high:016x}"}


def _vps(value: Any, vp: int, additional: tuple[int, ...]) -> list[int]:
    """`vps` as the console and CLI deliver it: unset, one number, or a comma list such as `0,1`."""
    if value is None or value == "":
        return [vp, *additional]
    if isinstance(value, int):
        return [value]
    return [int(part, 0) for part in str(value).split(",") if part.strip()]


def _cached_partition(ctx: RunContext) -> int | None:
    """The target's partition id if this boot's discovery cache already names it; never attaches to vmwp."""
    target = ctx.target
    if target is None:
        return None
    cache = ctx.config.paths.state_root / target.name / "discovery-cache.json"
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
        if data.get("vm_id") != target.vm_id:
            return None
        pid = bench_bridge.configure(ctx)["k4"].vmwp_pid()
        if data.get("vmwp_pid") != pid:
            return None
        return int(str(data["partition_id"]), 0)
    except Exception:  # no cache, no vmwp, or a stale boot: the label is a convenience
        return None


def live_registers(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    _require_checks(ctx, options, _registers_checks)
    snapshot = bool(options.get("snapshot"))
    discovery: dict[str, Any] | None = None
    if snapshot:
        if ctx.target is None:
            raise PrerequisiteError("snapshot requires a configured target")
        pid, vnd, handle, partition, how = bench_bridge.discover(ctx)
        discovery = {
            "vmwp_pid": pid,
            "dispatcher_vnd": hex(vnd),
            "partition_handle": hex(handle),
            "partition_id": hex(partition),
            "how": how,
        }
    else:
        partition = _cached_partition(ctx)
    target_partition = hex(partition) if partition is not None else None

    control = bench_bridge._module("h3_vtl1_debug_control")
    probe = control.Probe()
    try:
        gate = h3.parse(probe.ioctl(control.IOCTL_H3_RUN, None, h3.RESULT_SIZE))
        atomic_json(ctx.run_dir / "h3-gate.json", gate)
        if gate["enum_status"] != "success":
            if not gate["children"]:
                raise ExecutionFailure(f"child partition enumeration failed: HV_STATUS {gate['enum_status']}")
            ctx.output.event("warning", f"enumeration stopped early: HV_STATUS {gate['enum_status']}")
        if gate["children"]:
            ctx.output.table(
                h3.rows(gate, target_partition),
                ("partition", "vtl0 cr3", "vtl1 cr3", "vtl set", "max vtl", "verdict", "target"),
            )
        else:
            ctx.output.event("warning", "the root partition has no running children")

        snapshots: dict[str, Any] = {}
        if snapshot:
            assert partition is not None and ctx.target is not None
            child = next((row for row in gate["children"] if row["partition_id"] == target_partition), None)
            if child is None or child["verdict"] not in {"granted", "granted-unconfirmed"}:
                raise ExecutionFailure(
                    f"target partition {target_partition} is not a VTL1 child the gate can read: {child}"
                )
            for vp in _vps(options.get("vps"), ctx.target.vp, ctx.target.additional_vps):
                row = control.snapshot_coherent(probe, partition, vp)
                # Reads of their own, outside the batch: an IDT is fixed from boot, so their instant does
                # not matter. The root check finds the Secure Kernel through VTL1's and NT through VTL0's.
                row["registers"]["idtr"] = control.read_named(probe, partition, "idtr", vp)
                row["registers"]["vtl0_idtr"] = _vtl0_register(control, probe, partition, "idtr", vp)
                atomic_json(ctx.run_dir / f"h3-snapshot-vp{vp}.json", row)
                snapshots[str(vp)] = row
                registers = row["registers"]
                ctx.output.event(
                    "ok",
                    f"VP {vp} VTL1",
                    rip=registers["rip"]["low"],
                    rsp=registers["rsp"]["low"],
                    cr3=registers["cr3"]["low"],
                    dr7=registers["dr7"]["low"],
                )
    finally:
        probe.close()

    root_check: dict[str, Any] | None = None
    if snapshot and options.get("root_check", True):
        assert partition is not None
        child = next(row for row in gate["children"] if row["partition_id"] == target_partition)
        vtl0_cr3 = int(child["vtl0"]["cr3"], 16) if child["vtl0"]["status"] == "success" else None
        root_check = _root_check(
            ctx,
            partition,
            snapshots,
            vtl0_cr3,
            vmwp_pid=pid,
            partition_handle=handle,
        )
        atomic_json(ctx.run_dir / "h3-root-check.json", root_check)
        located = root_check["located"]
        ctx.output.event(
            "ok",
            f"Secure Kernel at {located['base']}, from VP {located['vp']}'s IDT; "
            "pages read through h3probe's memory operation inside vmwp",
            reads=root_check["h3_memory"]["reads"],
        )
        vtl0_check = root_check["identification"].get("vtl0_check")
        for vp, row in root_check["vps"].items():
            maps = row["verdict"] == "maps-pinned-image"
            ctx.output.event(
                "ok" if maps else "warning",
                f"VP {vp} root {row['cr3']}: {row['verdict']}, {_owner_text(row, vtl0_check)}",
                secure_kernel_base=root_check["secure_kernel_base"],
            )
        if vtl0_check == "disagrees":
            ctx.output.event("warning", "a trustlet's VTL0 PID disagrees with its own: the EPROCESS offsets do not fit this guest")
        identification = root_check["identification"]
        if "skipped" in identification or "error" in identification or "walk_error" in identification:
            reason = identification.get("skipped") or identification.get("error") or identification["walk_error"]
            ctx.output.event("warning", f"process census incomplete: {reason}")
    return {
        "gate": gate,
        "target_partition": target_partition,
        "discovery": discovery,
        "snapshots": snapshots,
        "root_check": root_check,
    }


def live_ambient(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    _require_checks(ctx, options, _control_checks)
    ctx.require_disposable()
    ctx.confirm(f"Arm hardware breakpoints in {ctx.target.vm_name} VTL1?")  # type: ignore[union-attr]
    runner, configured = bench_bridge.configure_runner(ctx, "run_k3_sk_live")
    arguments = ["--steps", str(options.get("steps", ctx.config.defaults.steps)), "--read-size", str(options.get("read_size", 32))]
    if options.get("only"):
        arguments.extend(["--only", str(options["only"])])
    with bench_bridge.runner_environment(ctx, configured["policy"]):
        code = bench_bridge.invoke_main(runner, arguments)
    if code:
        raise ExecutionFailure(f"ambient workflow exited {code}")
    return {"workflow": "ambient", "evidence_root": str(runner.RUN_ROOT)}


def live_transition(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    _require_checks(ctx, options, _transition_checks)
    ctx.require_disposable()
    ctx.confirm(f"Drive a VTL1 user-to-Secure-Kernel transition in {ctx.target.vm_name}?")  # type: ignore[union-attr]
    runner, configured = bench_bridge.configure_runner(ctx, "run_k3_sk_syscall", transition=True)
    arguments = [
        "--steps",
        str(options.get("steps", ctx.config.defaults.steps)),
        "--stack-bytes",
        str(options.get("stack_bytes", 64)),
        "--workload-seconds",
        str(options.get("workload_seconds", 150)),
        "--rounds",
        str(options.get("rounds", 2000)),
        "--workload-delay",
        str(options.get("workload_delay", 25)),
    ]
    if options.get("entry"):
        arguments.extend(["--entry", str(options["entry"])])
    if options.get("force_shadow_lstar"):
        arguments.append("--force-shadow-lstar")
    if options.get("inject_shadow_cr3"):
        arguments.append("--inject-shadow-cr3")
    if options.get("no_workload"):
        arguments.append("--no-workload")
    runner.SPIN_HOST = ctx.target.guest_spin_host  # type: ignore[union-attr]
    with bench_bridge.runner_environment(ctx, configured["policy"]):
        code = bench_bridge.invoke_main(runner, arguments)
    if code:
        raise ExecutionFailure(f"transition workflow exited {code}")
    return {"workflow": "transition", "evidence_root": str(runner.RUN_ROOT)}


def _kd_phase(client: McpClient, session_id: str) -> str:
    row = client.session(session_id)
    if row is None:
        return "closed"
    state = row.get("state", {})
    if state.get("state") == "secure_kernel_kd":
        return str(state.get("phase", "unknown"))
    return str(state.get("state", "unknown"))


def _monitor_kd(
    ctx: RunContext,
    client: McpClient,
    session_id: str,
    debugger_command: str,
) -> str:
    last_phase: str | None = None
    command_announced = False
    reconnect_seen: float | None = None
    while True:
        if ctx.cancelled():
            ctx.output.event("warning", "stop requested; ending the managed KD session")
            client.end_session(session_id)
            raise Cancelled("managed KD session stopped by operator")
        phase = _kd_phase(client, session_id)
        if phase != last_phase:
            ctx.output.event("phase", f"KD phase: {phase}", session_id=session_id)
            ctx.manifest.add_event("kd_phase", phase=phase)
            last_phase = phase
        if phase == "waiting_for_peer" and not command_announced:
            ctx.manifest.update(debugger_command=debugger_command)
            ctx.output.event("ok", "Secure Kernel KD guarded stop is ready", session_id=session_id)
            ctx.output.event("info", "Launch WinDbg manually with this command")
            print(debugger_command, file=ctx.output.stream, flush=True)
            ctx.output.event(
                "info",
                "The facade now supports ordinary g, up to four hardware breakpoints, guarded "
                "INT3 breakpoints when the startup policy allows writes, single-step, symbols, "
                "stacks, disassembly, registers, and memory access",
            )
            ctx.output.event(
                "info",
                "While g is running, Ctrl+Break is bound to that exact wait and lands through "
                "the controller's M2 rendezvous; Ctrl+Break while stopped resends the retained stop",
            )
            ctx.output.event(
                "info",
                "NT process/thread extensions and PEB inspection remain outside the Secure Kernel facade",
            )
            command_announced = True
        if phase == "reconnecting":
            reconnect_seen = reconnect_seen or time.monotonic()
            if time.monotonic() - reconnect_seen >= 1.0:
                client.end_session(session_id)
        elif phase in {"released", "closed"}:
            return phase
        elif phase in {"recovery_required", "live_control_unresolved", "failed"}:
            raise RecoveryRequired(f"managed KD entered {phase}; session {session_id} retained")
        time.sleep(0.5)


def _post_kd_audit(ctx: RunContext, *, survival_seconds: int = 0) -> dict[str, Any]:
    """Prove identity, breakpoint state, flags, and guarded text after release."""
    hvlib_loaded_before = module_loaded("hvlib.dll")
    if hvlib_loaded_before:
        raise RecoveryRequired("KD released but hvlib.dll was already loaded before its audit")
    target = ctx.target
    assert target is not None
    target_checks = doctor(ctx.config, target, required={"identity", "running"})
    target_rows = [
        row for row in target_checks if row["name"] in {"Hyper-V target identity", "Hyper-V target state"}
    ]
    if any(row["status"] != "ok" for row in target_rows):
        raise RecoveryRequired("KD released but the target identity/state audit failed")
    identity = next(row for row in target_rows if row["name"] == "Hyper-V target identity")

    pid, _vnd, source_handle, partition, discovery = bench_bridge.discover(ctx)
    configured = bench_bridge.configure(ctx)
    k4 = configured["k4"]
    survival = []
    elapsed = 0
    for checkpoint in list(range(0, survival_seconds + 1, 30)) or [0]:
        if checkpoint > elapsed:
            time.sleep(checkpoint - elapsed)
            elapsed = checkpoint
        survival.append(k4.health(pid, f"post-kd-release-{checkpoint}s"))
    if survival_seconds and elapsed != survival_seconds:
        time.sleep(survival_seconds - elapsed)
        survival.append(k4.health(pid, f"post-kd-release-{survival_seconds}s"))
    memory = bench_bridge._module("guest_physical")
    profile = json.loads(target.profile.read_text(encoding="utf-8"))
    initial = profile["secure_kernel_kd"]["initial"]
    rva = int(str(initial["rva"]), 0)
    expected = bytes(int(value) for value in initial["original"])

    source = None
    control = None
    paused = False
    try:
        k4.pause_vm()
        paused = True
        vtl1 = memory.vtl1_identity(partition, target.vp)
        cr3 = int(vtl1["cr3"])
        source = memory.H3Source(pid, source_handle, partition)
        guest = memory.GuestVirtual(source, cr3)
        base, base_evidence = memory.find_secure_kernel_base(
            guest,
            int(vtl1["idtr_base"]),
            int(vtl1["idtr_limit"]),
            target.secure_kernel_image,
        )
        address = base + rva
        guarded_text = guest.read(address, max(16, len(expected)))
        if not guarded_text.startswith(expected):
            raise RecoveryRequired(
                f"KD released but guarded text at 0x{address:x} does not match the profile"
            )
        source.close()
        source = None

        k4.EXPECTED_CR3 = cr3
        k4.TARGET_RVA = rva
        k4.TARGET_BYTES = expected
        control = k4.ControlClient(partition)
        control.begin_arm()
        snapshot = control.snapshot()
        registers = snapshot["registers"]

        def low(name: str) -> int:
            value = registers[name]["low"]
            return value if isinstance(value, int) else int(value, 0)

        debug = {name: registers[name] for name in ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")}
        if low("dr7") & 0xFF:
            raise RecoveryRequired(f"KD released with an active debug breakpoint: {debug}")
        if low("rflags") & ((1 << 8) | (1 << 16)):
            raise RecoveryRequired(f"KD released with TF/RF set: {registers['rflags']}")
        control.finish_arm()
        control.close()
        control = None
    finally:
        if source is not None:
            source.close()
        if control is not None:
            try:
                if control.phase == "arming":
                    control.finish_arm()
                control.close()
            except Exception:
                pass
        if paused:
            try:
                k4.resume_vm()
            except Exception as error:
                raise RecoveryRequired(f"post-KD audit could not resume the VM: {error}") from error

    health = survival[-1]
    hvlib_loaded_after = module_loaded("hvlib.dll")
    if hvlib_loaded_after:
        raise RecoveryRequired("KD post-release audit loaded hvlib.dll")
    result = {
        "identity": identity,
        "vmwp_pid": pid,
        "partition_handle": hex(source_handle),
        "partition_id": hex(partition),
        "discovery": discovery,
        "cr3": hex(cr3),
        "idtr_base": hex(int(vtl1["idtr_base"])),
        "idtr_limit": hex(int(vtl1["idtr_limit"])),
        "secure_kernel_base": hex(base),
        "base_discovery": base_evidence,
        "guarded_address": hex(address),
        "guarded_text": guarded_text.hex(),
        "debug_registers": debug,
        "rflags": registers["rflags"],
        "health": health,
        "survival": survival,
        "hvlib_loaded_before": hvlib_loaded_before,
        "hvlib_loaded_after": hvlib_loaded_after,
    }
    atomic_json(ctx.run_dir / "post-release-audit.json", result)
    return result


def kd_manual(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    _require_checks(ctx, options, _kd_checks)
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    ctx.confirm(f"Prepare a managed Secure Kernel KD stop for {target.vm_name}?")
    policy = ctx.run_dir / "sk-live-policy.json"
    write_policy(ctx.config, target, policy)
    transcript = ctx.run_dir / "mcp.jsonl"
    client = McpClient(
        ctx.config.paths.windbg_mcp_exe,
        cwd=ctx.config.paths.windbg_mcp_repo,
        policy=policy,
        transcript=transcript,
    )
    session_id: str | None = None
    try:
        server = client.initialize()
        ctx.manifest.update(server=server)
        opened = client.tool(
            "open_sk_kd",
            m8.open_arguments(
                ctx.config,
                target,
                vp=int(options.get("vp", target.vp)),
                arm_mode=str(options.get("arm_mode", ctx.config.defaults.arm_mode)),
                connect_timeout_ms=int(
                    options.get("connect_timeout_ms", ctx.config.defaults.connect_timeout_ms)
                ),
                idle_timeout_ms=int(
                    options.get("idle_timeout_ms", ctx.config.defaults.idle_timeout_ms)
                ),
            ),
            60,
        )
        session_id = str(opened["session_id"])
        connection = str(opened.get("connection", ""))
        if not connection:
            raise ExecutionFailure(f"open_sk_kd returned no typed connection: {opened}")
        debugger_command = [str(ctx.config.paths.debugger_exe), "-k", connection]
        rendered = powershell_command(debugger_command)
        ctx.manifest.update(session_id=session_id, connection=connection)
        ctx.output.event("ok", "Secure Kernel KD is preparing a guarded stop")
        final_phase = _monitor_kd(ctx, client, session_id, rendered)
        if final_phase == "released":
            client.end_session(session_id)
        audit = _post_kd_audit(ctx) if options.get("post_audit", True) else None
        ctx.output.event("ok", "KD controller released and post-release audit passed")
        return {
            "session_id": session_id,
            "connection": connection,
            "final_phase": final_phase,
            "post_release_audit": audit,
        }
    except KeyboardInterrupt:
        if session_id is not None:
            ctx.output.event("warning", "interrupt requested; ending the managed KD session")
            client.end_session(session_id)
        raise
    finally:
        (ctx.run_dir / "server.stderr.log").write_text(client.stderr, encoding="utf-8")
        client.close(terminate=True, timeout=ctx.config.defaults.max_pause_ms / 1000)


def kd_external(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    """Launch Classic WinDbg or WinDbgX through the supported managed-facade launcher."""
    _require_checks(ctx, options, _kd_external_checks)
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    frontend = str(options.get("frontend", "classic")).lower()
    if frontend not in {"classic", "windbgx"}:
        raise PrerequisiteError("frontend must be classic or windbgx")
    debugger = (
        ctx.config.paths.classic_debugger_exe
        if frontend == "classic"
        else ctx.config.paths.windbgx_exe
    )
    if debugger is None:
        raise PrerequisiteError("paths.windbgx_exe is not configured")
    if (
        frontend == "windbgx"
        and "windowsapps" in {part.lower() for part in debugger.parts}
        and debugger.parent.name.lower() == "windowsapps"
    ):
        raise PrerequisiteError(
            "paths.windbgx_exe must name the package executable, not the WindowsApps alias"
        )
    ctx.confirm(f"Launch {frontend} WinDbg on a managed Secure Kernel KD session for {target.vm_name}?")

    policy_path = ctx.run_dir / "sk-live-policy.json"
    policy = write_policy(ctx.config, target, policy_path)
    if bool(options.get("allow_memory_writes", False)):
        policy["allow_memory_writes"] = True
        atomic_json(policy_path, policy)
    open_path = ctx.run_dir / "open-sk-kd.json"
    m8.write_open_config(
        ctx.config,
        target,
        open_path,
        arm_mode=str(options.get("arm_mode", ctx.config.defaults.arm_mode)),
    )
    launcher = ctx.config.paths.windbg_mcp_repo / "tools" / "launch_sk_kd.ps1"
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(launcher),
        "-Frontend",
        "WinDbgX" if frontend == "windbgx" else "Classic",
        "-ConfigPath",
        str(open_path),
        "-ServerPath",
        str(ctx.config.paths.windbg_mcp_exe),
        "-DebuggerPath",
        str(debugger),
        "-OpenTimeoutMs",
        str(int(options.get("open_timeout_ms", ctx.config.defaults.max_pause_ms))),
        "-EndTimeoutMs",
        str(int(options.get("end_timeout_ms", 120_000))),
    ]
    ctx.run_process(
        command,
        env={
            "WINDBG_MCP_SK_LIVE_POLICY": str(policy_path),
            "WINDBG_MCP_TRANSCRIPT": str(ctx.run_dir / "mcp.jsonl"),
            "WINDBG_MCP_TRANSCRIPT_MAX_FIELD": "0",
        },
        name=f"{frontend}-secure-kernel-debugger",
        timeout=float(options.get("timeout", 7200)),
    )
    audit = (
        _post_kd_audit(ctx, survival_seconds=int(options.get("survival_seconds", 0)))
        if options.get("post_audit", True)
        else None
    )
    return {
        "frontend": frontend,
        "debugger": str(debugger),
        "open_config": str(open_path),
        "policy": str(policy_path),
        "post_release_audit": audit,
    }


def _wait_trigger(process: subprocess.Popen[str], timeout: float = 120) -> dict[str, Any]:
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=10)
        raise ExecutionFailure("the counted enclave trigger did not finish after the target resumed")
    result = {"exit_code": process.returncode, "stdout": stdout, "stderr": stderr}
    if process.returncode:
        raise ExecutionFailure(f"the counted enclave trigger failed: {result}")
    return result


def kd_debugger(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    """Drive the composite Secure Kernel session entirely through generic debugger tools."""
    _require_checks(ctx, options, _kd_debugger_checks)
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    cycles = int(options.get("free_run_cycles", 1))
    if not 1 <= cycles <= 25:
        raise PrerequisiteError("free_run_cycles must be in 1..=25")
    breakpoint = str(options.get("breakpoint", m8.DEFAULT_BREAKPOINT))
    symbol_path = Path(str(options.get("symbol_path") or ctx.config.paths.symbol_path))
    ctx.confirm(
        f"Open the composite Secure Kernel debugger on {target.vm_name}, hit {breakpoint}, "
        f"and run {cycles} break-in cycle(s)?"
    )

    policy_path = ctx.run_dir / "sk-live-policy.json"
    write_policy(ctx.config, target, policy_path)
    client = McpClient(
        ctx.config.paths.windbg_mcp_exe,
        cwd=ctx.config.paths.windbg_mcp_repo,
        policy=policy_path,
        transcript=ctx.run_dir / "mcp.jsonl",
    )
    session_id: str | None = None
    trigger: subprocess.Popen[str] | None = None
    result: dict[str, Any] = {"breakpoint": breakpoint, "free_run_cycles": cycles, "tools": []}

    def call(name: str, arguments: dict[str, Any], timeout: float = 180) -> dict[str, Any]:
        value = client.tool(name, {"session_id": session_id, **arguments}, timeout)
        result["tools"].append({"tool": name, "result": value})
        return value

    try:
        result["server"] = client.initialize()
        opened = client.tool(
            "open_sk_debugger",
            m8.open_arguments(
                ctx.config,
                target,
                arm_mode=str(options.get("arm_mode", ctx.config.defaults.arm_mode)),
                connect_timeout_ms=60_000,
                idle_timeout_ms=180_000,
            ),
            600,
        )
        session_id = str(opened["session_id"])
        result["session_id"] = session_id
        result["opened"] = opened
        result["symbol_path"] = client.tool_text(
            "set_symbol_path",
            {"session_id": session_id, "path": str(symbol_path), "reload": "/f securekernel.exe"},
            180,
        )
        call("modules", {})
        if str(options.get("arm_mode", ctx.config.defaults.arm_mode)) == "redirect":
            call("registers", {})
            call("step_into", {})
        call("set_breakpoint", {"expression": breakpoint})
        started = call("continue_async", {"max_run_ms": 120_000})
        execution = str(started["execution"])
        trigger = subprocess.Popen(
            m8.helper_command(
                ctx.config,
                target,
                "trigger",
                "--count",
                str(int(options.get("trigger_count", 1))),
            ),
            cwd=ctx.config.paths.windbg_mcp_repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stopped = call("wait_for_stop", {"execution": execution, "timeout_ms": 120_000})
        if stopped.get("stop") is None:
            raise ExecutionFailure(f"the guest did not reach {breakpoint}: {stopped}")
        result["breakpoint_stop"] = stopped
        call("registers", {})
        call("backtrace", {"frames": 8})
        call("disassemble", {"count": 8})
        call("step_into", {})
        call("clear_breakpoints", {"all": True})

        break_ins = []
        for cycle in range(cycles):
            started = call("continue_async", {"max_run_ms": 120_000})
            execution = str(started["execution"])
            if cycle == 0 and trigger is not None:
                result["trigger"] = _wait_trigger(trigger)
                trigger = None
            call("break_in", {"execution": execution})
            stopped = call(
                "wait_for_stop",
                {"execution": execution, "timeout_ms": 120_000},
            )
            if stopped.get("stop", {}).get("interrupted") is not True:
                raise ExecutionFailure(f"break-in cycle {cycle} did not report an interrupted stop")
            break_ins.append(stopped)
        result["break_ins"] = break_ins
        call("registers", {})
    finally:
        if session_id is not None:
            try:
                result["ended"] = client.end_session(session_id, 180)
            except Exception as error:
                result["end_error"] = f"{type(error).__name__}: {error}"
        if trigger is not None:
            try:
                result["trigger_after_release"] = _wait_trigger(trigger)
            except Exception as error:
                result["trigger_error"] = f"{type(error).__name__}: {error}"
        (ctx.run_dir / "server.stderr.log").write_text(client.stderr, encoding="utf-8")
        client.close(terminate=True, timeout=ctx.config.defaults.max_pause_ms / 1000)
        atomic_json(ctx.run_dir / "m8-composite.json", result)

    stderr = (ctx.run_dir / "server.stderr.log").read_text(encoding="utf-8")
    if "end_error" in result:
        raise RecoveryRequired(f"the composite session did not release cleanly: {result['end_error']}")
    if result.get("ended", {}).get("released") is not True:
        raise RecoveryRequired(f"the composite session did not prove release: {result.get('ended')}")
    if "trigger_error" in result:
        raise ExecutionFailure(str(result["trigger_error"]))
    required = {
        "KD go to 1 hardware breakpoint(s)": 1,
        "KD restored the hit hardware-breakpoint handle": 1,
        "KD go with no breakpoint": cycles,
        "KD break-in woke the running wait": cycles,
    }
    missing = {marker: count for marker, count in required.items() if stderr.count(marker) < count}
    if missing:
        raise ExecutionFailure(f"the composite facade log omitted required M8 route evidence: {missing}")
    result["post_release_audit"] = _post_kd_audit(
        ctx,
        survival_seconds=int(options.get("survival_seconds", 0)),
    )
    atomic_json(ctx.run_dir / "m8-composite.json", result)
    return result


CORE_MODULES = [
    ModuleSpec(
        id="capture.inspect",
        title="Inspect a Secure Kernel capture",
        category="core",
        risk="read-only",
        description="Decode VMRS, split BIN/VSV, or a named Hyper-V snapshot through windbg-mcp.",
        defaults={"capture_kind": "vmrs", "vp": 0, "vtl": 1, "cross_check": True, "symbols": True, "timeout": 600},
        check=_capture_check,
        run=capture_inspect,
    ),
    ModuleSpec(
        id="live.decode",
        title="Decode live VTL1 memory",
        category="core",
        risk="read-only",
        description=(
            "Run the live decoder through the direct or refusing-hypercall provider. Direct mode reads "
            "pages through h3probe's memory operation; mode=hypercall reads them through "
            "HvCallReadGpa, which refuses VTL1 and is the negative control."
        ),
        defaults={"mode": "direct", "cross_check": True, "timeout": 600},
        check=_common_checks,
        run=live_decode,
    ),
    ModuleSpec(
        id="live.registers",
        title="H3 gate: read child VTL0/VTL1 registers",
        category="core",
        risk="read-only",
        description=(
            "Ask h3probe for every child partition's VTL0 and VTL1 CR3 and VSM status (gate H3); "
            "with snapshot=true, also discover the target, read its VTL1 register snapshot, and "
            "check that each VP's root maps the pinned Secure Kernel image and name the Secure Kernel "
            "process that owns it (root_check=false skips both). Pages are read through h3probe's "
            "memory operation."
        ),
        defaults={"snapshot": False, "root_check": True},
        check=_registers_checks,
        run=live_registers,
    ),
    ModuleSpec(
        id="live.ambient",
        title="Ambient Secure Kernel stop/step",
        category="core",
        risk="target-control",
        description="Arm ambient interrupt entries, inspect the held stop, step, continue, and restore.",
        defaults={"steps": 8, "read_size": 32},
        check=_control_checks,
        run=live_ambient,
    ),
    ModuleSpec(
        id="live.transition",
        title="VTL1 user-to-Secure-Kernel transition",
        category="core",
        risk="target-control",
        description="Hold a trustlet transition, read its protected stack evidence, step, and resume.",
        defaults={"steps": 8, "stack_bytes": 64, "workload_seconds": 150, "rounds": 2000, "workload_delay": 25},
        check=_transition_checks,
        run=live_transition,
    ),
    ModuleSpec(
        id="kd.manual",
        title="Prepare KD for manual WinDbg attachment",
        category="core",
        risk="target-control",
        description="Open the managed KD facade, print the generated pipe command, monitor, and release.",
        defaults={"post_audit": True},
        check=_kd_checks,
        run=kd_manual,
    ),
    ModuleSpec(
        id="kd.external",
        title="Launch a managed Secure Kernel WinDbg client",
        category="core",
        risk="target-control",
        description=(
            "Run the supported launcher for Classic WinDbg or WinDbgX, keep the managed facade "
            "owned until the debugger exits, then release and audit it."
        ),
        defaults={"frontend": "classic", "post_audit": True, "allow_memory_writes": False},
        check=_kd_external_checks,
        run=kd_external,
    ),
    ModuleSpec(
        id="kd.debugger",
        title="Drive Secure Kernel through generic debugger tools",
        category="core",
        risk="target-control",
        description=(
            "Open the M8 composite session and use the ordinary symbol, module, breakpoint, go, "
            "break-in, register, stack, disassembly and step tools end to end."
        ),
        defaults={
            "arm_mode": "redirect",
            "breakpoint": m8.DEFAULT_BREAKPOINT,
            "trigger_count": 1,
            "free_run_cycles": 1,
            "survival_seconds": 0,
        },
        check=_kd_debugger_checks,
        run=kd_debugger,
    ),
]

