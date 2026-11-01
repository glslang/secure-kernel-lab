from __future__ import annotations

import json
from pathlib import Path
import subprocess
import time
from typing import Any

from .. import bench_bridge, m8
from ..context import RunContext
from ..doctor import passed, run as doctor
from ..errors import Cancelled, ExecutionFailure, PrerequisiteError, RecoveryRequired
from ..mcp import McpClient
from ..policy import write_policy
from ..util import atomic_json, module_loaded, powershell_command
from .spec import ModuleSpec


LIVE_CAPABILITIES = {
    "administrator",
    "mcp",
    "repo",
    "profile",
    "image",
    "identity",
    "running",
    "h3probe",
}
CONTROL_CAPABILITIES = LIVE_CAPABILITIES | {"disposable"}
AMBIENT_BREAKPOINTS = (
    (0xE7670, "4883ec08"),
    (0xE8F70, "4883ec08"),
    (0xE8100, "4883ec08"),
    (0xF6CC0, "f644240801"),
)


def _ambient_breakpoints(kernel_base: int) -> dict[str, Any]:
    rows = [
        {"address": hex(kernel_base + rva), "bytes": guard, "slot": slot}
        for slot, (rva, guard) in enumerate(AMBIENT_BREAKPOINTS)
    ]
    return {
        "instruction_address": rows[0]["address"],
        "instruction_bytes": rows[0]["bytes"],
        "slot": rows[0]["slot"],
        "additional_breakpoints": rows[1:],
    }


def _common_checks(ctx: RunContext, _options: dict[str, Any]) -> list[dict[str, Any]]:
    return doctor(ctx.config, ctx.target, required=LIVE_CAPABILITIES)


def _kd_checks(ctx: RunContext, _options: dict[str, Any]) -> list[dict[str, Any]]:
    return doctor(ctx.config, ctx.target, required=CONTROL_CAPABILITIES | {"windbg"})


def _kd_external_checks(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    frontend = str(options.get("frontend", "classic")).lower()
    capability = "windbgx" if frontend == "windbgx" else "windbg_classic"
    return doctor(ctx.config, ctx.target, required=CONTROL_CAPABILITIES | {capability})


def _effective_symbol_path(ctx: RunContext, options: dict[str, Any]) -> Path | None:
    value = options.get("symbol_path") or ctx.config.paths.symbol_path
    return Path(str(value)) if value else None


def _kd_debugger_checks(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    checks = doctor(ctx.config, ctx.target, required=CONTROL_CAPABILITIES)
    symbol_path = _effective_symbol_path(ctx, options)
    checks.append(
        {
            "name": "Secure Kernel symbol store",
            "status": "ok" if symbol_path is not None and symbol_path.is_dir() else "error",
            "detail": str(symbol_path or "not configured"),
            "required": True,
        }
    )
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


def _require_checks(
    ctx: RunContext,
    options: dict[str, Any],
    checker=_common_checks,
) -> list[dict[str, Any]]:
    checks = checker(ctx, options)
    failures = [row for row in checks if row["status"] == "error"]
    if failures:
        raise PrerequisiteError(
            "prerequisite checks failed: " + "; ".join(row["name"] for row in failures)
        )
    return checks


def _capture_check(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    checks = doctor(ctx.config, None, required={"mcp", "repo", "kit"})
    kind = str(options.get("capture_kind", "vmrs"))
    capture = str(options.get("capture", ""))
    if kind not in {"vm", "vmrs", "split"}:
        checks.append(
            {"name": "capture kind", "status": "error", "detail": kind, "required": True}
        )
    if not capture:
        checks.append(
            {
                "name": "capture selector",
                "status": "error",
                "detail": "set capture",
                "required": True,
            }
        )
    elif kind == "vmrs" and not Path(capture).is_file():
        checks.append(
            {
                "name": "capture file",
                "status": "error",
                "detail": capture,
                "required": True,
            }
        )
    image = Path(str(options.get("image") or (ctx.target.secure_kernel_image if ctx.target else "")))
    checks.append(
        {
            "name": "image",
            "status": "ok" if image.is_file() else "error",
            "detail": str(image),
            "required": True,
        }
    )
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
    command.extend(
        [
            "--vp",
            str(options.get("vp", 0)),
            "--vtl",
            str(options.get("vtl", 1)),
            "--kit",
            str(ctx.config.paths.windows_kit_root),
        ]
    )
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
    target = ctx.target
    if target is None:
        raise PrerequisiteError("live decode requires a target")
    mode = str(options.get("mode", "direct"))
    if mode not in {"direct", "hypercall"}:
        raise PrerequisiteError("mode must be direct or hypercall")
    pid, vnd, handle, partition, how = bench_bridge.discover(ctx)
    command = [
        str(ctx.config.paths.windbg_mcp_exe),
        "--sk-live",
        "--transport",
        "builtin:h3probe",
        "--pages",
        "h3" if mode == "direct" else "hypercall",
        "--image",
        str(options.get("image") or target.secure_kernel_image),
        "--partition-id",
        hex(partition),
        "--vp",
        str(target.vp),
    ]
    if mode == "direct":
        command.extend(["--vmwp-pid", str(pid), "--partition-handle", hex(handle)])
    if options.get("cross_check"):
        command.append("--cross-check")
    ctx.run_process(command, name="live-decode", timeout=float(options.get("timeout", 600)))
    return {
        "mode": mode,
        "partition_id": hex(partition),
        "discovery": {
            "vmwp_pid": pid,
            "dispatcher_vnd": hex(vnd),
            "partition_handle": hex(handle),
            "partition_id": hex(partition),
            "how": how,
        },
        "provider": "builtin:h3probe",
    }


def live_ambient(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    """Generate this boot's live-tier config through repository-owned discovery and providers."""
    _require_checks(ctx, options)
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    ctx.confirm(f"Run the live Secure Kernel acceptance tier against {target.vm_name}?")
    pid, vnd, handle, partition, how = bench_bridge.discover(ctx)
    provider = [
        str(ctx.config.paths.windbg_mcp_exe),
        "--sk-h3-memory",
        "--vmwp-pid",
        str(pid),
        "--partition-handle",
        hex(handle),
        "--partition-id",
        hex(partition),
        "--vp",
        str(target.vp),
        "--image",
        str(target.secure_kernel_image),
    ]
    shaped = subprocess.run(
        provider,
        cwd=ctx.config.paths.windbg_mcp_repo,
        input="SHAPE\n",
        text=True,
        capture_output=True,
        timeout=30,
    )
    if shaped.returncode:
        raise ExecutionFailure(shaped.stderr.strip() or shaped.stdout.strip())
    shape = next((line for line in shaped.stdout.splitlines() if line.startswith("SHAPE ")), None)
    if shape is None:
        raise ExecutionFailure(f"built-in memory provider omitted SHAPE: {shaped.stdout!r}")
    fields = dict(word.split("=", 1) for word in shape.split()[1:] if "=" in word)
    try:
        cr3 = int(fields["cr3"], 0)
        kernel_base = int(fields["kernel_base"], 0)
    except (KeyError, ValueError) as error:
        raise ExecutionFailure(f"built-in memory provider returned invalid SHAPE: {shape}") from error
    live_config = ctx.run_dir / "live-acceptance.json"
    value = {
        "disposable": True,
        "profile": str(target.profile),
        "control_transport": "builtin:h3probe",
        "live_transport": "builtin:h3probe",
        "vmwp_pid": pid,
        "dispatcher_vnd": hex(vnd),
        "vm_id": target.vm_id,
        "partition_id": hex(partition),
        "vp": target.vp,
        "expected_cr3": hex(cr3),
        "allow_transition_cr3": True,
        "trigger": m8.helper_command(ctx.config, target, "trigger", "--count", "1"),
        **_ambient_breakpoints(kernel_base),
    }
    atomic_json(live_config, value)
    policy = ctx.run_dir / "sk-live-policy.json"
    write_policy(ctx.config, target, policy)
    test = "a_live_secure_kernel_session_stops_steps_inspects_resumes_and_closes"
    ctx.run_process(
        [
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
        ],
        env={
            "WINDBG_MCP_SMOKE_SK_LIVE": str(live_config),
            "WINDBG_MCP_SK_LIVE_POLICY": str(policy),
            "WINDBG_MCP_TRANSCRIPT": str(ctx.run_dir / "mcp.jsonl"),
            "WINDBG_MCP_TRANSCRIPT_MAX_FIELD": "0",
        },
        name="live-ambient",
        timeout=float(options.get("timeout", 900)),
    )
    return {"test": test, "config": str(live_config), "discovery": how}


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
            print(debugger_command, file=ctx.output.stream, flush=True)
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


def _powershell(script: str) -> str:
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        capture_output=True,
        timeout=60,
    )
    if completed.returncode:
        raise ExecutionFailure(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout.strip()


def _set_paused(vm_id: str, paused: bool) -> None:
    escaped = vm_id.replace("'", "''")
    expected = "Paused" if paused else "Running"
    action = "Suspend-VM" if paused else "Resume-VM"
    script = (
        f"$v=Get-VM -Id '{escaped}' -ErrorAction Stop;"
        f"if($v.State.ToString() -ne '{expected}'){{{action} -VM $v -ErrorAction Stop;"
        "$v=Get-VM -Id $v.VMId -ErrorAction Stop};"
        f"if($v.State.ToString() -ne '{expected}'){{throw 'VM did not enter {expected}'}}"
    )
    _powershell(script)


def _post_kd_audit(
    ctx: RunContext,
    *,
    survival_seconds: int = 0,
    profile: Path | None = None,
) -> dict[str, Any]:
    """Keep orchestration in sklab and perform every privileged read in windbg-mcp."""
    if module_loaded("hvlib.dll"):
        raise RecoveryRequired("KD released but hvlib.dll was already loaded before its audit")
    target = ctx.target
    assert target is not None
    rows = doctor(ctx.config, target, required={"identity", "running"})
    identity_rows = [
        row
        for row in rows
        if row["name"] in {"Hyper-V target identity", "Hyper-V target state"}
    ]
    if any(row["status"] != "ok" for row in identity_rows):
        raise RecoveryRequired("KD released but the target identity/state audit failed")
    identity = next(row for row in identity_rows if row["name"] == "Hyper-V target identity")

    pid, vnd, handle, partition, how = bench_bridge.discover(ctx)
    survival = []
    elapsed = 0
    checkpoints = list(range(0, survival_seconds + 1, 30)) or [0]
    if survival_seconds not in checkpoints:
        checkpoints.append(survival_seconds)
    for checkpoint in checkpoints:
        if checkpoint > elapsed:
            time.sleep(checkpoint - elapsed)
            elapsed = checkpoint
        boot = m8.boot_identity(target)
        if int(boot["vmwp_pid"]) != pid or boot.get("heartbeat_ok") is not True:
            raise RecoveryRequired(f"target health changed during post-release audit: {boot}")
        survival.append({"label": f"post-kd-release-{checkpoint}s", **boot})

    profile_path = profile or target.profile
    profile_value = json.loads(profile_path.read_text(encoding="utf-8"))
    initial = profile_value["secure_kernel_kd"]["initial"]
    expected = bytes(int(value) for value in initial["original"])
    command = [
        str(ctx.config.paths.windbg_mcp_exe),
        "--sk-h3-audit",
        "--vmwp-pid",
        str(pid),
        "--partition-handle",
        hex(handle),
        "--partition-id",
        hex(partition),
        "--vp",
        str(target.vp),
        "--image",
        str(target.secure_kernel_image),
        "--target-rva",
        str(initial["rva"]),
        "--expected-bytes",
        expected.hex(),
    ]
    _set_paused(target.vm_id, True)
    try:
        completed = subprocess.run(
            command,
            cwd=ctx.config.paths.windbg_mcp_repo,
            text=True,
            capture_output=True,
            timeout=120,
        )
        if completed.returncode:
            raise RecoveryRequired(completed.stderr.strip() or completed.stdout.strip())
        try:
            privileged = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RecoveryRequired(
                f"windbg-mcp audit returned invalid JSON: {completed.stdout!r}"
            ) from error
    finally:
        try:
            _set_paused(target.vm_id, False)
        except Exception as error:
            raise RecoveryRequired(f"post-KD audit could not resume the VM: {error}") from error

    if module_loaded("hvlib.dll"):
        raise RecoveryRequired("KD post-release audit loaded hvlib.dll")
    result = {
        **privileged,
        "identity": identity,
        "discovery": {
            "vmwp_pid": pid,
            "dispatcher_vnd": hex(vnd),
            "partition_handle": hex(handle),
            "partition_id": hex(partition),
            "how": how,
        },
        "survival": survival,
        "health": survival[-1],
        "hvlib_loaded_before": False,
        "hvlib_loaded_after": False,
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
    client = McpClient(
        ctx.config.paths.windbg_mcp_exe,
        cwd=ctx.config.paths.windbg_mcp_repo,
        policy=policy,
        transcript=ctx.run_dir / "mcp.jsonl",
    )
    session_id: str | None = None
    try:
        ctx.manifest.update(server=client.initialize())
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
        rendered = powershell_command([str(ctx.config.paths.debugger_exe), "-k", connection])
        final_phase = _monitor_kd(ctx, client, session_id, rendered)
        if final_phase == "released":
            client.end_session(session_id)
        audit = _post_kd_audit(ctx) if options.get("post_audit", True) else None
        return {
            "session_id": session_id,
            "connection": connection,
            "final_phase": final_phase,
            "post_release_audit": audit,
        }
    finally:
        (ctx.run_dir / "server.stderr.log").write_text(client.stderr, encoding="utf-8")
        client.close(terminate=True, timeout=ctx.config.defaults.max_pause_ms / 1000)


def kd_external(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
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
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ctx.config.paths.windbg_mcp_repo / "tools" / "launch_sk_kd.ps1"),
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
        process.communicate(timeout=10)
        raise ExecutionFailure("the counted enclave trigger did not finish after the target resumed")
    result = {"exit_code": process.returncode, "stdout": stdout, "stderr": stderr}
    if process.returncode:
        raise ExecutionFailure(f"the counted enclave trigger failed: {result}")
    return result


def kd_debugger(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    _require_checks(ctx, options, _kd_debugger_checks)
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    cycles = int(options.get("free_run_cycles", 1))
    if not 1 <= cycles <= 25:
        raise PrerequisiteError("free_run_cycles must be in 1..=25")
    breakpoint = str(options.get("breakpoint", m8.DEFAULT_BREAKPOINT))
    symbol_path = _effective_symbol_path(ctx, options)
    if symbol_path is None:
        raise PrerequisiteError("a Secure Kernel symbol path is required")
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
        execution = str(call("continue_async", {"max_run_ms": 120_000})["execution"])
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
            execution = str(call("continue_async", {"max_run_ms": 120_000})["execution"])
            if cycle == 0 and trigger is not None:
                result["trigger"] = _wait_trigger(trigger)
                trigger = None
            call("break_in", {"execution": execution})
            stopped = call("wait_for_stop", {"execution": execution, "timeout_ms": 120_000})
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
    if "end_error" in result or result.get("ended", {}).get("released") is not True:
        raise RecoveryRequired(f"the composite session did not release cleanly: {result}")
    if "trigger_error" in result:
        raise ExecutionFailure(str(result["trigger_error"]))
    result["post_release_audit"] = _post_kd_audit(
        ctx, survival_seconds=int(options.get("survival_seconds", 0))
    )
    atomic_json(ctx.run_dir / "m8-composite.json", result)
    return result


CORE_MODULES = [
    ModuleSpec(
        "capture.inspect",
        "Inspect a Secure Kernel capture",
        "core",
        "read-only",
        "Decode VMRS, split BIN/VSV, or a named Hyper-V snapshot through windbg-mcp.",
        {"capture_kind": "vmrs", "vp": 0, "vtl": 1, "cross_check": True, "symbols": True, "timeout": 600},
        _capture_check,
        capture_inspect,
    ),
    ModuleSpec(
        "live.decode",
        "Decode live VTL1 memory",
        "core",
        "read-only",
        "Run the live decoder through windbg-mcp's built-in direct or refusing-hypercall source.",
        {"mode": "direct", "cross_check": True, "timeout": 600},
        _common_checks,
        live_decode,
    ),
    ModuleSpec(
        "live.ambient",
        "Run the repository-owned live VTL1 gate",
        "core",
        "target-control",
        "Discover this boot, generate the private config and run windbg-mcp's exact live tier.",
        {"timeout": 900},
        _common_checks,
        live_ambient,
    ),
    ModuleSpec(
        "kd.manual",
        "Prepare KD for manual WinDbg attachment",
        "core",
        "target-control",
        "Open the managed KD facade, print the generated pipe command, monitor, release and audit.",
        {"post_audit": True},
        _kd_checks,
        kd_manual,
    ),
    ModuleSpec(
        "kd.external",
        "Launch a managed Secure Kernel WinDbg client",
        "core",
        "target-control",
        "Launch Classic WinDbg or WinDbgX through the managed facade and audit release.",
        {"frontend": "classic", "post_audit": True, "allow_memory_writes": False},
        _kd_external_checks,
        kd_external,
    ),
    ModuleSpec(
        "kd.debugger",
        "Drive Secure Kernel through generic debugger tools",
        "core",
        "target-control",
        "Drive the M8 composite session and audit release through repository-owned providers.",
        {
            "arm_mode": "redirect",
            "breakpoint": m8.DEFAULT_BREAKPOINT,
            "trigger_count": 1,
            "free_run_cycles": 1,
            "survival_seconds": 0,
        },
        _kd_debugger_checks,
        kd_debugger,
    ),
]
