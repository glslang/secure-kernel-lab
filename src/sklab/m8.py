from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from .config import Config, Target
from .errors import ExecutionFailure, PrerequisiteError
from .policy import control_transport, live_transport, write_policy
from .util import atomic_json


M8_SCHEMA = "windbg-mcp.sk-kd-m8.2a-config/v1"
DEFAULT_BREAKPOINT = "securekernel!IumInvokeSecureService"
NATURAL_STOP_RVA = "0x00000000000e7670"
NATURAL_STOP_BYTES = [0x48, 0x83, 0xEC, 0x08]


def open_arguments(
    config: Config,
    target: Target,
    *,
    arm_mode: str | None = None,
    connect_timeout_ms: int | None = None,
    idle_timeout_ms: int | None = None,
    vp: int | None = None,
) -> dict[str, Any]:
    return {
        "profile": str(target.profile),
        "control_transport": control_transport(target, vp=True, transition=True),
        "live_transport": live_transport(target),
        "vm_id": target.vm_id,
        "vp": target.vp if vp is None else vp,
        "arm_mode": arm_mode or config.defaults.arm_mode,
        "connect_timeout_ms": connect_timeout_ms or config.defaults.connect_timeout_ms,
        "idle_timeout_ms": idle_timeout_ms or config.defaults.idle_timeout_ms,
    }


def write_open_config(
    config: Config,
    target: Target,
    path: Path,
    *,
    arm_mode: str | None = None,
) -> dict[str, Any]:
    value = open_arguments(config, target, arm_mode=arm_mode)
    atomic_json(path, value)
    return value


def helper_command(config: Config, target: Target, action: str, *arguments: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "sklab.m8_helper",
        "--config",
        str(config.source),
        "--target",
        target.name,
        action,
        *arguments,
    ]


def debugger_control_script() -> Path:
    return Path(__file__).resolve().parents[2] / "scripts" / "m8_debugger_control.ps1"


def debugger_control_command(action: str, *, text: str | None = None) -> list[str]:
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(debugger_control_script()),
        "-Action",
        action,
        "-DebuggerPid",
        "{pid}",
    ]
    if text is not None:
        command.extend(["-Text", text])
    return command


def qualification_paths(config: Config) -> tuple[Path, Path, Path]:
    classic = config.paths.classic_debugger_exe
    windbgx = config.paths.windbgx_exe
    symbols = config.paths.symbol_path
    if windbgx is None:
        raise PrerequisiteError(
            "M8 qualification requires paths.windbgx_exe naming the package UI executable, "
            "not its WindowsApps execution alias"
        )
    if symbols is None:
        raise PrerequisiteError(
            "M8 qualification requires paths.symbol_path naming the local Secure Kernel symbol store"
        )
    for name, path, directory in (
        ("classic_debugger_exe", classic, False),
        ("windbgx_exe", windbgx, False),
        ("symbol_path", symbols, True),
    ):
        valid = path.is_dir() if directory else path.is_file()
        if not valid:
            kind = "directory" if directory else "file"
            raise PrerequisiteError(f"paths.{name} must name a readable {kind}: {path}")
    if (
        "windowsapps" in {part.lower() for part in windbgx.parts}
        and windbgx.parent.name.lower() == "windowsapps"
    ):
        raise PrerequisiteError(
            "paths.windbgx_exe is an app-execution alias; name DbgX.Shell.exe (or WinDbgX.exe "
            "on an older build) inside the installed Microsoft.WinDbg package so its process "
            "lifetime matches the debugger UI"
        )
    return classic, windbgx, symbols


def write_qualification_config(
    config: Config,
    target: Target,
    directory: Path,
    *,
    breakpoint: str = DEFAULT_BREAKPOINT,
) -> Path:
    classic, windbgx, symbols = qualification_paths(config)
    directory.mkdir(parents=True, exist_ok=True)
    hardware_policy = directory / "m8-policy-hardware.json"
    int3_policy = directory / "m8-policy-int3.json"
    qualification = directory / "m8-qualification.json"
    artifacts = directory / "artifacts"

    hardware = write_policy(config, target, hardware_policy)
    software = json.loads(json.dumps(hardware))
    software["allow_memory_writes"] = True
    atomic_json(int3_policy, software)

    value = {
        "schema": M8_SCHEMA,
        "disposable": True,
        "open": open_arguments(
            config,
            target,
            arm_mode="redirect",
            connect_timeout_ms=60_000,
            idle_timeout_ms=60_000,
        ),
        "frontends": {"classic": str(classic), "windbgx": str(windbgx)},
        "windbgx_script": debugger_control_command("Command", text="{command}"),
        "interrupts": {
            "classic": debugger_control_command("Break"),
            "windbgx": debugger_control_command("Break"),
        },
        "resets": {
            "classic": debugger_control_command("Reset"),
            "windbgx": debugger_control_command("Reset"),
        },
        "policies": {"hardware": str(hardware_policy), "int3": str(int3_policy)},
        "breakpoint": breakpoint,
        "symbol_path": str(symbols),
        "trigger": helper_command(config, target, "trigger", "--count", "{count}"),
        "boot_probe": helper_command(config, target, "boot"),
        "post_release_audit": helper_command(
            config, target, "audit", "--survival-seconds", "60"
        ),
        "artifact_dir": str(artifacts),
    }
    atomic_json(qualification, value)
    return qualification


def write_composite_config(
    config: Config,
    target: Target,
    path: Path,
    *,
    breakpoint: str = DEFAULT_BREAKPOINT,
) -> Path:
    symbols = config.paths.symbol_path
    if symbols is None or not symbols.is_dir():
        raise PrerequisiteError(
            "M8 composite qualification requires paths.symbol_path naming the local symbol store"
        )
    value = {
        **open_arguments(config, target, arm_mode="redirect"),
        "disposable": True,
        "symbol_path": str(symbols),
        "breakpoint": breakpoint,
        "trigger": helper_command(config, target, "trigger", "--count", "1"),
        "post_release_audit": helper_command(
            config, target, "audit", "--survival-seconds", "60"
        ),
    }
    atomic_json(path, value)
    return path


def write_managed_kd_config(config: Config, target: Target, path: Path) -> Path:
    symbols = config.paths.symbol_path
    if symbols is None or not symbols.is_dir():
        raise PrerequisiteError(
            "managed KD acceptance requires paths.symbol_path naming the local symbol store"
        )
    kd = config.paths.cdb_exe.with_name("kd.exe")
    if not kd.is_file():
        raise PrerequisiteError(f"managed KD acceptance requires kd.exe beside paths.cdb_exe: {kd}")
    try:
        profile = json.loads(target.profile.read_text(encoding="utf-8"))
        profile["secure_kernel_kd"]["initial"] = {
            "rva": NATURAL_STOP_RVA,
            "original": NATURAL_STOP_BYTES,
        }
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise PrerequisiteError(f"cannot prepare the managed KD profile {target.profile}: {error}") from error
    natural_profile = path.with_name("managed-kd-profile.json")
    atomic_json(natural_profile, profile)
    value = {
        **open_arguments(config, target, arm_mode="natural"),
        "profile": str(natural_profile),
        "kd": str(kd),
        "disposable": True,
        "symbol_path": str(symbols),
        "trigger": helper_command(config, target, "trigger", "--count", "1"),
        "post_release_audit": helper_command(
            config, target, "audit", "--survival-seconds", "60"
        ),
    }
    atomic_json(path, value)
    return path


def boot_identity(target: Target) -> dict[str, Any]:
    escaped = target.vm_id.replace("'", "''")
    command = (
        f"$v=Get-VM -Id '{escaped}' -ErrorAction Stop;"
        "$p=@(Get-CimInstance Win32_Process -Filter \"Name='vmwp.exe'\" | "
        f"Where-Object {{$_.CommandLine -match [regex]::Escape('{escaped}')}});"
        "if($p.Count -ne 1){throw \"expected one vmwp, found $($p.Count)\"};"
        "$vmwpPid=[uint32]$p[0].ProcessId;"
        "$process=Get-Process -Id $vmwpPid -ErrorAction Stop;"
        "$heartbeat=Get-VMIntegrationService -VM $v -Name Heartbeat -ErrorAction Stop;"
        "[pscustomobject]@{vm_id=$v.VMId.ToString();"
        "boot_id=('{0}:{1}' -f $vmwpPid,$process.StartTime.ToUniversalTime().Ticks);"
        "vmwp_pid=$vmwpPid;vp_count=[uint32]$v.ProcessorCount;"
        "heartbeat_ok=($v.State.ToString() -eq 'Running' -and "
        "$heartbeat.PrimaryStatusDescription -eq 'OK')}|ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        text=True,
        capture_output=True,
        timeout=60,
    )
    if completed.returncode:
        raise ExecutionFailure(completed.stderr.strip() or completed.stdout.strip())
    try:
        value = json.loads(completed.stdout)
    except ValueError as error:
        raise ExecutionFailure(f"boot probe returned invalid JSON: {completed.stdout!r}") from error
    if str(value.get("vm_id", "")).lower() != target.vm_id.lower():
        raise ExecutionFailure(f"boot probe answered for the wrong VM: {value}")
    return value


def trigger_enclave(target: Target, count: int) -> dict[str, Any]:
    if not 1 <= count <= 10_000:
        raise PrerequisiteError("trigger count must be in 1..=10000")
    credential = target.guest_credential_file
    if credential is None or not credential.is_file():
        raise PrerequisiteError(
            "M8 trigger requires targets.<name>.guest_credential_file with username and password"
        )
    credential_path = str(credential).replace("'", "''")
    vm_id = target.vm_id.replace("'", "''")
    vm_name = target.vm_name.replace("'", "''")
    host = target.guest_spin_host.replace("'", "''")
    image = target.guest_enclave_image.replace("'", "''")
    command = (
        "$deadline=[DateTime]::UtcNow.AddSeconds(30);$runningSince=$null;"
        "do{"
        f"$v=Get-VM -Id '{vm_id}' -ErrorAction Stop;"
        f"if($v.Name -ne '{vm_name}'){{throw 'the allowlisted target identity changed'}};"
        "$state=$v.State.ToString();"
        "if($state -eq 'Running'){"
        "if($null -eq $runningSince){$runningSince=[DateTime]::UtcNow};"
        "if(([DateTime]::UtcNow-$runningSince).TotalMilliseconds -ge 500){break}"
        "}elseif($state -eq 'Paused'){$runningSince=$null}"
        "else{throw \"the allowlisted target is not running: $state\"};"
        "Start-Sleep -Milliseconds 100"
        "}while([DateTime]::UtcNow -lt $deadline);"
        "if($v.State.ToString() -ne 'Running' -or $null -eq $runningSince)"
        "{throw 'the allowlisted target did not resume within 30 seconds'};"
        f"$g=Get-Content -LiteralPath '{credential_path}' -Raw|ConvertFrom-Json;"
        "$c=New-Object System.Management.Automation.PSCredential([string]$g.username,"
        "(ConvertTo-SecureString ([string]$g.password) -AsPlainText -Force));"
        f"$r=Invoke-Command -VMName '{vm_name}' -Credential $c -ArgumentList {count},'{host}','{image}' "
        "-ScriptBlock {param($n,$hostPath,$imagePath);"
        "if(-not(Test-Path -LiteralPath $hostPath -PathType Leaf)-or"
        " -not(Test-Path -LiteralPath $imagePath -PathType Leaf))"
        "{throw 'the VBS enclave assets are missing'};"
        "$lines=@(& $hostPath 1 $n 2>&1|ForEach-Object{[string]$_});$exit=$LASTEXITCODE;"
        "[pscustomobject]@{requested_count=$n;"
        "host_sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $hostPath).Hash.ToLowerInvariant();"
        "image_sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $imagePath).Hash.ToLowerInvariant();"
        "output=$lines;exit_code=$exit}};"
        "$r|ConvertTo-Json -Depth 6 -Compress;"
        "if($r.exit_code -ne 0){exit [int]$r.exit_code}"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        text=True,
        capture_output=True,
        timeout=max(120, count * 30),
    )
    if completed.returncode:
        raise ExecutionFailure(completed.stderr.strip() or completed.stdout.strip())
    try:
        return json.loads(completed.stdout)
    except ValueError as error:
        raise ExecutionFailure(f"enclave trigger returned invalid JSON: {completed.stdout!r}") from error
