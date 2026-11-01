from __future__ import annotations

import ctypes
import json
from pathlib import Path
import subprocess
from typing import Any

from .artifacts import load_manifest, verify
from .config import Config, Target
from .drivers import status as driver_status
from .util import sha256


def _check(name: str, ok: bool, detail: str, *, required: bool = True) -> dict[str, Any]:
    return {
        "name": name,
        "status": "ok" if ok else ("error" if required else "warning"),
        "detail": detail,
        "required": required,
    }


def _admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _vm(target: Target) -> tuple[bool, str | None, str]:
    escaped = target.vm_id.replace("'", "''")
    command = (
        f"$v=Get-VM -Id '{escaped}' -ErrorAction Stop; "
        "$v | Select-Object Name,@{n='State';e={$_.State.ToString()}},VMId | ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            text=True,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, None, str(error)
    if completed.returncode:
        return False, None, completed.stderr.strip() or completed.stdout.strip()
    try:
        value = json.loads(completed.stdout)
    except ValueError:
        return False, None, completed.stdout.strip()
    matches = str(value.get("Name", "")) == target.vm_name
    raw_state = value.get("State")
    state = str(raw_state) if raw_state is not None else None
    return matches, state, f"{value.get('Name')} ({raw_state}) {value.get('VMId')}"


def _provider(config: Config, target: Target | None, required: bool) -> dict[str, Any]:
    """Probe the repository-owned provider without opening its device in sklab."""
    if target is None:
        return _check(
            "h3probe built-in provider",
            False,
            "a configured target is required for the provider handshake",
            required=required,
        )
    discovery = subprocess.run(
        [
            str(config.paths.windbg_mcp_exe),
            "--sk-discover-identity",
            "--profile",
            str(target.profile),
            "--vm-id",
            target.vm_id,
        ],
        cwd=config.paths.windbg_mcp_repo,
        text=True,
        capture_output=True,
        timeout=120,
    )
    if discovery.returncode:
        return _check(
            "h3probe built-in provider",
            False,
            discovery.stderr.strip() or discovery.stdout.strip(),
            required=required,
        )
    try:
        identity = json.loads(discovery.stdout)
        partition = str(identity["partition_id"])
    except (KeyError, TypeError, ValueError) as error:
        return _check(
            "h3probe built-in provider",
            False,
            f"invalid discovery reply: {error}: {discovery.stdout!r}",
            required=required,
        )
    probe = subprocess.run(
        [
            str(config.paths.windbg_mcp_exe),
            "--sk-control-probe",
            "--transport",
            "builtin:h3probe",
            "--vm-id",
            target.vm_id,
            "--partition-id",
            partition,
            "--vp",
            str(target.vp),
        ],
        cwd=config.paths.windbg_mcp_repo,
        text=True,
        capture_output=True,
        timeout=30,
    )
    detail = probe.stdout.strip() if probe.returncode == 0 else probe.stderr.strip()
    return _check("h3probe built-in provider", probe.returncode == 0, detail, required=required)


def _drivers(
    config: Config,
    target: Target | None,
    required: bool,
    provider: bool = False,
) -> list[dict[str, Any]]:
    """Check service lifecycle here; delegate the device/ABI handshake to windbg-mcp."""
    drivers = config.drivers
    probe = driver_status(drivers.h3probe_service)
    if not probe.installed:
        return [
            _check(
                "h3probe service",
                False,
                f"{probe.service} is not installed; see drivers/h3probe/README.md",
                required=required,
            )
        ]
    rows = [_check("h3probe service", True, f"{probe.service}: {probe.image}", required=required)]
    image = probe.image
    if image is None or not image.is_file():
        rows.append(_check("h3probe image", False, f"service image not found: {image}", required=required))
    elif drivers.h3probe_sha256:
        actual = sha256(image)
        rows.append(
            _check(
                "h3probe image hash",
                actual == drivers.h3probe_sha256,
                f"expected {drivers.h3probe_sha256}, actual {actual}",
                required=required,
            )
        )
    else:
        rows.append(
            _check(
                "h3probe image hash",
                False,
                f"unpinned; set drivers.h3probe_sha256 = '{sha256(image)}'",
                required=False,
            )
        )
    detail = probe.state if probe.running else f"{probe.state}; start it with: sklab driver start"
    rows.append(_check("h3probe running", probe.running, detail, required=required))
    if probe.running and provider:
        rows.append(_provider(config, target, required))
    return rows


def run(
    config: Config,
    target: Target | None = None,
    *,
    required: set[str] | None = None,
) -> list[dict[str, Any]]:
    def needed(capability: str) -> bool:
        return required is None or capability in required

    paths = config.paths
    checks = [
        _check(
            "administrator",
            _admin(),
            "process has an elevated administrator token",
            required=needed("administrator"),
        ),
        _check(
            "windbg-mcp executable",
            paths.windbg_mcp_exe.is_file(),
            str(paths.windbg_mcp_exe),
            required=needed("mcp"),
        ),
        _check(
            "windbg-mcp repository",
            (paths.windbg_mcp_repo / "Cargo.toml").is_file(),
            str(paths.windbg_mcp_repo),
            required=needed("repo"),
        ),
        _check(
            "WinDbg",
            paths.debugger_exe.is_file(),
            str(paths.debugger_exe),
            required=needed("windbg"),
        ),
        _check(
            "Classic WinDbg",
            paths.classic_debugger_exe.is_file(),
            str(paths.classic_debugger_exe),
            required=needed("windbg_classic"),
        ),
        _check(
            "WinDbgX package UI executable",
            paths.windbgx_exe is not None and paths.windbgx_exe.is_file(),
            str(paths.windbgx_exe or "not configured"),
            required=needed("windbgx"),
        ),
        _check(
            "Secure Kernel symbol store",
            paths.symbol_path is not None and paths.symbol_path.is_dir(),
            str(paths.symbol_path or "not configured"),
            required=needed("symbols"),
        ),
        _check("cdb", paths.cdb_exe.is_file(), str(paths.cdb_exe), required=needed("cdb")),
        _check(
            "Windows Kit",
            paths.windows_kit_root.is_dir(),
            str(paths.windows_kit_root),
            required=needed("kit"),
        ),
    ]
    provider = needed("h3probe") or needed("h3_memory")
    checks.extend(_drivers(config, target, provider, provider))
    if target is not None:
        checks.extend(
            [
                _check(
                    "disposable target",
                    target.disposable,
                    target.name,
                    required=needed("disposable"),
                ),
                _check(
                    "dispatcher profile",
                    target.profile.is_file(),
                    str(target.profile),
                    required=needed("profile"),
                ),
                _check(
                    "Secure Kernel image",
                    target.secure_kernel_image.is_file(),
                    str(target.secure_kernel_image),
                    required=needed("image"),
                ),
            ]
        )
        if target.secure_kernel_image.is_file() and target.expected_image_sha256:
            actual = sha256(target.secure_kernel_image)
            checks.append(
                _check(
                    "Secure Kernel image hash",
                    actual == target.expected_image_sha256,
                    f"expected {target.expected_image_sha256}, actual {actual}",
                    required=needed("image"),
                )
            )
        vm_ok, vm_state, detail = _vm(target)
        vm_running = vm_state == "Running"
        checks.append(
            _check(
                "Hyper-V target identity",
                vm_ok,
                detail,
                required=needed("identity"),
            )
        )
        state_detail = detail
        if vm_state is not None and not vm_running:
            state_detail += f"; start it with: Start-VM -Id '{target.vm_id}'"
        checks.append(
            _check(
                "Hyper-V target state",
                vm_running,
                state_detail,
                required=needed("running"),
            )
        )
    artifacts = load_manifest(config.source.parent / "artifact-manifest.toml", paths.artifacts_root)
    for artifact in artifacts.values():
        if target is None or not artifact.required_by or any(
            item == target.name or item.startswith("core.") for item in artifact.required_by
        ):
            result = verify(artifact)
            checks.append(
                _check(
                    f"artifact:{artifact.name}",
                    result["status"] == "ok",
                    f"{result['status']} {result['path']}",
                    required=False,
                )
            )
    return checks


def passed(checks: list[dict[str, Any]]) -> bool:
    return all(row["status"] != "error" for row in checks)

