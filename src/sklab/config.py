from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib
from typing import Any

from .errors import PrerequisiteError


DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "config.local.toml"


def _path(base: Path, value: object, field_name: str, *, required: bool = True) -> Path | None:
    if value is None or str(value).strip() == "":
        if required:
            raise PrerequisiteError(f"configuration omits {field_name}")
        return None
    path = Path(os.path.expandvars(str(value))).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve(strict=False)


@dataclass(frozen=True)
class Defaults:
    connect_timeout_ms: int = 120_000
    idle_timeout_ms: int = 300_000
    max_pause_ms: int = 600_000
    arm_mode: str = "redirect"
    steps: int = 8


@dataclass(frozen=True)
class Paths:
    windbg_mcp_repo: Path
    windbg_mcp_exe: Path
    debugger_exe: Path
    classic_debugger_exe: Path
    windbgx_exe: Path | None
    symbol_path: Path | None
    cdb_exe: Path
    windows_kit_root: Path
    artifacts_root: Path
    runs_root: Path
    state_root: Path


@dataclass(frozen=True)
class Drivers:
    h3probe_service: str = "h3probe"
    h3probe_sha256: str | None = None


@dataclass(frozen=True)
class Target:
    name: str
    vm_id: str
    vm_name: str
    disposable: bool
    profile: Path
    secure_kernel_image: Path
    vp: int = 0
    additional_vps: tuple[int, ...] = ()
    guest_spin_host: str = r"C:\encl\spin_host.exe"
    guest_enclave_image: str = r"C:\encl\spin_enclave.dll"
    guest_credential_file: Path | None = None
    parent_disk: Path | None = None
    work_disk_root: Path | None = None
    expected_image_sha256: str | None = None
    expected_vmwp_sha256: str | None = None
    expected_vid_sha256: str | None = None


@dataclass(frozen=True)
class Config:
    source: Path
    paths: Paths
    defaults: Defaults
    targets: dict[str, Target] = field(default_factory=dict)
    drivers: Drivers = field(default_factory=Drivers)

    def target(self, name: str | None = None) -> Target:
        selected = name or next(iter(self.targets), None)
        if selected is None or selected not in self.targets:
            known = ", ".join(sorted(self.targets)) or "none"
            raise PrerequisiteError(f"unknown or missing target {selected!r}; configured: {known}")
        return self.targets[selected]


def load(path: Path | None = None) -> Config:
    selected = path or Path(os.environ.get("SKLAB_CONFIG", DEFAULT_CONFIG))
    selected = selected.expanduser().resolve(strict=False)
    if not selected.is_file():
        raise PrerequisiteError(
            f"no lab configuration at {selected}; copy config.example.toml to config.local.toml"
        )
    try:
        raw = tomllib.loads(selected.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise PrerequisiteError(f"cannot load {selected}: {error}") from error
    base = selected.parent
    paths_raw = raw.get("paths", {})
    kit = _path(base, paths_raw.get("windows_kit_root"), "paths.windows_kit_root")
    debugger = _path(
        base,
        paths_raw.get("debugger_exe", kit / "Debuggers" / "x64" / "windbg.exe"),
        "paths.debugger_exe",
    )
    cdb = _path(
        base,
        paths_raw.get("cdb_exe", kit / "Debuggers" / "x64" / "cdb.exe"),
        "paths.cdb_exe",
    )
    classic_debugger = _path(
        base,
        paths_raw.get("classic_debugger_exe", kit / "Debuggers" / "x64" / "windbg.exe"),
        "paths.classic_debugger_exe",
    )
    paths = Paths(
        windbg_mcp_repo=_path(base, paths_raw.get("windbg_mcp_repo"), "paths.windbg_mcp_repo"),
        windbg_mcp_exe=_path(base, paths_raw.get("windbg_mcp_exe"), "paths.windbg_mcp_exe"),
        debugger_exe=debugger,
        classic_debugger_exe=classic_debugger,
        windbgx_exe=_path(
            base,
            paths_raw.get("windbgx_exe"),
            "paths.windbgx_exe",
            required=False,
        ),
        symbol_path=_path(
            base,
            paths_raw.get("symbol_path"),
            "paths.symbol_path",
            required=False,
        ),
        cdb_exe=cdb,
        windows_kit_root=kit,
        artifacts_root=_path(base, paths_raw.get("artifacts_root", "artifacts"), "paths.artifacts_root"),
        runs_root=_path(base, paths_raw.get("runs_root", "runs"), "paths.runs_root"),
        state_root=_path(base, paths_raw.get("state_root", ".state"), "paths.state_root"),
    )
    defaults_raw = raw.get("defaults", {})
    defaults = Defaults(
        connect_timeout_ms=int(defaults_raw.get("connect_timeout_ms", 120_000)),
        idle_timeout_ms=int(defaults_raw.get("idle_timeout_ms", 300_000)),
        max_pause_ms=int(defaults_raw.get("max_pause_ms", 600_000)),
        arm_mode=str(defaults_raw.get("arm_mode", "redirect")),
        steps=int(defaults_raw.get("steps", 8)),
    )
    if defaults.arm_mode not in {"natural", "redirect"}:
        raise PrerequisiteError("defaults.arm_mode must be natural or redirect")
    for name, value in (
        ("connect_timeout_ms", defaults.connect_timeout_ms),
        ("idle_timeout_ms", defaults.idle_timeout_ms),
        ("max_pause_ms", defaults.max_pause_ms),
    ):
        if not 1 <= value <= 3_600_000:
            raise PrerequisiteError(f"defaults.{name} must be in 1..=3600000")
    drivers_raw = raw.get("drivers", {})
    # h3probe is the only driver. A configuration still naming LiveCloudKd's is refused rather
    # than half-honoured, so nothing goes on believing a second driver is in use.
    for table, key in ((paths_raw, "paths.livecloudkd_root"), (drivers_raw, "drivers.hvmm_service")):
        if key.split(".")[1] in table:
            raise PrerequisiteError(
                f"{key} is no longer read: h3probe is sklab's only driver "
                "(docs/h3probe-only-plan.md); remove it from the configuration"
            )
    drivers = Drivers(
        h3probe_service=str(drivers_raw.get("h3probe_service", "h3probe")),
        h3probe_sha256=_optional_hash(drivers_raw.get("h3probe_sha256"), "drivers"),
    )
    targets: dict[str, Target] = {}
    for name, row in raw.get("targets", {}).items():
        if not isinstance(row, dict):
            raise PrerequisiteError(f"targets.{name} must be a table")
        targets[name] = Target(
            name=name,
            vm_id=str(row.get("vm_id", "")).lower(),
            vm_name=str(row.get("vm_name", "")),
            disposable=row.get("disposable") is True,
            profile=_path(base, row.get("profile"), f"targets.{name}.profile"),
            secure_kernel_image=_path(
                base, row.get("secure_kernel_image"), f"targets.{name}.secure_kernel_image"
            ),
            vp=int(row.get("vp", 0)),
            additional_vps=tuple(int(vp) for vp in row.get("additional_vps", [])),
            guest_spin_host=str(row.get("guest_spin_host", r"C:\encl\spin_host.exe")),
            guest_enclave_image=str(
                row.get("guest_enclave_image", r"C:\encl\spin_enclave.dll")
            ),
            guest_credential_file=_path(
                base,
                row.get("guest_credential_file"),
                f"targets.{name}.guest_credential_file",
                required=False,
            ),
            parent_disk=_path(
                base, row.get("parent_disk"), f"targets.{name}.parent_disk", required=False
            ),
            work_disk_root=_path(
                base,
                row.get("work_disk_root"),
                f"targets.{name}.work_disk_root",
                required=False,
            ),
            expected_image_sha256=_optional_hash(row.get("expected_image_sha256"), name),
            expected_vmwp_sha256=_optional_hash(row.get("expected_vmwp_sha256"), name),
            expected_vid_sha256=_optional_hash(row.get("expected_vid_sha256"), name),
        )
        if not targets[name].vm_id or not targets[name].vm_name:
            raise PrerequisiteError(f"targets.{name} requires vm_id and vm_name")
    return Config(source=selected, paths=paths, defaults=defaults, targets=targets, drivers=drivers)


def _optional_hash(value: Any, table: str) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    result = str(value).upper()
    if len(result) != 64 or any(ch not in "0123456789ABCDEF" for ch in result):
        section = table if table == "drivers" else f"targets.{table}"
        raise PrerequisiteError(f"{section} contains an invalid SHA-256")
    return result

