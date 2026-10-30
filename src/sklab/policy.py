from __future__ import annotations

import json
from pathlib import Path
import sys

from .config import Config, Target
from .util import atomic_json, command_line


def bench_directory() -> Path:
    return Path(__file__).resolve().parent / "bench"


def control_transport(target: Target, *, vp: bool = False, transition: bool = False) -> str:
    parts = [
        sys.executable,
        str(bench_directory() / "k4_control_provider.py"),
        "--vm-id",
        target.vm_id,
        "--partition-id",
        "{partition_id}",
    ]
    if vp:
        parts.extend(["--vp", "{vp}"])
    if transition:
        parts.append("--allow-transition-cr3")
    return command_line(parts)


def live_transport(target: Target) -> str:
    """The live-memory child: h3probe's memory operation, through vmwp's own handle.

    It serves the guarded one-byte write behind a software breakpoint (`--writes`), because that
    capability is not authority: windbg-mcp makes a write only under a policy that sets
    `allow_memory_writes`, which `write_policy` never does.
    """
    parts = [
        sys.executable,
        str(bench_directory() / "gpa_server.py"),
        "--vmwp-pid",
        "{vmwp_pid}",
        "--partition-handle",
        "{partition_handle}",
        "--partition-id",
        "{partition_id}",
        "--vp",
        "{vp}",
        "--image",
        str(target.secure_kernel_image),
        "--writes",
    ]
    return command_line(parts)


def write_policy(config: Config, target: Target, path: Path) -> dict[str, object]:
    transports = []
    for with_vp in (False, True):
        for transition in (False, True):
            transports.append(control_transport(target, vp=with_vp, transition=transition))
    transports.append(live_transport(target))
    policy = {
        "disposable_vm_ids": [target.vm_id],
        "transport_commands": list(dict.fromkeys(transports)),
        "profile_roots": [str(target.profile.parent.resolve())],
        "kit_roots": [str(config.paths.windows_kit_root.resolve())],
        "max_pause_ms": config.defaults.max_pause_ms,
    }
    atomic_json(path, policy)
    return policy

