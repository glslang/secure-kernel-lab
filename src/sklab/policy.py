from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from .config import Config, Target
from .util import atomic_json


BUILTIN_H3PROBE = "builtin:h3probe"


def bench_directory() -> Path:
    return Path(__file__).resolve().parent / "bench"


def control_transport(target: Target, *, vp: bool = False, transition: bool = False) -> str:
    del target, vp, transition
    return BUILTIN_H3PROBE


def live_transport(target: Target) -> str:
    del target
    return BUILTIN_H3PROBE


def write_policy(
    config: Config,
    target: Target,
    path: Path,
    *,
    extra_profile_roots: Iterable[Path] = (),
) -> dict[str, object]:
    profile_roots = [target.profile.parent.resolve()]
    for root in extra_profile_roots:
        resolved = root.resolve()
        if resolved not in profile_roots:
            profile_roots.append(resolved)
    policy = {
        "disposable_vm_ids": [target.vm_id],
        "builtin_transports": [BUILTIN_H3PROBE],
        "profile_roots": [str(root) for root in profile_roots],
        "kit_roots": [str(config.paths.windows_kit_root.resolve())],
        "max_pause_ms": config.defaults.max_pause_ms,
    }
    atomic_json(path, policy)
    return policy

