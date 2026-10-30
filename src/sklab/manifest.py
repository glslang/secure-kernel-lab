from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
import subprocess
from typing import Any

from .config import Config, Target
from .util import atomic_json, sha256


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _git_head(path: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


@dataclass
class RunManifest:
    path: Path
    value: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        config: Config,
        module_id: str,
        target: Target | None,
        options: dict[str, Any],
    ) -> "RunManifest":
        stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        run_id = f"{stamp}-{module_id.replace('.', '-')}-{secrets.token_hex(3)}"
        directory = config.paths.runs_root / run_id
        directory.mkdir(parents=True, exist_ok=False)
        value: dict[str, Any] = {
            "schema": "secure-kernel-lab.run.v1",
            "run_id": run_id,
            "module": module_id,
            "result": "running",
            "started_at": _now(),
            "pid": os.getpid(),
            "config": str(config.source),
            "options": options,
            "application_git_head": _git_head(config.source.parent),
            "windbg_mcp_git_head": _git_head(config.paths.windbg_mcp_repo),
            "windbg_mcp_exe": str(config.paths.windbg_mcp_exe),
        }
        if config.paths.windbg_mcp_exe.is_file():
            value["windbg_mcp_sha256"] = sha256(config.paths.windbg_mcp_exe)
        if target is not None:
            value["target"] = {
                "name": target.name,
                "vm_id": target.vm_id,
                "vm_name": target.vm_name,
                "vp": target.vp,
                "profile": str(target.profile),
            }
        result = cls(directory / "manifest.json", value)
        result.save()
        return result

    @property
    def directory(self) -> Path:
        return self.path.parent

    def update(self, **fields: Any) -> None:
        self.value.update(fields)
        self.save()

    def add_event(self, event: str, **fields: Any) -> None:
        self.value.setdefault("events", []).append({"at": _now(), "event": event, **fields})
        self.save()

    def finish(self, result: str, **fields: Any) -> None:
        self.value.update(fields)
        self.value["result"] = result
        self.value["finished_at"] = _now()
        self.save()

    def save(self) -> None:
        atomic_json(self.path, self.value)

